//! The control plane's store, served to enrolled members (`POST /cluster/v1/store`): every
//! operation runs on one `DirStore` that only this process writes, under one lock and judged by
//! one clock, so fenced writes are checked atomically (ADR-0031).

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use rdock_cluster::protocol::{StoreRequest, StoreResponse};
use rdock_cluster::{ClusterStore, DirStore, StoreError};

fn failed(error: &StoreError) -> StoreResponse {
    let (kind, current) = match error {
        StoreError::Conflict { current, .. } => ("conflict", *current),
        StoreError::Fenced { .. } => ("fenced", 0),
        StoreError::Lost(_) => ("lost", 0),
        StoreError::InvalidKey(_) => ("invalid_key", 0),
        StoreError::Unavailable(_) | StoreError::Backend(_) => ("backend", 0),
    };
    StoreResponse::Error {
        kind: kind.to_owned(),
        message: error.to_string(),
        current,
    }
}

fn ttl(ms: u64) -> std::time::Duration {
    // Leases between one second and an hour, whatever a member asks for.
    std::time::Duration::from_millis(ms.clamp(1_000, 3_600_000))
}

/// Runs `request` for `instance`.
pub(crate) async fn serve(
    store: &DirStore,
    instance: &str,
    request: StoreRequest,
) -> StoreResponse {
    // A member writes only under its own leases.
    let foreign = match &request {
        StoreRequest::Put {
            fence: Some(lease), ..
        }
        | StoreRequest::Delete {
            fence: Some(lease), ..
        } => (lease.holder != instance).then(|| lease.clone()),
        _ => None,
    };
    if let Some(lease) = foreign {
        return failed(&StoreError::Fenced {
            lease: lease.name,
            token: lease.token,
        });
    }
    let result = match request {
        StoreRequest::Get { key } => store.get(&key).await.map(|entry| StoreResponse::Entry {
            version: entry.as_ref().map_or(0, |e| e.version),
            value: entry.map(|e| STANDARD.encode(e.value)),
        }),
        StoreRequest::Put {
            key,
            value,
            expect,
            fence,
        } => match STANDARD.decode(value) {
            Ok(value) => store
                .put(&key, value, expect, fence.as_ref())
                .await
                .map(|version| StoreResponse::Version { version }),
            Err(e) => Err(StoreError::Backend(format!("the value is not base64: {e}"))),
        },
        StoreRequest::Delete { key, expect, fence } => store
            .delete(&key, expect, fence.as_ref())
            .await
            .map(|()| StoreResponse::Done),
        StoreRequest::List { prefix } => store
            .list(&prefix)
            .await
            .map(|keys| StoreResponse::Keys { keys }),
        StoreRequest::Acquire { name, ttl_ms } => store
            .acquire(&name, instance, ttl(ttl_ms))
            .await
            .map(|lease| StoreResponse::Lease { lease }),
        StoreRequest::Renew { lease, ttl_ms } if lease.holder == instance => store
            .renew(&lease, ttl(ttl_ms))
            .await
            .map(|lease| StoreResponse::Lease { lease: Some(lease) }),
        StoreRequest::Release { lease } if lease.holder == instance => {
            store.release(&lease).await.map(|()| StoreResponse::Done)
        }
        StoreRequest::Renew { lease, .. } | StoreRequest::Release { lease } => {
            Err(StoreError::Lost(lease.name))
        }
        StoreRequest::Lease { name } => store
            .lease(&name)
            .await
            .map(|lease| StoreResponse::Lease { lease }),
    };
    result.unwrap_or_else(|e| failed(&e))
}
