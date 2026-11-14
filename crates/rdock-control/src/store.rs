//! The control plane's store, served to enrolled members (`POST /cluster/v1/store`): every
//! operation runs on one `DirStore` that only this process writes, under one lock and judged by
//! one clock, so fenced writes are checked atomically (ADR-0031).
//!
//! **Who may write what** (review finding M1). Every member may read every key: data planes
//! issue certificates, so each holds the ACME account key and the certificates' private keys
//! (ADR-0031's trust model). Writes are limited to what the protocol needs:
//!
//! | Keys | Written (put or delete) by |
//! |---|---|
//! | `certs/<name>/…`, `orders/<name>.json` | the holder of the lease `cert/<name>`, fenced |
//! | `accounts/<directory>/…` | the holder of the lease `account/<directory>`, fenced |
//! | `challenges/<id>` | a holder of a `cert/…` lease, fenced; removed by anyone once older than the janitor's age |
//! | `challenge-acks/<id>/<instance>` | that instance; removed by anyone once the answer is gone |
//! | `members/<instance>`, `limits/members/<instance>` | that instance; removed by anyone once a day old |
//! | `limits/<budget>/<window end>-<digest>` | anyone, only upwards (a total never shrinks); removed by anyone a minute after the window ended, by this process's clock |
//!
//! Leases can be taken only under `cert/` and `account/`, and always for the calling
//! instance. Anything else is refused.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use rdock_cluster::janitor::{left_over, limit_window_end};
use rdock_cluster::protocol::{StoreRequest, StoreResponse};
use rdock_cluster::{Clock, ClusterStore, DirStore, Lease, StoreError, SystemClock};

fn failed(error: &StoreError) -> StoreResponse {
    let (kind, current) = match error {
        StoreError::Conflict { current, .. } => ("conflict", *current),
        StoreError::Fenced { .. } => ("fenced", 0),
        StoreError::Lost(_) => ("lost", 0),
        StoreError::InvalidKey(_) => ("invalid_key", 0),
        StoreError::Forbidden(_) => ("forbidden", 0),
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
    if let Err(e) = authorize(store, instance, &request).await {
        return failed(&e);
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

fn forbidden(what: &str) -> StoreError {
    StoreError::Forbidden(what.to_owned())
}

/// The fence must be the lease `name` (whose holder is the caller: checked before).
fn fenced_by(fence: Option<&Lease>, name: &str, key: &str) -> Result<(), StoreError> {
    if fence.is_some_and(|f| f.name == name) {
        Ok(())
    } else {
        Err(forbidden(&format!(
            "`{key}` is written only under the lease `{name}`"
        )))
    }
}

/// The second segment of `key` (`certs/<name>/…` → `<name>`).
fn second(key: &str) -> &str {
    key.split('/').nth(1).unwrap_or_default()
}

/// Whether `instance` may perform `request` (see the module documentation).
async fn authorize(
    store: &DirStore,
    instance: &str,
    request: &StoreRequest,
) -> Result<(), StoreError> {
    let (key, fence, value, delete) = match request {
        StoreRequest::Get { .. } | StoreRequest::List { .. } | StoreRequest::Lease { .. } => {
            return Ok(());
        }
        StoreRequest::Acquire { name, .. } => {
            return if name.starts_with("cert/") || name.starts_with("account/") {
                Ok(())
            } else {
                Err(forbidden(&format!(
                    "no lease `{name}` in the cluster protocol"
                )))
            };
        }
        StoreRequest::Renew { .. } | StoreRequest::Release { .. } => return Ok(()),
        StoreRequest::Put {
            key, value, fence, ..
        } => (key.as_str(), fence.as_ref(), Some(value), false),
        StoreRequest::Delete { key, fence, .. } => (key.as_str(), fence.as_ref(), None, true),
    };
    let now = SystemClock.now_ms();
    let stored = || async { store.get(key).await.map(|e| e.map(|e| e.value)) };
    let own = |name: &str| name == instance;
    if let Some(name) = key
        .strip_prefix("members/")
        .or_else(|| key.strip_prefix("limits/members/"))
    {
        if own(name) || (delete && left_over(key, stored().await?.as_deref(), now)) {
            return Ok(());
        }
        return Err(forbidden("a member writes only its own heartbeat"));
    }
    if let Some(rest) = key.strip_prefix("challenge-acks/") {
        let (id, who) = rest.split_once('/').unwrap_or((rest, ""));
        if own(who) && !who.is_empty() {
            return Ok(());
        }
        if delete && store.get(&format!("challenges/{id}")).await?.is_none() {
            return Ok(());
        }
        return Err(forbidden("a member confirms only for itself"));
    }
    if key.starts_with("challenges/") {
        if fence.is_some_and(|f| f.name.starts_with("cert/")) {
            return Ok(());
        }
        if delete && left_over(key, stored().await?.as_deref(), now) {
            return Ok(());
        }
        return Err(forbidden(
            "challenge answers are written under a certificate lease",
        ));
    }
    if key.starts_with("certs/") {
        return fenced_by(fence, &format!("cert/{}", second(key)), key);
    }
    if let Some(name) = key
        .strip_prefix("orders/")
        .and_then(|rest| rest.strip_suffix(".json"))
    {
        return fenced_by(fence, &format!("cert/{name}"), key);
    }
    if key.starts_with("accounts/") {
        return fenced_by(fence, &format!("account/{}", second(key)), key);
    }
    if limit_window_end(key).is_some() {
        if delete {
            return if left_over(key, None, now) {
                Ok(())
            } else {
                Err(forbidden(
                    "a limit window is removed only a minute after it ended",
                ))
            };
        }
        let total = |bytes: &[u8]| {
            serde_json::from_slice::<serde_json::Value>(bytes)
                .ok()
                .and_then(|v| v.get("total").and_then(serde_json::Value::as_u64))
        };
        let new = value
            .and_then(|v| STANDARD.decode(v).ok())
            .and_then(|v| total(&v))
            .ok_or_else(|| forbidden("a limit total is {\"total\": n}"))?;
        let old = stored().await?.as_deref().and_then(total).unwrap_or(0);
        return if new >= old {
            Ok(())
        } else {
            Err(forbidden("a limit total never shrinks"))
        };
    }
    Err(forbidden(&format!(
        "`{key}` is not a key of the cluster protocol"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rdock_cluster::Expect;

    fn put(key: &str, value: &[u8], fence: Option<Lease>) -> StoreRequest {
        StoreRequest::Put {
            key: key.to_owned(),
            value: STANDARD.encode(value),
            expect: Expect::Any,
            fence,
        }
    }

    fn delete(key: &str, fence: Option<Lease>) -> StoreRequest {
        StoreRequest::Delete {
            key: key.to_owned(),
            expect: Expect::Any,
            fence,
        }
    }

    fn ok(response: &StoreResponse) -> bool {
        !matches!(response, StoreResponse::Error { .. })
    }

    fn refused(response: &StoreResponse) -> bool {
        matches!(response, StoreResponse::Error { kind, .. } if kind == "forbidden")
    }

    /// Review finding M1: a member writes certificates only under their lease, only its own
    /// heartbeat and confirmations, limit totals only upwards; everything else is refused.
    #[tokio::test]
    #[allow(clippy::too_many_lines)] // one walk through every key class
    async fn members_write_only_what_the_protocol_lets_them() {
        let dir = tempfile::tempdir().unwrap();
        let store = DirStore::exclusive(dir.path());
        // Unfenced writes of a certificate, an order, an account, an answer: refused.
        for key in [
            "certs/a.example/cert.pem",
            "orders/a.example.json",
            "accounts/ca.test-dir/account.json",
            "challenges/http-x",
            "something/else",
        ] {
            assert!(
                refused(&serve(&store, "edge-b", put(key, b"x", None)).await),
                "{key}"
            );
        }
        // Another member's heartbeat and confirmation: refused; its own: allowed.
        assert!(refused(
            &serve(&store, "edge-b", put("members/edge-a", b"{}", None)).await
        ));
        assert!(refused(
            &serve(&store, "edge-b", put("limits/members/edge-a", b"{}", None)).await
        ));
        assert!(refused(
            &serve(
                &store,
                "edge-b",
                put("challenge-acks/http-x/edge-a", b"", None)
            )
            .await
        ));
        assert!(ok(&serve(
            &store,
            "edge-b",
            put("members/edge-b", b"{}", None)
        )
        .await));
        // Under the lease of the certificate: allowed; under another name's lease: refused.
        let StoreResponse::Lease { lease: Some(lease) } = serve(
            &store,
            "edge-b",
            StoreRequest::Acquire {
                name: "cert/a.example".into(),
                ttl_ms: 60_000,
            },
        )
        .await
        else {
            panic!("no lease");
        };
        assert!(ok(&serve(
            &store,
            "edge-b",
            put("certs/a.example/cert.pem", b"x", Some(lease.clone()))
        )
        .await));
        assert!(refused(
            &serve(
                &store,
                "edge-b",
                put("certs/b.example/cert.pem", b"x", Some(lease.clone()))
            )
            .await
        ));
        assert!(ok(&serve(
            &store,
            "edge-b",
            put(
                "challenges/http-x",
                br#"{"created_at_ms": 1}"#,
                Some(lease.clone())
            )
        )
        .await));
        // Another member cannot use that lease (it is not the holder), nor take odd leases.
        assert!(!ok(&serve(
            &store,
            "edge-a",
            put("certs/a.example/cert.pem", b"y", Some(lease))
        )
        .await));
        assert!(refused(
            &serve(
                &store,
                "edge-a",
                StoreRequest::Acquire {
                    name: "anything".into(),
                    ttl_ms: 60_000
                }
            )
            .await
        ));
        // An answer left over (old by this clock) may be removed by anyone.
        assert!(ok(&serve(
            &store,
            "edge-a",
            delete("challenges/http-x", None)
        )
        .await));
        // Limit totals only grow; a live window is not removed.
        let window = rdock_cluster::janitor::limit_key("rl-a", SystemClock.now_ms(), "k");
        assert!(ok(&serve(
            &store,
            "edge-a",
            put(&window, br#"{"total": 5}"#, None)
        )
        .await));
        assert!(refused(
            &serve(&store, "edge-b", put(&window, br#"{"total": 1}"#, None)).await
        ));
        assert!(ok(&serve(
            &store,
            "edge-b",
            put(&window, br#"{"total": 7}"#, None)
        )
        .await));
        assert!(refused(
            &serve(&store, "edge-b", delete(&window, None)).await
        ));
        let ended = rdock_cluster::janitor::limit_key("rl-a", 1_000, "k");
        assert!(ok(&serve(
            &store,
            "edge-a",
            put(&ended, br#"{"total": 5}"#, None)
        )
        .await));
        assert!(ok(&serve(&store, "edge-b", delete(&ended, None)).await));
    }
}
