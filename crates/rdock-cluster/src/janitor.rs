//! Records in a cluster store that nobody removes otherwise (review findings L9, M3, M6): answers
//! of an order whose holder died before it withdrew them, confirmations of answers that are
//! gone, heartbeats of members that left (generated instance names make these grow without
//! bound), and the totals of limit windows that ended.
//!
//! Every member tidies what it can see once a minute; the control plane does the same on its
//! own store. On the control plane's store each removal is also checked by the control plane
//! with its own clock ([`left_over`]), so a member whose clock runs ahead cannot remove a record
//! that others still use.

use std::time::Duration;

use serde_json::Value;

use crate::store::{ClusterStore, Expect, StoreError};

/// An answer older than this was left by an order that ended without withdrawing it: no order
/// waits this long between publishing an answer and the CA's validation.
pub const ANSWER_MAX_AGE: Duration = Duration::from_secs(3600);

/// A heartbeat older than this belongs to a member that left.
pub const RECORD_MAX_AGE: Duration = Duration::from_secs(24 * 3600);

/// A limit window's total is kept this long after the window ended, so a member whose clock
/// runs up to this much behind still finds it (review finding M6).
pub const WINDOW_MARGIN: Duration = Duration::from_secs(60);

fn ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// The store key of a limit total: `limits/<budget>/<window end>-<key digest>`, one flat
/// directory per budget, so removing ended windows lists that budget only.
#[must_use]
pub fn limit_key(budget: &str, window_end_ms: u64, digest: &str) -> String {
    format!(
        "limits/{}/{window_end_ms}-{digest}",
        crate::store::segment(budget)
    )
}

/// The window end of a key made by [`limit_key`].
#[must_use]
pub fn limit_window_end(key: &str) -> Option<u64> {
    let rest = key.strip_prefix("limits/")?;
    let (budget, name) = rest.split_once('/')?;
    if budget == "members" || name.contains('/') {
        return None;
    }
    name.split_once('-')?.0.parse().ok()
}

/// A number field of a JSON document.
fn field(value: &[u8], name: &str) -> Option<u64> {
    serde_json::from_slice::<Value>(value)
        .ok()?
        .get(name)?
        .as_u64()
}

/// Whether the record at `key` (whose value is `value`, when it has one) may be removed by
/// anyone at `now_ms` because it is left over: an ended limit window past the margin, a
/// heartbeat older than [`RECORD_MAX_AGE`], an answer older than [`ANSWER_MAX_AGE`].
#[must_use]
pub fn left_over(key: &str, value: Option<&[u8]>, now_ms: u64) -> bool {
    if let Some(end) = limit_window_end(key) {
        return end.saturating_add(ms(WINDOW_MARGIN)) <= now_ms;
    }
    let Some(value) = value else {
        return true;
    };
    if key.starts_with("members/") || key.starts_with("limits/members/") {
        return field(value, "at_ms")
            .is_some_and(|at| at.saturating_add(ms(RECORD_MAX_AGE)) <= now_ms);
    }
    if key.starts_with("challenges/") {
        return field(value, "created_at_ms")
            .is_some_and(|at| at.saturating_add(ms(ANSWER_MAX_AGE)) <= now_ms);
    }
    false
}

/// Removes left-over answers, confirmations and heartbeats (not limit windows: each member
/// removes those of the limits it runs, and the control plane all of them). Errors other than
/// an unreachable store are skipped: another member may have tidied the same record, or the
/// store refuses a removal its own clock does not allow yet.
pub async fn tidy(store: &dyn ClusterStore, now_ms: u64) -> Result<(), StoreError> {
    // Confirmations first: an answer published after this listing has no confirmation in it.
    let acks = store.list("challenge-acks").await?;
    let answers = store.list("challenges").await?;
    let mut live = std::collections::BTreeSet::new();
    for key in &answers {
        let value = store.get(key).await?;
        if left_over(key, value.as_ref().map(|e| e.value.as_slice()), now_ms) {
            remove(store, key).await?;
        } else if let Some(id) = key.strip_prefix("challenges/") {
            live.insert(id.to_owned());
        }
    }
    for key in acks {
        let id = key
            .strip_prefix("challenge-acks/")
            .and_then(|rest| rest.split('/').next());
        if id.is_some_and(|id| !live.contains(id)) {
            remove(store, &key).await?;
        }
    }
    for prefix in ["members", "limits/members"] {
        for key in store.list(prefix).await? {
            let value = store.get(&key).await?;
            if value
                .as_ref()
                .is_some_and(|e| left_over(&key, Some(&e.value), now_ms))
            {
                remove(store, &key).await?;
            }
        }
    }
    Ok(())
}

/// Removes the totals of `budget`'s windows that ended more than [`WINDOW_MARGIN`] before
/// `now_ms` (listing that budget only).
pub async fn tidy_limits(
    store: &dyn ClusterStore,
    budget: &str,
    now_ms: u64,
) -> Result<(), StoreError> {
    let prefix = format!("limits/{}", crate::store::segment(budget));
    for key in store.list(&prefix).await? {
        if limit_window_end(&key).is_some() && left_over(&key, None, now_ms) {
            remove(store, &key).await?;
        }
    }
    Ok(())
}

/// Removes the totals of every limit window that ended more than [`WINDOW_MARGIN`] before
/// `now_ms`: the control plane's sweep over its own store.
pub async fn tidy_all_limits(store: &dyn ClusterStore, now_ms: u64) -> Result<(), StoreError> {
    for key in store.list("limits").await? {
        if limit_window_end(&key).is_some() && left_over(&key, None, now_ms) {
            remove(store, &key).await?;
        }
    }
    Ok(())
}

async fn remove(store: &dyn ClusterStore, key: &str) -> Result<(), StoreError> {
    match store.delete(key, Expect::Any, None).await {
        Err(e @ StoreError::Unavailable(_)) => Err(e),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemoryStore;

    const NOW: u64 = 1_800_000_000_000;

    #[test]
    fn keys_and_ages() {
        let key = limit_key("rl-a", 60_000, "00ff");
        assert_eq!(key, "limits/rl-a/60000-00ff");
        assert_eq!(limit_window_end(&key), Some(60_000));
        assert_eq!(limit_window_end("limits/members/edge-1"), None);
        let window = limit_key("b", NOW - 59_000, "k");
        assert!(!left_over(&window, None, NOW), "inside the margin");
        assert!(left_over(&window, None, NOW + 1_000));
        let beat = br#"{"at_ms": 1}"#;
        assert!(left_over("members/x", Some(beat), NOW));
        let fresh = format!(r#"{{"at_ms": {}}}"#, NOW - 1000);
        assert!(!left_over("members/x", Some(fresh.as_bytes()), NOW));
        assert!(!left_over("certs/a/cert.pem", Some(b"x"), NOW));
    }

    #[tokio::test]
    async fn left_over_records_are_removed() {
        let store = MemoryStore::new();
        let put = |key: &'static str, value: String| {
            let store = store.clone();
            async move {
                store
                    .put(key, value.into_bytes(), Expect::Any, None)
                    .await
                    .unwrap();
            }
        };
        let old = NOW - 2 * 3_600_000;
        put(
            "challenges/http-old",
            format!(r#"{{"created_at_ms": {old}}}"#),
        )
        .await;
        put("challenge-acks/http-old/a", String::new()).await;
        put(
            "challenges/http-new",
            format!(r#"{{"created_at_ms": {NOW}}}"#),
        )
        .await;
        put("challenge-acks/http-new/a", String::new()).await;
        put("challenge-acks/http-gone/a", String::new()).await;
        put("members/gone", r#"{"at_ms": 1}"#.to_owned()).await;
        put("members/here", format!(r#"{{"at_ms": {NOW}}}"#)).await;
        put("limits/members/gone", r#"{"at_ms": 1}"#.to_owned()).await;
        tidy(&store, NOW).await.unwrap();
        assert_eq!(
            store.list("").await.unwrap(),
            [
                "challenge-acks/http-new/a",
                "challenges/http-new",
                "members/here",
            ]
        );
        put("limits/b/1000-k", String::new()).await;
        let live = limit_key("b", NOW, "k");
        store
            .put(&live, Vec::new(), Expect::Any, None)
            .await
            .unwrap();
        tidy_limits(&store, "b", NOW).await.unwrap();
        assert_eq!(store.list("limits").await.unwrap(), [live]);
    }
}
