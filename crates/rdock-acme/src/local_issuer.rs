//! The background task that keeps a local-CA certificate for every private name the
//! configuration serves with `tls: auto`, and publishes them to the resolver's local index
//! (ADR-0020). Like the ACME manager, the data plane never waits for it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rdock_tls::{CertIndex, LoadedCert, SniResolver};
use tokio::sync::watch;
use tracing::warn;

use crate::local_ca::LocalCa;

/// The longest the task sleeps between checks.
const MAX_SLEEP: Duration = Duration::from_secs(3600);
/// Wait after the CA could not be opened or a leaf could not be issued.
const RETRY: Duration = Duration::from_secs(60);

/// Handle to the local issuing task.
#[derive(Debug)]
pub struct LocalIssuer {
    names: watch::Sender<Vec<String>>,
}

impl LocalIssuer {
    /// Starts the task. The CA lives in `dir` and is created on first use; certificates go to
    /// `resolver` through [`SniResolver::swap_local`].
    #[must_use]
    pub fn spawn(dir: PathBuf, resolver: Arc<SniResolver>) -> Self {
        let (names, rx) = watch::channel(Vec::new());
        let worker = Worker {
            dir,
            resolver,
            ca: None,
            leaves: BTreeMap::new(),
        };
        tokio::spawn(worker.run(rx));
        Self { names }
    }

    /// Replaces the names to certify; an unchanged list is ignored.
    pub fn update(&self, mut names: Vec<String>) {
        names.sort();
        names.dedup();
        self.names.send_if_modified(|current| {
            if *current == names {
                return false;
            }
            *current = names;
            true
        });
    }
}

struct Worker {
    dir: PathBuf,
    resolver: Arc<SniResolver>,
    ca: Option<LocalCa>,
    leaves: BTreeMap<String, LoadedCert>,
}

impl Worker {
    async fn run(mut self, mut names: watch::Receiver<Vec<String>>) {
        loop {
            let wanted = names.borrow_and_update().clone();
            let wake = self.step(&wanted, crate::manager::unix_now());
            tokio::select! {
                changed = names.changed() => if changed.is_err() { return },
                () = tokio::time::sleep(wake) => {}
            }
        }
    }

    /// Issues what `wanted` needs and publishes it; returns how long to sleep.
    fn step(&mut self, wanted: &[String], now: i64) -> Duration {
        self.leaves.retain(|name, _| wanted.contains(name));
        if wanted.is_empty() {
            self.publish();
            return MAX_SLEEP;
        }
        let Some(ca) = open_ca(&mut self.ca, &self.dir, now) else {
            return RETRY;
        };
        let mut retry = false;
        for name in wanted {
            if self
                .leaves
                .get(name)
                .is_some_and(|leaf| now < renew_at(leaf))
            {
                continue;
            }
            match ca.issue(name, now) {
                Ok(leaf) => {
                    self.leaves.insert(name.clone(), leaf);
                }
                Err(e) => {
                    warn!(name = %name, error = %e, "cannot issue a local certificate");
                    retry = true;
                }
            }
        }
        let next = self
            .leaves
            .values()
            .map(renew_at)
            .chain(std::iter::once(ca.rotate_at()))
            .min()
            .unwrap_or(now);
        self.publish();
        let sleep = Duration::from_secs(u64::try_from(next - now).unwrap_or(0)).min(MAX_SLEEP);
        if retry { sleep.min(RETRY) } else { sleep }
    }

    fn publish(&self) {
        let certs: Vec<LoadedCert> = self.leaves.values().cloned().collect();
        // Clients connecting to an address send no server name; serve them an address
        // certificate when there is one.
        let default = certs
            .iter()
            .find(|c| c.name.parse::<std::net::IpAddr>().is_ok())
            .map(|c| c.name.clone());
        self.resolver
            .swap_local(CertIndex::build(&certs, default.as_deref()));
    }
}

/// The CA, opened on first use and with its intermediate rotated when due.
fn open_ca<'a>(slot: &'a mut Option<LocalCa>, dir: &Path, now: i64) -> Option<&'a LocalCa> {
    let result = match slot.take() {
        Some(mut ca) => ca.rotate_if_due(now).map(|_| ca),
        None => LocalCa::open(dir, now),
    };
    match result {
        Ok(ca) => Some(slot.insert(ca)),
        Err(e) => {
            warn!(error = %e, "cannot use the local CA");
            None
        }
    }
}

/// A leaf is renewed with a third of its lifetime left.
fn renew_at(leaf: &LoadedCert) -> i64 {
    leaf.not_after - (leaf.not_after - leaf.not_before) / 3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issues_publishes_renews_and_drops_names() {
        let dir = tempfile::tempdir().unwrap();
        let resolver = Arc::new(SniResolver::new(CertIndex::default()));
        let mut worker = Worker {
            dir: dir.path().join("pki"),
            resolver: resolver.clone(),
            ca: None,
            leaves: BTreeMap::new(),
        };
        let now = 1_800_000_000;
        let names = vec!["app.localhost".to_owned(), "127.0.0.1".to_owned()];
        let sleep = worker.step(&names, now);
        assert!(resolver.covers("app.localhost"));
        assert!(
            resolver.lookup(None).is_some(),
            "an address certificate is the default"
        );
        assert!(sleep > Duration::ZERO && sleep <= MAX_SLEEP);
        let first = resolver.lookup(Some("app.localhost")).unwrap();

        worker.step(&names, now + 60);
        let same = resolver.lookup(Some("app.localhost")).unwrap();
        assert!(Arc::ptr_eq(&first, &same), "not renewed early");

        worker.step(&names, now + 5 * 24 * 3600);
        let renewed = resolver.lookup(Some("app.localhost")).unwrap();
        assert!(!Arc::ptr_eq(&first, &renewed), "renewed with a third left");

        worker.step(&[], now);
        assert!(!resolver.covers("app.localhost"));
    }
}
