//! Zone discovery: the closest name at or above the record that the provider knows as a zone,
//! unless the configuration names the zone.

use std::collections::HashMap;
use std::future::Future;
use std::sync::Mutex;

use rdock_acme::dns::DnsError;

/// Finds and remembers the zone of each record name, for the life of one solver (one renewal
/// pass), so presenting two values on one name looks the zone up once.
#[derive(Debug, Default)]
pub(crate) struct ZoneFinder {
    configured: Option<String>,
    found: Mutex<HashMap<String, String>>,
}

impl ZoneFinder {
    /// A finder that answers `configured` when set, without asking the provider.
    pub(crate) fn new(configured: Option<&str>) -> Self {
        Self {
            configured: configured.map(normalize),
            found: Mutex::default(),
        }
    }

    /// The zone holding `fqdn`. `is_zone` asks the provider whether a name is a zone it serves;
    /// candidates are tried from `fqdn` itself up to the name below the top-level domain.
    pub(crate) async fn zone<F, Fut>(
        &self,
        provider: &str,
        fqdn: &str,
        mut is_zone: F,
    ) -> Result<String, DnsError>
    where
        F: FnMut(String) -> Fut,
        Fut: Future<Output = Result<bool, DnsError>>,
    {
        if let Some(zone) = &self.configured {
            return contains(zone, fqdn).then(|| zone.clone()).ok_or_else(|| {
                DnsError(format!("`{fqdn}` is not in the configured zone `{zone}`"))
            });
        }
        if let Some(zone) = self.remembered(fqdn) {
            return Ok(zone);
        }
        for candidate in candidates(fqdn) {
            if is_zone(candidate.to_owned()).await? {
                self.remember(fqdn, candidate);
                return Ok(candidate.to_owned());
            }
        }
        Err(DnsError(format!(
            "no {provider} zone holds `{fqdn}`; set `zone`, or allow the credential to read the zone"
        )))
    }

    fn remembered(&self, fqdn: &str) -> Option<String> {
        self.found.lock().ok()?.get(fqdn).cloned()
    }

    fn remember(&self, fqdn: &str, zone: &str) {
        if let Ok(mut found) = self.found.lock() {
            found.insert(fqdn.to_owned(), zone.to_owned());
        }
    }
}

/// `fqdn` and each parent, closest first, ending at the name below the top-level domain.
pub(crate) fn candidates(fqdn: &str) -> impl Iterator<Item = &str> {
    std::iter::successors(Some(fqdn), |name| {
        name.split_once('.').map(|(_, parent)| parent)
    })
    .filter(|name| name.contains('.'))
}

/// The record name relative to its zone, `@` for the apex. `fqdn` must be in `zone`.
pub(crate) fn relative_name(fqdn: &str, zone: &str) -> String {
    match fqdn
        .strip_suffix(zone)
        .and_then(|rest| rest.strip_suffix('.'))
    {
        Some(relative) if !relative.is_empty() => relative.to_owned(),
        _ => "@".to_owned(),
    }
}

/// A name as providers compare it: lower case, without a trailing dot.
pub(crate) fn normalize(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

fn contains(zone: &str, fqdn: &str) -> bool {
    fqdn == zone || fqdn.ends_with(&format!(".{zone}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidates_walk_up_to_the_registered_name() {
        let walk: Vec<&str> = candidates("_acme-challenge.app.example.com").collect();
        assert_eq!(
            walk,
            [
                "_acme-challenge.app.example.com",
                "app.example.com",
                "example.com"
            ]
        );
    }

    #[test]
    fn relative_names() {
        assert_eq!(
            relative_name("_acme-challenge.app.example.com", "example.com"),
            "_acme-challenge.app"
        );
        assert_eq!(relative_name("example.com", "example.com"), "@");
    }

    #[tokio::test]
    async fn the_configured_zone_wins_and_must_hold_the_name() {
        let finder = ZoneFinder::new(Some("Example.COM."));
        let zone = finder
            .zone("Test", "_acme-challenge.example.com", |_| async {
                panic!("no lookup with a configured zone")
            })
            .await
            .unwrap();
        assert_eq!(zone, "example.com");
        let error = finder
            .zone("Test", "_acme-challenge.example.org", |_| async {
                Ok(true)
            })
            .await
            .unwrap_err();
        assert!(error.0.contains("not in the configured zone"), "{error}");
    }

    #[tokio::test]
    async fn found_zones_are_remembered() {
        let finder = ZoneFinder::new(None);
        let asked = Mutex::new(Vec::new());
        for _ in 0..2 {
            let zone = finder
                .zone("Test", "_acme-challenge.app.example.com", |name| {
                    asked.lock().unwrap().push(name.clone());
                    async move { Ok(name == "example.com") }
                })
                .await
                .unwrap();
            assert_eq!(zone, "example.com");
        }
        assert_eq!(
            asked.lock().unwrap().len(),
            3,
            "the second call asks nothing"
        );
        let none = finder
            .zone("Test", "_acme-challenge.example.org", |_| async {
                Ok(false)
            })
            .await
            .unwrap_err();
        assert!(none.0.contains("no Test zone holds"), "{none}");
    }
}
