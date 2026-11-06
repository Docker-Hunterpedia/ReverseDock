//! Zone discovery: the closest name at or above the record that the provider knows as a zone,
//! unless the configuration names the zone.

use std::collections::HashMap;
use std::future::Future;
use std::sync::Mutex;

use rdock_acme::dns::DnsError;

/// Finds and remembers the zone of each record name, for the life of one solver (one renewal
/// pass), so presenting two values on one name looks the zone up once. A zone is remembered as
/// the provider's handle for it: its name for most providers, its ID for Route 53 and Google.
#[derive(Debug, Default)]
pub(crate) struct ZoneFinder {
    configured: Option<String>,
    found: Mutex<HashMap<String, String>>,
}

impl ZoneFinder {
    /// A finder that answers `configured` (a zone name) when set, without asking the provider.
    pub(crate) fn new(configured: Option<&str>) -> Self {
        Self {
            configured: configured.map(normalize),
            found: Mutex::default(),
        }
    }

    /// The zone holding `fqdn`. `lookup` asks the provider about one candidate name and answers
    /// the handle of a zone it serves under that name, if any (a private zone is no answer);
    /// candidates are tried from `fqdn` itself up to the name below the top-level domain.
    pub(crate) async fn zone<F, Fut>(
        &self,
        provider: &str,
        fqdn: &str,
        mut lookup: F,
    ) -> Result<String, DnsError>
    where
        F: FnMut(String) -> Fut,
        Fut: Future<Output = Result<Option<String>, DnsError>>,
    {
        if let Some(zone) = self.known(fqdn)? {
            return Ok(zone);
        }
        for candidate in candidates(fqdn) {
            if let Some(zone) = lookup(candidate.to_owned()).await? {
                self.remember(fqdn, &zone);
                return Ok(zone);
            }
        }
        Err(no_zone(provider, fqdn))
    }

    /// The zone holding `fqdn`, for providers that answer it in one call: `owner` asks for the
    /// zone that owns `fqdn` and answers its name.
    pub(crate) async fn zone_of<F, Fut>(
        &self,
        provider: &str,
        fqdn: &str,
        owner: F,
    ) -> Result<String, DnsError>
    where
        F: FnOnce(String) -> Fut,
        Fut: Future<Output = Result<Option<String>, DnsError>>,
    {
        if let Some(zone) = self.known(fqdn)? {
            return Ok(zone);
        }
        let zone = owner(fqdn.to_owned())
            .await?
            .map(|zone| normalize(&zone))
            .filter(|zone| contains(zone, fqdn))
            .ok_or_else(|| no_zone(provider, fqdn))?;
        self.remember(fqdn, &zone);
        Ok(zone)
    }

    /// The configured zone, checked to hold `fqdn`, or the one found for it before.
    fn known(&self, fqdn: &str) -> Result<Option<String>, DnsError> {
        if let Some(zone) = &self.configured {
            return contains(zone, fqdn)
                .then(|| Some(zone.clone()))
                .ok_or_else(|| {
                    DnsError(format!("`{fqdn}` is not in the configured zone `{zone}`"))
                });
        }
        Ok(self.remembered(fqdn))
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

fn no_zone(provider: &str, fqdn: &str) -> DnsError {
    DnsError(format!(
        "no {provider} zone holds `{fqdn}`; set `zone`, or allow the credential to read the zone"
    ))
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
            .zone("Test", "_acme-challenge.example.org", |name| async {
                Ok(Some(name))
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
                    async move { Ok((name == "example.com").then(|| "zone-id".to_owned())) }
                })
                .await
                .unwrap();
            assert_eq!(zone, "zone-id");
        }
        assert_eq!(
            asked.lock().unwrap().len(),
            3,
            "the second call asks nothing"
        );
        let none = finder
            .zone("Test", "_acme-challenge.example.org", |_| async {
                Ok(None)
            })
            .await
            .unwrap_err();
        assert!(none.0.contains("no Test zone holds"), "{none}");
    }

    #[tokio::test]
    async fn an_owner_lookup_must_answer_a_parent_of_the_name() {
        let finder = ZoneFinder::new(None);
        let zone = finder
            .zone_of("Test", "_acme-challenge.app.example.com", |_| async {
                Ok(Some("Example.com.".to_owned()))
            })
            .await
            .unwrap();
        assert_eq!(zone, "example.com");
        let remembered = finder
            .zone_of("Test", "_acme-challenge.app.example.com", |_| async {
                panic!("remembered")
            })
            .await
            .unwrap();
        assert_eq!(remembered, "example.com");
        let foreign = finder
            .zone_of("Test", "_acme-challenge.example.org", |_| async {
                Ok(Some("example.com".to_owned()))
            })
            .await
            .unwrap_err();
        assert!(foreign.0.contains("no Test zone holds"), "{foreign}");
    }
}
