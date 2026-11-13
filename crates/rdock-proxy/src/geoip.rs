//! GeoIP lookups for `ClientCountry`, `ClientContinent` and `ClientASN` (H-SEC-04, ADR-0031).
//!
//! Databases are MaxMind DB files (format 2.0, <https://maxmind.github.io/MaxMind-DB/>) read
//! wholly into memory with the `maxminddb` crate (no `mmap`): MaxMind GeoLite2/GeoIP2 Country
//! and ASN, DB-IP Lite and IPinfo Lite. Both record shapes are understood: GeoIP2's nested
//! `country.iso_code`, `continent.code`, `autonomous_system_number`, and IPinfo Lite's flat
//! `country_code`, `continent_code`, `asn` (`"AS13335"`). The database is operator-supplied
//! input; the crate bounds every decode (values and bytes per record, since 0.31).
//!
//! An address that is not globally routable (loopback, private, link-local, shared CGNAT space,
//! unique-local, documentation, multicast) is never looked up, and an address the database does
//! not know has no country: matchers on either never match.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rdock_model::settings::{GeoIp as GeoIpSettings, OnStale};
use serde::Deserialize;

/// What a lookup found. Empty for unknown and non-global addresses.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GeoRecord {
    /// ISO 3166-1 alpha-2, upper case.
    pub country: Option<[u8; 2]>,
    /// Continent code, upper case.
    pub continent: Option<[u8; 2]>,
    /// Autonomous system number.
    pub asn: Option<u32>,
}

impl GeoRecord {
    /// The country code as text.
    #[must_use]
    pub fn country_str(&self) -> Option<&str> {
        self.country
            .as_ref()
            .and_then(|c| std::str::from_utf8(c).ok())
    }
}

/// One database file, loaded.
pub struct Database {
    path: PathBuf,
    stamp: Stamp,
    reader: maxminddb::Reader<Vec<u8>>,
    /// Build time from the metadata (Unix seconds).
    pub build_epoch: u64,
    /// `database_type` from the metadata, e.g. `GeoLite2-Country`.
    pub kind: String,
}

impl std::fmt::Debug for Database {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Database")
            .field("path", &self.path)
            .field("kind", &self.kind)
            .field("build_epoch", &self.build_epoch)
            .finish_non_exhaustive()
    }
}

/// File identity used to reuse a loaded database across reloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Stamp {
    len: u64,
    modified: Option<SystemTime>,
    /// Device and inode on Unix: a file written aside and renamed into place is a new inode,
    /// even with the same length and a modification time in the same clock tick.
    inode: Option<(u64, u64)>,
}

fn stamp(path: &Path) -> Result<Stamp, String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("`{}`: {e}", path.display()))?;
    #[cfg(unix)]
    let inode = {
        use std::os::unix::fs::MetadataExt;
        Some((meta.dev(), meta.ino()))
    };
    #[cfg(not(unix))]
    let inode = None;
    Ok(Stamp {
        len: meta.len(),
        modified: meta.modified().ok(),
        inode,
    })
}

/// Largest database file read (IPinfo Lite with ASNs is about 60 MB in 2026).
const MAX_FILE: u64 = 512 * 1024 * 1024;

impl Database {
    /// Reads and checks `path`.
    ///
    /// # Errors
    ///
    /// The file cannot be read, is too large, or is not a MaxMind DB.
    pub fn open(path: &Path) -> Result<Self, String> {
        let stamp = stamp(path)?;
        if stamp.len > MAX_FILE {
            return Err(format!(
                "`{}` is larger than {} MiB",
                path.display(),
                MAX_FILE >> 20
            ));
        }
        let bytes = std::fs::read(path).map_err(|e| format!("`{}`: {e}", path.display()))?;
        Self::from_bytes(path, stamp, bytes)
    }

    fn from_bytes(path: &Path, stamp: Stamp, bytes: Vec<u8>) -> Result<Self, String> {
        let reader = maxminddb::Reader::from_source(bytes)
            .map_err(|e| format!("`{}` is not a MaxMind DB file: {e}", path.display()))?;
        let build_epoch = reader.metadata().build_epoch;
        let kind = reader.metadata().database_type.clone();
        Ok(Self {
            path: path.to_owned(),
            stamp,
            reader,
            build_epoch,
            kind,
        })
    }

    /// Seconds since the database was built (0 for a build time in the future).
    #[must_use]
    pub fn age(&self, now: SystemTime) -> Duration {
        let now = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        Duration::from_secs(now.saturating_sub(self.build_epoch))
    }

    fn lookup(&self, ip: IpAddr) -> Option<Fields> {
        self.reader.lookup(ip).ok()?.decode::<Fields>().ok()?
    }
}

/// The fields read from a record, in either supported shape.
#[derive(Debug, Default, Deserialize)]
struct Fields {
    #[serde(default)]
    country: Option<Named>,
    #[serde(default)]
    continent: Option<Coded>,
    #[serde(default)]
    country_code: Option<String>,
    #[serde(default)]
    continent_code: Option<String>,
    #[serde(default)]
    autonomous_system_number: Option<u32>,
    #[serde(default)]
    asn: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct Named {
    #[serde(default)]
    iso_code: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct Coded {
    #[serde(default)]
    code: Option<String>,
}

fn code(text: Option<&str>) -> Option<[u8; 2]> {
    let bytes = text?.as_bytes();
    match bytes {
        [a, b] if a.is_ascii_alphabetic() && b.is_ascii_alphabetic() => {
            Some([a.to_ascii_uppercase(), b.to_ascii_uppercase()])
        }
        _ => None,
    }
}

impl Fields {
    fn into_record(self) -> GeoRecord {
        GeoRecord {
            country: code(
                self.country
                    .as_ref()
                    .and_then(|c| c.iso_code.as_deref())
                    .or(self.country_code.as_deref()),
            ),
            continent: code(
                self.continent
                    .as_ref()
                    .and_then(|c| c.code.as_deref())
                    .or(self.continent_code.as_deref()),
            ),
            asn: self.autonomous_system_number.or_else(|| {
                let text = self.asn.as_deref()?;
                let digits = text
                    .strip_prefix("AS")
                    .or_else(|| text.strip_prefix("as"))
                    .unwrap_or(text);
                digits.parse().ok()
            }),
        }
    }
}

/// The databases in use.
#[derive(Debug, Default)]
pub struct GeoIp {
    country: Option<Arc<Database>>,
    asn: Option<Arc<Database>>,
}

/// A loaded set of databases and what loading noticed.
#[derive(Debug)]
pub struct Loaded {
    /// The databases.
    pub geoip: Arc<GeoIp>,
    /// Warnings (stale databases under `on_stale: warn`).
    pub warnings: Vec<String>,
}

impl GeoIp {
    /// Loads the databases of `settings`, reusing files of `previous` that did not change.
    ///
    /// # Errors
    ///
    /// A file cannot be read or parsed, or is older than `max_age` with `on_stale: refuse`.
    pub fn load(
        settings: &GeoIpSettings,
        previous: Option<&GeoIp>,
        now: SystemTime,
    ) -> Result<Loaded, String> {
        let mut warnings = Vec::new();
        let mut open = |path: Option<&PathBuf>, old: Option<&Arc<Database>>, field: &str| {
            let Some(path) = path else {
                return Ok(None);
            };
            let reused = old
                .filter(|db| db.path == *path && stamp(path).is_ok_and(|s| s == db.stamp))
                .cloned();
            let db = match reused {
                Some(db) => db,
                None => Arc::new(Database::open(path).map_err(|e| format!("geoip.{field}: {e}"))?),
            };
            let age = db.age(now);
            let max = settings.max_age.as_std();
            if age > max {
                let message = format!(
                    "geoip.{field}: `{}` was built {} days ago, more than `max_age` ({} days); download a current file (the GeoLite EULA requires deleting versions within 30 days of a newer release)",
                    path.display(),
                    age.as_secs() / 86_400,
                    max.as_secs() / 86_400
                );
                match settings.on_stale {
                    OnStale::Refuse => return Err(message),
                    OnStale::Warn => warnings.push(message),
                }
            }
            Ok(Some(db))
        };
        let country = open(
            settings.database.as_ref(),
            previous.and_then(|p| p.country.as_ref()),
            "database",
        )?;
        let asn = open(
            settings.asn_database.as_ref(),
            previous.and_then(|p| p.asn.as_ref()),
            "asn_database",
        )?;
        Ok(Loaded {
            geoip: Arc::new(Self { country, asn }),
            warnings,
        })
    }

    /// The loaded databases by role (`country`, `asn`), for metrics.
    #[must_use]
    pub fn databases(&self) -> BTreeMap<&'static str, &Database> {
        let mut out = BTreeMap::new();
        if let Some(db) = &self.country {
            out.insert("country", db.as_ref());
        }
        if let Some(db) = &self.asn {
            out.insert("asn", db.as_ref());
        }
        out
    }

    /// Looks `ip` up. IPv4-mapped IPv6 addresses are looked up as IPv4.
    #[must_use]
    pub fn lookup(&self, ip: IpAddr) -> GeoRecord {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
            IpAddr::V4(_) => ip,
        };
        if !is_global(ip) {
            return GeoRecord::default();
        }
        let mut record = self
            .country
            .as_ref()
            .and_then(|db| db.lookup(ip))
            .map(Fields::into_record)
            .unwrap_or_default();
        if let Some(asn) = self
            .asn
            .as_ref()
            .and_then(|db| db.lookup(ip))
            .and_then(|f| f.into_record().asn)
        {
            record.asn = Some(asn);
        }
        record
    }
}

/// Whether `ip` is globally routable enough to be geolocated.
#[must_use]
pub fn is_global(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_global_v4(v4),
        IpAddr::V6(v6) => is_global_v6(v6),
    }
}

fn is_global_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_documentation()
        || a == 0
        || a >= 240
        // 100.64.0.0/10, shared address space (RFC 6598, CGNAT)
        || (a == 100 && (64..128).contains(&b))
        // 192.0.0.0/24, IETF protocol assignments
        || (a == 192 && b == 0 && c == 0)
        // 198.18.0.0/15, benchmarking
        || (a == 198 && (b == 18 || b == 19)))
}

fn is_global_v6(ip: Ipv6Addr) -> bool {
    let first = ip.segments()[0];
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        // fc00::/7 unique local
        || (first & 0xfe00) == 0xfc00
        // fe80::/10 link-local
        || (first & 0xffc0) == 0xfe80
        // 2001:db8::/32 documentation
        || (first == 0x2001 && ip.segments()[1] == 0x0db8)
        // ::/96 and other addresses in the first /16 (IPv4-compatible, 64:ff9b:: is global)
        || first == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_global_addresses() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "100.64.0.1",
            "169.254.1.1",
            "192.0.2.1",
            "0.0.0.0",
            "255.255.255.255",
            "::1",
            "fd00::1",
            "fe80::1",
            "2001:db8::1",
            "::",
        ] {
            assert!(!is_global(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["81.2.69.142", "89.160.20.112", "2001:218::1"] {
            assert!(is_global(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn both_record_shapes() {
        let geoip2 = Fields {
            country: Some(Named {
                iso_code: Some("GB".into()),
            }),
            continent: Some(Coded {
                code: Some("EU".into()),
            }),
            autonomous_system_number: Some(64496),
            ..Fields::default()
        }
        .into_record();
        assert_eq!(geoip2.country_str(), Some("GB"));
        assert_eq!(geoip2.continent, Some(*b"EU"));
        assert_eq!(geoip2.asn, Some(64496));
        let ipinfo = Fields {
            country_code: Some("se".into()),
            continent_code: Some("EU".into()),
            asn: Some("AS65551".into()),
            ..Fields::default()
        }
        .into_record();
        assert_eq!(ipinfo.country_str(), Some("SE"));
        assert_eq!(ipinfo.asn, Some(65551));
        assert_eq!(code(Some("DEU")), None);
    }
}
