//! Cloudflare's edge ranges (W-CF-01): the list compiled into the binary, the API response and
//! the cache file in the data directory.

use std::fs;
use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// The ranges compiled into the binary, used until a cache or a fetch replaces them.
///
/// Source: <https://www.cloudflare.com/ips-v4/> and <https://www.cloudflare.com/ips-v6/>,
/// which match `https://api.cloudflare.com/client/v4/ips` (checked 2026-10-28).
pub const BUILTIN: [&str; 22] = [
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
];

/// A list longer than this is not Cloudflare's.
const MAX_RANGES: usize = 1024;
/// Ranges wider than these would trust a large part of the internet; Cloudflare's widest are
/// a /13 and a /29.
const MIN_V4_PREFIX: u8 = 8;
const MIN_V6_PREFIX: u8 = 16;

/// Why a list of ranges was not accepted.
#[derive(Debug, thiserror::Error)]
pub enum InvalidList {
    /// The body is not the JSON the API documents.
    #[error("unexpected response: {0}")]
    Json(#[from] serde_json::Error),
    /// The API reported a failure.
    #[error("the API answered success: false")]
    NotSuccessful,
    /// There are no ranges, or more than any real list has.
    #[error("{0} ranges")]
    Count(usize),
    /// An entry is not a CIDR range of the right family.
    #[error("`{0}` is not an {1} CIDR range")]
    Range(String, &'static str),
    /// An entry covers too much of the address space to be an edge network.
    #[error("`{0}` is too wide")]
    TooWide(IpNet),
}

/// A validated list of ranges with the API's version tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpList {
    /// The `etag` of the list; it changes whenever the ranges do.
    pub etag: Option<String>,
    /// IPv4 and IPv6 ranges.
    pub ranges: Vec<IpNet>,
}

impl IpList {
    /// The list compiled into the binary.
    #[must_use]
    pub fn builtin() -> Self {
        Self {
            etag: None,
            ranges: BUILTIN.iter().filter_map(|r| r.parse().ok()).collect(),
        }
    }

    /// Parses the body of `GET /client/v4/ips`.
    pub fn from_api(body: &[u8]) -> Result<Self, InvalidList> {
        #[derive(Deserialize)]
        struct Response {
            success: bool,
            result: Option<Wire>,
        }
        let response: Response = serde_json::from_slice(body)?;
        match response.result {
            Some(wire) if response.success => wire.validate(),
            _ => Err(InvalidList::NotSuccessful),
        }
    }
}

/// The ranges as the API and the cache file spell them.
#[derive(Debug, Serialize, Deserialize)]
struct Wire {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    etag: Option<String>,
    ipv4_cidrs: Vec<String>,
    ipv6_cidrs: Vec<String>,
}

impl Wire {
    fn from_list(list: &IpList) -> Self {
        let family = |v4: bool| {
            list.ranges
                .iter()
                .filter(|net| matches!(net, IpNet::V4(_)) == v4)
                .map(ToString::to_string)
                .collect()
        };
        Self {
            etag: list.etag.clone(),
            ipv4_cidrs: family(true),
            ipv6_cidrs: family(false),
        }
    }

    fn validate(self) -> Result<IpList, InvalidList> {
        let count = self.ipv4_cidrs.len() + self.ipv6_cidrs.len();
        if count == 0 || count > MAX_RANGES {
            return Err(InvalidList::Count(count));
        }
        let mut ranges = Vec::with_capacity(count);
        for text in &self.ipv4_cidrs {
            ranges.push(range(text, true)?);
        }
        for text in &self.ipv6_cidrs {
            ranges.push(range(text, false)?);
        }
        Ok(IpList {
            etag: self.etag,
            ranges,
        })
    }
}

fn range(text: &str, v4: bool) -> Result<IpNet, InvalidList> {
    let family = if v4 { "IPv4" } else { "IPv6" };
    let net: IpNet = text
        .parse()
        .map_err(|_| InvalidList::Range(text.to_owned(), family))?;
    let min = match net.addr() {
        IpAddr::V4(_) if v4 => MIN_V4_PREFIX,
        IpAddr::V6(_) if !v4 => MIN_V6_PREFIX,
        _ => return Err(InvalidList::Range(text.to_owned(), family)),
    };
    if net.prefix_len() < min {
        return Err(InvalidList::TooWide(net));
    }
    Ok(net.trunc())
}

/// The cache file, `<dir>/ips.json`, holding the last list fetched and when.
#[derive(Debug, Clone)]
pub struct Cache {
    path: PathBuf,
}

/// What the cache file holds.
#[derive(Debug, Serialize, Deserialize)]
struct CacheFile {
    /// Unix seconds of the last successful fetch, changed or not.
    fetched_at: u64,
    #[serde(flatten)]
    list: Wire,
}

/// Why the cache could not be read or written.
#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    /// Reading or writing failed.
    #[error("{0}: {1}")]
    Io(PathBuf, io::Error),
    /// The file does not hold a valid list.
    #[error("{0}: {1}")]
    Invalid(PathBuf, InvalidList),
}

impl Cache {
    /// The cache in `dir` (normally `$RDOCK_DATA_DIR/cloudflare`).
    #[must_use]
    pub fn new(dir: &Path) -> Self {
        Self {
            path: dir.join("ips.json"),
        }
    }

    /// The cached list and the Unix time it was fetched, or `None` when there is no cache.
    pub fn load(&self) -> Result<Option<(IpList, u64)>, CacheError> {
        let bytes = match fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(CacheError::Io(self.path.clone(), err)),
        };
        let file: CacheFile = serde_json::from_slice(&bytes)
            .map_err(|e| CacheError::Invalid(self.path.clone(), e.into()))?;
        let list = file
            .list
            .validate()
            .map_err(|e| CacheError::Invalid(self.path.clone(), e))?;
        Ok(Some((list, file.fetched_at)))
    }

    /// Replaces the cache atomically (a temporary file renamed over it).
    pub fn save(&self, list: &IpList, fetched_at: u64) -> Result<(), CacheError> {
        let io_error = |e| CacheError::Io(self.path.clone(), e);
        let file = CacheFile {
            fetched_at,
            list: Wire::from_list(list),
        };
        let bytes = serde_json::to_vec_pretty(&file)
            .map_err(|e| CacheError::Invalid(self.path.clone(), e.into()))?;
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir).map_err(io_error)?;
        }
        let mut tmp = self.path.as_os_str().to_owned();
        tmp.push(".tmp");
        fs::write(&tmp, bytes).map_err(io_error)?;
        fs::rename(&tmp, &self.path).map_err(io_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BODY: &str = r#"{"result":{"ipv4_cidrs":["173.245.48.0/20"],"ipv6_cidrs":["2400:cb00::/32"],"etag":"abc"},"success":true,"errors":[],"messages":[]}"#;

    #[test]
    fn the_builtin_list_parses_completely() {
        let list = IpList::builtin();
        assert_eq!(list.ranges.len(), BUILTIN.len());
        let edge: IpAddr = "104.16.0.1".parse().unwrap();
        assert!(list.ranges.iter().any(|n| n.contains(&edge)));
    }

    #[test]
    fn parses_the_api_response() {
        let list = IpList::from_api(BODY.as_bytes()).unwrap();
        assert_eq!(list.etag.as_deref(), Some("abc"));
        assert_eq!(list.ranges.len(), 2);
    }

    #[test]
    fn refuses_lists_that_could_trust_everyone() {
        let body = |v4: &str, v6: &str, success: bool| {
            format!(
                r#"{{"result":{{"ipv4_cidrs":[{v4}],"ipv6_cidrs":[{v6}],"etag":"x"}},"success":{success}}}"#
            )
        };
        let cases = [
            body(r#""0.0.0.0/0""#, "", true),
            body(r#""2400:cb00::/32""#, "", true),
            body("", r#""::/0""#, true),
            body(r#""nonsense""#, "", true),
            body("", "", true),
            body(r#""173.245.48.0/20""#, "", false),
        ];
        for case in cases {
            assert!(IpList::from_api(case.as_bytes()).is_err(), "{case}");
        }
        assert!(IpList::from_api(b"<html>").is_err());
    }

    #[test]
    fn the_cache_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::new(&dir.path().join("cloudflare"));
        assert!(cache.load().unwrap().is_none());
        let list = IpList::from_api(BODY.as_bytes()).unwrap();
        cache.save(&list, 42).unwrap();
        assert_eq!(cache.load().unwrap(), Some((list, 42)));
        std::fs::write(dir.path().join("cloudflare/ips.json"), "{}").unwrap();
        assert!(cache.load().is_err());
    }
}
