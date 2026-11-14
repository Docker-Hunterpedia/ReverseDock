//! An independent implementation of NGINX's location selection and `proxy_pass` URI rule, written
//! from the official reference (read 2026-11-14), used to check what `rdock migrate nginx`
//! writes, in `rdock-migrate`'s tests and in `rdock`'s end-to-end test.
//!
//! - <https://nginx.org/en/docs/http/ngx_http_core_module.html#location>: "nginx first checks
//!   locations defined using the prefix strings (prefix locations). Among them, the location with
//!   the longest matching prefix is selected and remembered. Then regular expressions are checked,
//!   in the order of their appearance in the configuration file. The search of regular expressions
//!   terminates on the first match … If no match with a regular expression is found … the
//!   configuration of the prefix location remembered earlier is used." "If the longest matching
//!   prefix location has the `^~` modifier then regular expressions are not checked." "If an exact
//!   match is found, the search terminates." "If a location is defined by a prefix string that ends
//!   with the slash character, and requests are processed by one of `proxy_pass` … In response to a
//!   request with URI equal to this string, but without the trailing slash, a permanent redirect
//!   with the code 301 will be returned to the requested URI with the slash appended." (NGINX does
//!   this when no location is named exactly as the request, before regular expressions.)
//! - <https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_pass>: "If the `proxy_pass`
//!   directive is specified with a URI, then … the part of a normalized request URI matching the
//!   location is replaced by a URI specified in the directive"; "If `proxy_pass` is specified
//!   without a URI, the request URI is passed to the server in the same form as sent by a client".

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

/// A location modifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mod {
    /// `=`
    Exact,
    /// `^~`
    Preferential,
    /// `~` (false) or `~*` (true)
    Regex(bool),
    /// none
    Prefix,
}

/// One location that proxies.
#[derive(Debug, Clone)]
pub struct Location {
    pub modifier: Mod,
    pub uri: String,
    /// The URI part of `proxy_pass` (`None`: none).
    pub proxy_uri: Option<String>,
}

impl Location {
    /// The `location` line's argument part.
    pub fn header(&self) -> String {
        match self.modifier {
            Mod::Exact => format!("= {}", self.uri),
            Mod::Preferential => format!("^~ {}", self.uri),
            Mod::Regex(false) => format!("~ {}", self.uri),
            Mod::Regex(true) => format!("~* {}", self.uri),
            Mod::Prefix => self.uri.clone(),
        }
    }
}

/// What NGINX does with a request URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The location at this index answers.
    Location(usize),
    /// A 301 to this path (the trailing-slash redirect).
    Redirect(String),
    /// No location matches.
    None,
}

fn is_static(m: Mod) -> bool {
    matches!(m, Mod::Exact | Mod::Preferential | Mod::Prefix)
}

/// NGINX's choice for `uri` (every location proxies).
pub fn select(locations: &[Location], uri: &str) -> Outcome {
    if let Some(i) = locations
        .iter()
        .position(|l| l.modifier == Mod::Exact && l.uri == uri)
    {
        return Outcome::Location(i);
    }
    if !locations
        .iter()
        .any(|l| is_static(l.modifier) && l.uri == uri)
    {
        let with_slash = format!("{uri}/");
        if let Some(l) = locations
            .iter()
            .find(|l| matches!(l.modifier, Mod::Preferential | Mod::Prefix) && l.uri == with_slash)
        {
            return Outcome::Redirect(l.uri.clone());
        }
    }
    let best = locations
        .iter()
        .enumerate()
        .filter(|(_, l)| {
            matches!(l.modifier, Mod::Preferential | Mod::Prefix) && uri.starts_with(l.uri.as_str())
        })
        .max_by_key(|(_, l)| l.uri.len());
    if let Some((i, l)) = best
        && l.modifier == Mod::Preferential
    {
        return Outcome::Location(i);
    }
    for (i, l) in locations.iter().enumerate() {
        if let Mod::Regex(ci) = l.modifier {
            let pattern = if ci {
                format!("(?i){}", l.uri)
            } else {
                l.uri.clone()
            };
            if regex::Regex::new(&pattern).unwrap().is_match(uri) {
                return Outcome::Location(i);
            }
        }
    }
    best.map_or(Outcome::None, |(i, _)| Outcome::Location(i))
}

/// The path NGINX sends upstream for `uri` handled by `location`.
pub fn upstream_path(location: &Location, uri: &str) -> String {
    match (&location.proxy_uri, location.modifier) {
        (None, _) => uri.to_owned(),
        (Some(u), Mod::Exact) => u.clone(),
        (Some(u), _) => format!("{u}{}", &uri[location.uri.len()..]),
    }
}
