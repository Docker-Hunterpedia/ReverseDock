//! Location precedence and `proxy_pass` URIs: `rdock migrate nginx`'s routes, evaluated with
//! ReverseDock's routing rules (priority first, then name; `PathPrefix` is a string prefix,
//! `PathRegexp` searches the path) and its path middlewares, must give the same answer as an
//! independent implementation of NGINX's documented algorithm (`support/nginx_reference.rs`) for
//! every request: a fixed table of the documented cases, and random location sets.
//! The end-to-end test `crates/rdock/tests/e2e_migrate_nginx.rs` checks the same against the
//! real router.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "support/nginx_reference.rs"]
mod nginx_reference;

use std::fmt::Write as _;

use nginx_reference::{Location, Mod, Outcome, select, upstream_path};
use proptest::prelude::*;
use rdock_migrate::nginx::{Options, nginx};
use rdock_rules::{Expr, Matcher};
use serde_json::Value;

const HOST: &str = "t.example";

/// The configuration: one server, location `i` proxies to `loc<i>`.
fn config(locations: &[Location]) -> String {
    let mut text = format!("http {{\n server {{\n  listen 80;\n  server_name {HOST};\n");
    for (i, l) in locations.iter().enumerate() {
        let uri = l.proxy_uri.clone().unwrap_or_default();
        let _ = writeln!(
            text,
            "  location {} {{ proxy_pass http://loc{i}:80{uri}; }}",
            l.header()
        );
    }
    text.push_str(" }\n}\n");
    text
}

fn matches(expr: &Expr, path: &str) -> bool {
    match expr {
        Expr::Matcher(m) => match m {
            Matcher::Host(h) => h == HOST,
            Matcher::Path(p) => p == path,
            Matcher::PathPrefix(p) => path.starts_with(p.as_str()),
            Matcher::PathRegexp(re) => regex::Regex::new(re).unwrap().is_match(path),
            other => panic!("unexpected matcher {other:?}"),
        },
        Expr::Not(e) => !matches(e, path),
        Expr::And(all) => all.iter().all(|e| matches(e, path)),
        Expr::Or(any) => any.iter().any(|e| matches(e, path)),
    }
}

#[allow(clippy::assigning_clones)] // `rest` borrows `current`
/// What the migrated configuration does: the location answering (by its backend) and the path
/// it receives, or a redirect, or nothing.
fn migrated(document: &Value, path: &str) -> (Outcome, Option<String>) {
    let routes = document["routes"].as_object().cloned().unwrap_or_default();
    let mut candidates: Vec<(i64, String, &Value)> = Vec::new();
    for (name, route) in &routes {
        if route.get("enabled") == Some(&Value::Bool(false)) {
            continue;
        }
        let rule = rdock_rules::parse(route["match"].as_str().unwrap()).unwrap();
        if matches(&rule, path) {
            candidates.push((route["priority"].as_i64().unwrap(), name.clone(), route));
        }
    }
    candidates.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    let Some((_, _, route)) = candidates.first() else {
        return (Outcome::None, None);
    };
    let mut current = path.to_owned();
    for name in route["middlewares"].as_array().cloned().unwrap_or_default() {
        let m = &document["middlewares"][name.as_str().unwrap()];
        match m["type"].as_str().unwrap() {
            "redirect" => {
                return (
                    Outcome::Redirect(m["path"].as_str().unwrap().to_owned()),
                    None,
                );
            }
            "strip_prefix" => {
                for p in m["prefixes"].as_array().unwrap() {
                    if let Some(rest) = current.strip_prefix(p.as_str().unwrap()) {
                        current = if rest.starts_with('/') {
                            rest.to_owned()
                        } else {
                            format!("/{rest}")
                        };
                        break;
                    }
                }
            }
            "add_prefix" => {
                current = format!(
                    "{}{current}",
                    m["prefix"].as_str().unwrap().trim_end_matches('/')
                );
            }
            "replace_path" => current = m["path"].as_str().unwrap().to_owned(),
            "rewrite" => {
                let re = regex::Regex::new(m["regex"].as_str().unwrap()).unwrap();
                if re.is_match(&current) {
                    let out = re
                        .replace_all(&current, m["replacement"].as_str().unwrap())
                        .into_owned();
                    current = if out.starts_with('/') {
                        out
                    } else {
                        format!("/{out}")
                    };
                }
            }
            other => panic!("unexpected middleware {other}"),
        }
    }
    let service = route["service"].as_str().unwrap();
    let address = document["services"][service]["backends"][0]["address"]
        .as_str()
        .unwrap();
    let index: usize = address
        .trim_start_matches("loc")
        .trim_end_matches(":80")
        .parse()
        .unwrap();
    (Outcome::Location(index), Some(current))
}

/// Checks every request; returns the mismatches.
fn check(locations: &[Location], requests: &[&str]) -> Vec<String> {
    let text = config(locations);
    let m = nginx(
        &text,
        &Options {
            file: "nginx.conf".into(),
            ..Options::default()
        },
    )
    .unwrap();
    let document: Value = serde_saphyr::from_str(&m.yaml).unwrap();
    let mut failures = Vec::new();
    for request in requests {
        let expected = select(locations, request);
        let (actual, path) = migrated(&document, request);
        if expected != actual {
            failures.push(format!(
                "{request}: NGINX {expected:?}, migrated {actual:?}\n{text}"
            ));
            continue;
        }
        if let Outcome::Location(i) = expected {
            let want = upstream_path(&locations[i], request);
            // NGINX may send an empty path segment (`/a` + `/b/` → `/b//c`); ReverseDock sends one
            // slash, which the migration reports as approximate.
            let want = collapse(&want);
            if path.as_deref() != Some(want.as_str()) {
                failures.push(format!(
                    "{request}: NGINX sends {want}, migrated {path:?}\n{text}"
                ));
            }
        }
    }
    failures
}

fn collapse(path: &str) -> String {
    let mut out = String::new();
    for c in path.chars() {
        if c == '/' && out.ends_with('/') {
            continue;
        }
        out.push(c);
    }
    out
}

fn loc(modifier: Mod, uri: &str, proxy_uri: Option<&str>) -> Location {
    Location {
        modifier,
        uri: uri.to_owned(),
        proxy_uri: proxy_uri.map(str::to_owned),
    }
}

#[test]
fn the_documented_example_selects_the_same_locations() {
    // The example of the `location` reference, each block proxying.
    let locations = vec![
        loc(Mod::Exact, "/", None),
        loc(Mod::Prefix, "/", None),
        loc(Mod::Prefix, "/documents/", None),
        loc(Mod::Preferential, "/images/", None),
        loc(Mod::Regex(true), r"\.(gif|jpg|jpeg)$", None),
    ];
    let requests = [
        "/",
        "/index.html",
        "/documents/document.html",
        "/images/1.gif",
        "/documents/1.jpg",
        "/documents",
        "/images",
        "/x.GIF",
    ];
    let failures = check(&locations, &requests);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    // As the reference says: "/" → A, "/index.html" → B, "/documents/document.html" → C,
    // "/images/1.gif" → D, "/documents/1.jpg" → E.
    assert_eq!(select(&locations, "/documents/1.jpg"), Outcome::Location(4));
    assert_eq!(select(&locations, "/images/1.gif"), Outcome::Location(3));
}

#[test]
fn proxy_pass_uris_give_the_same_upstream_paths() {
    let locations = vec![
        loc(Mod::Prefix, "/name/", Some("/remote/")),
        loc(Mod::Prefix, "/strip/", Some("/")),
        loc(Mod::Prefix, "/noslash", Some("/")),
        loc(Mod::Prefix, "/join/", Some("/joined")),
        loc(Mod::Prefix, "/", Some("/base/")),
        loc(Mod::Exact, "/exact", Some("/elsewhere")),
        loc(Mod::Prefix, "/asis/", None),
        loc(Mod::Preferential, "/pref/", Some("/p/")),
        loc(Mod::Prefix, "/top", Some("/x")),
    ];
    let requests = [
        "/name/a/b",
        "/name/",
        "/name",
        "/strip/x",
        "/strip/",
        "/noslash",
        "/noslash/x",
        "/noslashy",
        "/join/q",
        "/join/",
        "/other",
        "/",
        "/exact",
        "/exact/no",
        "/asis/k?q=1",
        "/asis",
        "/pref/z",
        "/pref",
        "/top",
        "/topper",
        "/top/a",
    ];
    let failures = check(&locations, &requests);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn preferential_prefixes_lose_to_longer_plain_prefixes() {
    let locations = vec![
        loc(Mod::Preferential, "/static/", None),
        loc(Mod::Prefix, "/static/img/", None),
        loc(Mod::Regex(false), r"\.png$", None),
        loc(Mod::Preferential, "/static/img/raw/", None),
    ];
    let requests = [
        "/static/a.png",
        "/static/img/a.png",
        "/static/img/a.txt",
        "/static/img/raw/a.png",
        "/static/img",
        "/static",
        "/x.png",
    ];
    let failures = check(&locations, &requests);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

fn segment() -> impl Strategy<Value = String> {
    prop::sample::select(vec!["a", "b", "ab", "x", "A"]).prop_map(str::to_owned)
}

fn uri() -> impl Strategy<Value = String> {
    (prop::collection::vec(segment(), 0..3), any::<bool>()).prop_map(|(segments, slash)| {
        let mut uri = format!("/{}", segments.join("/"));
        if slash && uri.len() > 1 {
            uri.push('/');
        }
        uri
    })
}

fn location() -> impl Strategy<Value = Location> {
    let regex = prop::sample::select(vec!["^/a", "b$", r"\.x$", "/ab/", "^/a/b", "x"]);
    prop_oneof![
        (
            uri(),
            prop::option::of(prop::sample::select(vec!["/", "/u/", "/u"]))
        )
            .prop_map(|(u, p)| loc(Mod::Prefix, &u, p)),
        (
            uri(),
            prop::option::of(prop::sample::select(vec!["/", "/u/"]))
        )
            .prop_map(|(u, p)| loc(Mod::Preferential, &u, p)),
        (uri(), prop::option::of(prop::sample::select(vec!["/e"]))).prop_map(|(u, p)| loc(
            Mod::Exact,
            &u,
            p
        )),
        (regex, any::<bool>()).prop_map(|(r, ci)| loc(Mod::Regex(ci), r, None)),
    ]
}

fn request() -> impl Strategy<Value = String> {
    (
        uri(),
        prop::option::of(prop::sample::select(vec![".x", ".X", "b"])),
    )
        .prop_map(|(u, s)| format!("{u}{}", s.unwrap_or("")))
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    #[test]
    fn random_locations_select_like_nginx(mut locations in prop::collection::vec(location(), 1..7), requests in prop::collection::vec(request(), 1..12)) {
        // NGINX refuses duplicate locations: keep the first of each name per kind.
        let mut seen = std::collections::BTreeSet::new();
        locations.retain(|l| {
            let key = match l.modifier { Mod::Exact => format!("={}", l.uri), Mod::Regex(_) => format!("~{}", l.uri), _ => format!("p{}", l.uri) };
            seen.insert(key)
        });
        let requests: Vec<&str> = requests.iter().map(String::as_str).collect();
        let failures = check(&locations, &requests);
        prop_assert!(failures.is_empty(), "{}", failures.join("\n"));
    }
}
