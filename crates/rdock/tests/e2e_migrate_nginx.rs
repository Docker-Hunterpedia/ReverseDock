//! End-to-end: an NGINX configuration migrated with `rdock migrate nginx` and run by rdock picks
//! the same location and sends the same upstream path as NGINX's documented algorithm
//! (`crates/rdock-migrate/tests/support/nginx_reference.rs`, an independent implementation) for a
//! matrix of requests: location precedence (`=`, `^~`, regular expressions in order, the longest
//! prefix), the trailing-slash redirect, and the `proxy_pass` URI cases.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "../../rdock-migrate/tests/support/nginx_reference.rs"]
mod nginx_reference;

use std::fmt::Write as _;
use std::net::SocketAddr;

use nginx_reference::{Location, Mod, Outcome, select, upstream_path};
use rdock_testkit::backend::Backend;
use rdock_testkit::client::{self, get};
use rdock_testkit::free_port;
use rdock_testkit::rdock::Rdock;

const RDOCK: &str = env!("CARGO_BIN_EXE_rdock");
const HOST: &str = "nginx.test";

fn loc(modifier: Mod, uri: &str, proxy_uri: Option<&str>) -> Location {
    Location {
        modifier,
        uri: uri.to_owned(),
        proxy_uri: proxy_uri.map(str::to_owned),
    }
}

fn collapse(path: &str) -> String {
    let mut out = String::new();
    for c in path.chars() {
        if !(c == '/' && out.ends_with('/')) {
            out.push(c);
        }
    }
    out
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // the locations, the request matrix and the comparison in one place
async fn migrated_locations_and_upstream_paths_match_nginx() {
    let locations = vec![
        loc(Mod::Exact, "/", None),
        loc(Mod::Prefix, "/", None),
        loc(Mod::Prefix, "/documents/", None),
        loc(Mod::Preferential, "/images/", None),
        loc(Mod::Regex(true), r"\.(gif|jpg|jpeg)$", None),
        loc(Mod::Prefix, "/images/raw/", Some("/originals/")),
        loc(Mod::Prefix, "/name/", Some("/remote/")),
        loc(Mod::Prefix, "/strip/", Some("/")),
        loc(Mod::Prefix, "/noslash", Some("/")),
        loc(Mod::Prefix, "/join/", Some("/joined")),
        loc(Mod::Exact, "/exact", Some("/elsewhere")),
        loc(Mod::Regex(false), "^/api/v[0-9]+/", None),
    ];
    let mut backends = Vec::new();
    for i in 0..locations.len() {
        backends.push(Backend::start(&format!("loc{i}")).await);
    }
    let mut conf = format!("http {{\n  server {{\n    listen 80;\n    server_name {HOST};\n");
    for (i, l) in locations.iter().enumerate() {
        let _ = writeln!(
            conf,
            "    location {} {{ proxy_pass http://{}{}; }}",
            l.header(),
            backends[i].addr,
            l.proxy_uri.clone().unwrap_or_default()
        );
    }
    conf.push_str("  }\n}\n");
    let migration = rdock_migrate::nginx::nginx(
        &conf,
        &rdock_migrate::nginx::Options {
            file: "nginx.conf".into(),
            full: true,
            ..Default::default()
        },
    )
    .unwrap();
    let port = free_port();
    assert!(
        migration.yaml.contains("address: \":80\""),
        "{}",
        migration.yaml
    );
    let config = migration.yaml.replace(
        "address: \":80\"",
        &format!("address: \"127.0.0.1:{port}\""),
    );
    let _rdock = Rdock::start(RDOCK, &config);
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let requests = [
        "/",
        "/index.html",
        "/documents/document.html",
        "/documents",
        "/images/1.gif",
        "/documents/1.jpg",
        "/images",
        "/images/raw/2.png",
        "/images/raw/3.JPG",
        "/name/a/b?x=1",
        "/name",
        "/strip/x",
        "/strip",
        "/noslash",
        "/noslash/x",
        "/noslashy",
        "/join/q",
        "/exact",
        "/exact/no",
        "/api/v2/users",
        "/api/vx/users",
        "/X.Gif",
    ];
    let mut failures = Vec::new();
    for request in requests {
        let (path, query) = request
            .split_once('?')
            .map_or((request, None), |(p, q)| (p, Some(q)));
        let expected = select(&locations, path);
        let reply = client::http1(addr, get(HOST, request)).await;
        match &expected {
            Outcome::Location(i) => {
                let want_path = collapse(&upstream_path(&locations[*i], path));
                let want = match query {
                    Some(q) => format!("{want_path}?{q}"),
                    None => want_path,
                };
                if reply.status != 200 {
                    failures.push(format!(
                        "{request}: NGINX location {i}, rdock status {}",
                        reply.status
                    ));
                    continue;
                }
                let body = reply.json();
                if body["backend"] != format!("loc{i}") || body["target"] != want {
                    failures.push(format!(
                        "{request}: NGINX loc{i} with {want}, rdock {} with {}",
                        body["backend"], body["target"]
                    ));
                }
            }
            Outcome::Redirect(to) => {
                let location = reply.header("location").unwrap_or_default();
                if reply.status != 301 || !location.ends_with(to.as_str()) {
                    failures.push(format!(
                        "{request}: NGINX 301 to {to}, rdock {} {location}",
                        reply.status
                    ));
                }
            }
            Outcome::None => {
                if reply.status != 404 {
                    failures.push(format!(
                        "{request}: NGINX no location, rdock {}",
                        reply.status
                    ));
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{}\n\n{}",
        failures.join("\n"),
        migration.yaml
    );
}
