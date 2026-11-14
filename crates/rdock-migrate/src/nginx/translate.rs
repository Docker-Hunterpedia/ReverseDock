//! Servers, locations and directives → listeners, routes, services and middlewares.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use serde_json::{Map, Value, json};

use super::Run;
use super::parser::Directive;
use crate::output::{self, escape, literal_replacement};

/// Priority tiers (times [`SUB`]): a server's `return` and redirecting `rewrite`s run before
/// location selection; then exact locations and the trailing-slash redirect; `^~` prefixes;
/// regular expressions in file order; plain prefixes, longest first; the server's own content.
const TIER_SERVER_RETURN: i64 = 700_000;
const TIER_SERVER_REWRITE: i64 = 600_000;
const TIER_EXACT: i64 = 500_000;
const TIER_PREFERENTIAL: i64 = 400_000;
const TIER_REGEX: i64 = 300_000;
const TIER_PREFIX: i64 = 200_000;
const TIER_SERVER: i64 = 100_000;
/// Room for a location's redirecting `rewrite`s above its own route.
const SUB: i64 = 10;

/// Directives that need no translation: process, buffer and file tuning without an effect on
/// routing, or behaviour ReverseDock has built in.
const NO_EFFECT: &[(&str, &str)] = &[
    ("user", "process settings"),
    ("worker_processes", "process settings"),
    ("worker_rlimit_nofile", "process settings"),
    ("worker_connections", "process settings"),
    ("worker_shutdown_timeout", "process settings"),
    ("worker_cpu_affinity", "process settings"),
    ("worker_priority", "process settings"),
    ("multi_accept", "process settings"),
    ("use", "process settings"),
    ("accept_mutex", "process settings"),
    ("pid", "process settings"),
    ("daemon", "process settings"),
    ("master_process", "process settings"),
    ("pcre_jit", "process settings"),
    ("thread_pool", "process settings"),
    ("timer_resolution", "process settings"),
    ("lock_file", "process settings"),
    ("env", "process settings"),
    ("load_module", "dynamic modules"),
    ("sendfile", "I/O tuning"),
    ("tcp_nopush", "I/O tuning"),
    ("tcp_nodelay", "I/O tuning"),
    ("aio", "I/O tuning"),
    ("directio", "I/O tuning"),
    ("output_buffers", "buffer tuning"),
    ("types_hash_max_size", "hash table tuning"),
    ("types_hash_bucket_size", "hash table tuning"),
    ("server_names_hash_bucket_size", "hash table tuning"),
    ("server_names_hash_max_size", "hash table tuning"),
    ("variables_hash_max_size", "hash table tuning"),
    ("variables_hash_bucket_size", "hash table tuning"),
    ("map_hash_bucket_size", "hash table tuning"),
    ("map_hash_max_size", "hash table tuning"),
    ("proxy_headers_hash_max_size", "hash table tuning"),
    ("proxy_headers_hash_bucket_size", "hash table tuning"),
    ("client_body_buffer_size", "buffer tuning"),
    ("client_header_buffer_size", "buffer tuning"),
    ("proxy_buffer_size", "buffer tuning"),
    ("proxy_buffers", "buffer tuning"),
    ("proxy_busy_buffers_size", "buffer tuning"),
    ("proxy_max_temp_file_size", "buffer tuning"),
    ("proxy_temp_file_write_size", "buffer tuning"),
    ("proxy_temp_path", "buffer tuning"),
    ("client_body_temp_path", "buffer tuning"),
    ("open_file_cache", "file cache tuning"),
    ("open_file_cache_valid", "file cache tuning"),
    ("open_file_cache_min_uses", "file cache tuning"),
    ("open_file_cache_errors", "file cache tuning"),
    ("reset_timedout_connection", "connection tuning"),
    ("lingering_close", "connection tuning"),
    ("lingering_time", "connection tuning"),
    ("lingering_timeout", "connection tuning"),
    ("keepalive_requests", "connection tuning"),
    ("http2_max_concurrent_streams", "HTTP/2 tuning"),
    ("http2_recv_buffer_size", "HTTP/2 tuning"),
    ("http2_chunk_size", "HTTP/2 tuning"),
    ("ssl_buffer_size", "TLS tuning"),
    (
        "ssl_session_timeout",
        "TLS session resumption, which ReverseDock manages",
    ),
    (
        "ssl_session_cache",
        "TLS session resumption, which ReverseDock manages",
    ),
    (
        "ssl_session_tickets",
        "TLS session resumption, which ReverseDock manages",
    ),
    (
        "ssl_dhparam",
        "finite-field Diffie-Hellman, which ReverseDock does not offer",
    ),
    (
        "ssl_ecdh_curve",
        "the key exchange groups, which ReverseDock chooses",
    ),
    ("ssl_stapling", "OCSP stapling, which ReverseDock manages"),
    (
        "ssl_stapling_verify",
        "OCSP stapling, which ReverseDock manages",
    ),
    (
        "ssl_trusted_certificate",
        "OCSP stapling, which ReverseDock manages",
    ),
    (
        "ssl_prefer_server_ciphers",
        "the cipher order, which ReverseDock's policy fixes",
    ),
    (
        "server_tokens",
        "the version in `Server` (ReverseDock sends none)",
    ),
    (
        "default_type",
        "the default media type (ReverseDock's static files have their own table)",
    ),
    (
        "types",
        "media types (ReverseDock's static files have their own table)",
    ),
    ("charset", "the charset of text answers"),
    ("source_charset", "the charset of text answers"),
    (
        "resolver",
        "DNS resolution of backends, which ReverseDock does itself",
    ),
    (
        "resolver_timeout",
        "DNS resolution of backends, which ReverseDock does itself",
    ),
    (
        "proxy_redirect",
        "rewriting `Location` headers from backends (see the report's default note)",
    ),
    (
        "proxy_pass_header",
        "headers NGINX hides by default, which ReverseDock passes anyway",
    ),
    (
        "proxy_ignore_client_abort",
        "ReverseDock stops the backend request when the client goes away",
    ),
    (
        "absolute_redirect",
        "absolute redirects (ReverseDock's are absolute)",
    ),
    ("port_in_redirect", "the port in redirects"),
    ("server_name_in_redirect", "the host name in redirects"),
    ("msie_padding", "old browser workarounds"),
    ("msie_refresh", "old browser workarounds"),
    (
        "gzip_static",
        "precompressed files (ReverseDock's `static` serves them with `precompressed`)",
    ),
    (
        "etag",
        "entity tags (ReverseDock's static files always have them)",
    ),
    (
        "if_modified_since",
        "conditional requests (ReverseDock's static files answer them)",
    ),
    ("log_not_found", "logging"),
    ("log_subrequest", "logging"),
    ("open_log_file_cache", "logging"),
    (
        "underscores_in_headers",
        "headers with underscores (ReverseDock drops forwarding headers spelled with `_` from untrusted clients)",
    ),
    (
        "ignore_invalid_headers",
        "invalid header names (ReverseDock refuses them)",
    ),
    ("recursive_error_pages", "error page handling"),
    ("break", "stopping rewrite directives (nothing follows)"),
];

/// Directive prefixes refused by construct: (prefix, reason, hint, blocks the routes).
const REFUSED_PREFIX: &[(&str, &str, &str, bool)] = &[
    (
        "proxy_cache",
        "caching (`proxy_cache*`) is not migrated in this version",
        "use the `cache` middleware and `caches` (see the HTTP cache guide)",
        false,
    ),
    (
        "proxy_store",
        "storing proxied files has no equivalent",
        "",
        false,
    ),
    (
        "fastcgi_",
        "FastCGI has no equivalent (F-WEB-04 is not implemented)",
        "run the application behind an HTTP server and proxy to it",
        true,
    ),
    (
        "uwsgi_",
        "uWSGI has no equivalent",
        "run the application with its HTTP server and proxy to it",
        true,
    ),
    (
        "scgi_",
        "SCGI has no equivalent",
        "run the application with an HTTP server and proxy to it",
        true,
    ),
    ("memcached_", "memcached has no equivalent", "", true),
    (
        "js_",
        "njs scripting has no equivalent",
        "a native plugin (`type: plugin`) or a backend",
        true,
    ),
    (
        "perl",
        "Perl scripting has no equivalent",
        "a native plugin (`type: plugin`) or a backend",
        true,
    ),
    (
        "lua_",
        "Lua scripting has no equivalent",
        "a native plugin (`type: plugin`) or a backend",
        true,
    ),
    (
        "sub_filter",
        "rewriting response bodies (`sub_filter`) has no equivalent",
        "the `transform` middleware rewrites JSON bodies",
        false,
    ),
    (
        "limit_req",
        "`limit_req` delays excess requests and answers 503 by default; ReverseDock's `rate_limit` answers 429 at once, so it is not migrated in this version",
        "if a 429 at once is acceptable, write a `rate_limit` middleware (`average`, `period`, `burst`)",
        false,
    ),
    (
        "limit_conn",
        "`limit_conn` answers 503 by default; ReverseDock's `in_flight` answers 429, so it is not migrated in this version",
        "if 429 is acceptable, write an `in_flight` middleware (`amount`)",
        false,
    ),
    (
        "geo",
        "`geo` (variables from client addresses) has no equivalent",
        "`ClientIP(…)` matchers or the `ip_allow`/`ip_deny` middlewares",
        false,
    ),
    (
        "split_clients",
        "`split_clients` has no equivalent",
        "a weighted split service (`split`)",
        false,
    ),
    (
        "mirror",
        "`mirror` is not migrated",
        "the route's `mirror` (`service`, `percent`)",
        false,
    ),
    ("ssi", "server-side includes have no equivalent", "", false),
    (
        "image_filter",
        "image filtering has no equivalent",
        "",
        false,
    ),
    ("xslt", "XSLT has no equivalent", "", false),
    ("secure_link", "secure links have no equivalent", "", true),
    (
        "auth_jwt",
        "`auth_jwt` (NGINX Plus) is not migrated",
        "the `jwt` middleware",
        true,
    ),
    (
        "health_check",
        "`health_check` (NGINX Plus) is not migrated",
        "`health.active` on the service",
        false,
    ),
    (
        "sticky",
        "`sticky` (NGINX Plus) is not migrated",
        "`sticky.cookie` on the service",
        false,
    ),
];

/// One location of a server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Modifier {
    Exact,
    Preferential,
    Regex { case_insensitive: bool },
    Prefix,
    Named,
    Predicate,
}

struct Loc<'t> {
    d: &'t Directive,
    modifier: Modifier,
    uri: String,
}

fn parse_location(d: &Directive) -> Option<(Modifier, String)> {
    let args = d.values();
    match args.as_slice() {
        ["=", uri] => Some((Modifier::Exact, (*uri).to_owned())),
        ["^~", uri] => Some((Modifier::Preferential, (*uri).to_owned())),
        ["~", re] => Some((
            Modifier::Regex {
                case_insensitive: false,
            },
            (*re).to_owned(),
        )),
        ["~*", re] => Some((
            Modifier::Regex {
                case_insensitive: true,
            },
            (*re).to_owned(),
        )),
        [uri] if uri.starts_with('@') => Some((Modifier::Named, (*uri).to_owned())),
        [uri] if uri.starts_with('$') => Some((Modifier::Predicate, (*uri).to_owned())),
        [uri] if uri.starts_with('=') && uri.len() > 1 => {
            Some((Modifier::Exact, uri[1..].to_owned()))
        }
        [uri] if uri.starts_with("^~") && uri.len() > 2 => {
            Some((Modifier::Preferential, uri[2..].to_owned()))
        }
        [uri] if uri.starts_with("~*") && uri.len() > 2 => Some((
            Modifier::Regex {
                case_insensitive: true,
            },
            uri[2..].to_owned(),
        )),
        [uri] if uri.starts_with('~') && uri.len() > 1 => Some((
            Modifier::Regex {
                case_insensitive: false,
            },
            uri[1..].to_owned(),
        )),
        [uri] => Some((Modifier::Prefix, (*uri).to_owned())),
        _ => None,
    }
}

/// The innermost occurrence of a directive (normal inheritance: an inner level overrides).
fn last<'t>(levels: &[&'t [Directive]], name: &str) -> Option<&'t Directive> {
    levels.iter().rev().find_map(|level| {
        level
            .iter()
            .rev()
            .find(|d| d.name == name && d.block.is_none())
    })
}

/// The occurrences of the innermost level that has any of `names` ("inherited from the previous
/// configuration level if and only if there are no … directives defined on the current level").
fn list<'t>(levels: &[&'t [Directive]], names: &[&str]) -> Vec<&'t Directive> {
    for level in levels.iter().rev() {
        let found: Vec<&Directive> = level
            .iter()
            .filter(|d| names.contains(&d.name.as_str()) && d.block.is_none())
            .collect();
        if !found.is_empty() {
            return found;
        }
    }
    Vec::new()
}

/// An NGINX time (`60s`, `1m30s`, `500ms`, `60` = seconds) as a ReverseDock duration.
fn time(text: &str) -> Option<String> {
    let mut total_ms: u64 = 0;
    let mut rest = text.trim();
    if rest.is_empty() {
        return None;
    }
    while !rest.is_empty() {
        let end = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        let n: u64 = rest[..end].parse().ok()?;
        rest = &rest[end..];
        let unit_end = rest
            .find(|c: char| c.is_ascii_digit())
            .unwrap_or(rest.len());
        let factor = match &rest[..unit_end] {
            "" | "s" => 1_000,
            "ms" => 1,
            "m" => 60_000,
            "h" => 3_600_000,
            "d" => 86_400_000,
            "w" => 604_800_000,
            "M" => 2_592_000_000,
            "y" => 31_536_000_000,
            _ => return None,
        };
        total_ms = total_ms.checked_add(n.checked_mul(factor)?)?;
        rest = &rest[unit_end..];
    }
    Some(rdock_model::values::Duration::from_millis(total_ms).to_string())
}

/// An NGINX size (`1m` = 1 MiB, `10k`, `1g`, `1024`) in bytes.
fn size(text: &str) -> Option<u64> {
    let text = text.trim();
    let (number, factor) = match text.chars().last()? {
        'k' | 'K' => (&text[..text.len() - 1], 1024),
        'm' | 'M' => (&text[..text.len() - 1], 1024 * 1024),
        'g' | 'G' => (&text[..text.len() - 1], 1024 * 1024 * 1024),
        _ => (text, 1),
    };
    number.parse::<u64>().ok()?.checked_mul(factor)
}

fn size_text(bytes: u64) -> String {
    if bytes.is_multiple_of(1024 * 1024) {
        format!("{}MiB", bytes / (1024 * 1024))
    } else if bytes.is_multiple_of(1024) {
        format!("{}KiB", bytes / 1024)
    } else {
        format!("{bytes}B")
    }
}

/// The top level: `http`, process settings, `events`, `stream`, `mail`. A file without `http`
/// whose top level holds `server` or `upstream` blocks (a `conf.d` file) is read as the inside
/// of `http`.
pub(crate) fn top(run: &mut Run<'_>, tree: &[Directive]) {
    let has_http = tree.iter().any(|d| d.name == "http" && d.block.is_some());
    if !has_http
        && tree.iter().any(|d| {
            (d.name == "server" || d.name == "upstream" || d.name == "location")
                && d.block.is_some()
        })
    {
        http(run, tree, None);
        return;
    }
    for d in tree {
        match (d.name.as_str(), &d.block) {
            ("http", Some(block)) => {
                run.exact(
                    d,
                    "the `http` block: its settings are inherited by the servers below",
                );
                http(run, block, Some(d));
            }
            ("events", Some(block)) => {
                run.dropped(d, "connection processing settings have no equivalent");
                for inner in block {
                    run.dropped(inner, "connection processing settings have no equivalent");
                }
            }
            ("stream" | "mail", Some(block)) => {
                refuse(
                    run,
                    d,
                    &format!(
                        "the `{}` block (TCP/UDP or mail proxying) is not migrated in this version",
                        d.name
                    ),
                    if d.name == "stream" {
                        "write `tcp_routes`/`tcp_services` (or `udp_*`) by hand; `HostSNI` and `tls.passthrough` replace `ssl_preread`"
                    } else {
                        ""
                    },
                );
                refuse_all(
                    run,
                    block,
                    &format!("inside the `{}` block, which is not migrated", d.name),
                );
            }
            ("include", None) => include(run, d),
            (name, None) => top_directive(run, d, name),
            (_, Some(block)) => {
                run.dropped(d, format!("block `{}` has no equivalent", d.name));
                refuse_all(
                    run,
                    block,
                    &format!("inside `{}`, which is not migrated", d.name),
                );
            }
        }
    }
}

fn top_directive(run: &mut Run<'_>, d: &Directive, name: &str) {
    if name == "error_log" {
        run.approx(
            d,
            "ReverseDock writes its own log to standard error (`rdock run --log <level>`)",
        );
    } else if let Some((_, why)) = NO_EFFECT.iter().find(|(n, _)| *n == name) {
        run.exact(d, format!("{why}: no equivalent needed"));
    } else {
        run.dropped(d, format!("`{name}` is not a directive this tool knows"));
        run.code(d, "nginx.directive.unknown");
    }
}

fn include(run: &mut Run<'_>, d: &Directive) {
    let outcome = run
        .loaded
        .includes
        .get(&(d.file, d.line, d.column))
        .cloned();
    match outcome {
        Some(Ok(files)) => {
            let message = if files.is_empty() {
                "the mask matches no file".to_owned()
            } else {
                format!("read {}", files.join(", "))
            };
            run.exact(d, message);
            run.code(d, "nginx.include");
        }
        Some(Err(why)) => {
            if d.arg(0).ends_with("mime.types") {
                run.exact(
                    d,
                    "media types: ReverseDock's static files have their own table",
                );
                run.code(d, "nginx.include");
            } else {
                run.manual(d, format!("not read: {why}"), "pass `--include-outside` to read files outside the main file's directory, or migrate the file on its own");
                run.code(d, "nginx.include.manual");
            }
        }
        None => {
            run.manual(d, "not read", "");
            run.code(d, "nginx.include.manual");
        }
    }
}

/// Refuses a construct with its reason.
fn refuse(run: &mut Run<'_>, d: &Directive, why: &str, hint: &str) {
    run.manual(d, why, hint);
    run.code(d, "nginx.refused");
}

fn refuse_all(run: &mut Run<'_>, block: &[Directive], why: &str) {
    for d in block {
        refuse(run, d, why, "");
        if let Some(inner) = &d.block {
            refuse_all(run, inner, why);
        }
    }
}

/// An upstream block as a service template.
struct Upstream {
    service: Map<String, Value>,
}

/// What the `http` level (or a `conf.d` file's top level) holds.
fn http(run: &mut Run<'_>, block: &[Directive], _opener: Option<&Directive>) {
    let mut upstreams: BTreeMap<String, Upstream> = BTreeMap::new();
    let mut ws_vars: BTreeSet<String> = BTreeSet::new();
    let mut servers: Vec<&Directive> = Vec::new();
    for d in block {
        match (d.name.as_str(), &d.block) {
            ("upstream", Some(inner)) => {
                let name = d.arg(0).to_owned();
                let up = upstream(run, d, inner);
                upstreams.insert(name, up);
            }
            ("map", Some(inner)) => {
                if let Some(var) = websocket_map(d, inner) {
                    run.exact(d, format!("the WebSocket `map` idiom: `{var}` is the `Connection` header of an upgrade, which ReverseDock forwards by itself"));
                    for e in inner {
                        run.exact(e, "part of the WebSocket `map` idiom");
                    }
                    ws_vars.insert(var);
                } else {
                    refuse(
                        run,
                        d,
                        "`map` (variables computed from others) has no equivalent; directives that use its variable are reported where they are",
                        "write the cases as routes with matchers",
                    );
                    refuse_all(run, inner, "inside a `map`, which is not migrated");
                }
            }
            ("server", Some(_)) => servers.push(d),
            ("include", None) => include(run, d),
            _ => {}
        }
    }
    let level: Vec<&Directive> = block.iter().filter(|d| d.block.is_none()).collect();
    http_level(run, &level);
    // Hosts served over TLS anywhere (for the HTTP-to-HTTPS redirect idiom).
    let tls_hosts: BTreeSet<String> = servers
        .iter()
        .filter(|s| server_listens(s).iter().any(|l| l.ssl))
        .flat_map(|s| server_names(s))
        .filter(|n| !n.contains('*') && !n.starts_with('~') && !n.starts_with('.') && *n != "_")
        .collect();
    let ctx = Http {
        block,
        upstreams: &upstreams,
        ws_vars: &ws_vars,
        servers: &servers,
        tls_hosts: &tls_hosts,
    };
    for (index, s) in servers.iter().enumerate() {
        server(run, &ctx, s, index);
    }
    account_level(run, block);
}

/// Directives at the `http` level that are not inherited content settings.
fn http_level(run: &mut Run<'_>, level: &[&Directive]) {
    for d in level {
        let name = d.name.as_str();
        match name {
            "access_log" => {
                if d.arg(0) == "off" {
                    run.approx(
                        d,
                        "access logs are off unless `observability.access_log` turns them on",
                    );
                } else {
                    run.observability
                        .insert("access_log".to_owned(), json!({ "enabled": true }));
                    run.approx(d, "access logging is on: `observability.access_log.enabled: true` (with `--full`); the file and the format are ReverseDock's (JSON to standard output)");
                }
            }
            "log_format" => run.approx(
                d,
                "access log formats: ReverseDock writes JSON with fixed fields",
            ),
            "error_log" => run.approx(
                d,
                "ReverseDock writes its own log to standard error (`rdock run --log <level>`)",
            ),
            "set_real_ip_from" => {
                let list = run
                    .security
                    .entry("trusted_proxies".to_owned())
                    .or_insert_with(|| json!([]));
                if let Value::Array(a) = list {
                    a.push(json!(d.arg(0)));
                }
                run.approx(
                    d,
                    "→ `security.trusted_proxies` (with `--full`), which applies to every listener",
                );
            }
            "real_ip_header" => match d.arg(0).to_ascii_lowercase().as_str() {
                "x-forwarded-for" => run.exact(
                    d,
                    "`X-Forwarded-For` is ReverseDock's default client-IP header",
                ),
                "x-real-ip" => {
                    run.security
                        .insert("client_ip_header".to_owned(), json!("x_real_ip"));
                    run.approx(
                        d,
                        "→ `security.client_ip_header: x_real_ip` (with `--full`)",
                    );
                }
                "proxy_protocol" => run.exact(
                    d,
                    "the PROXY protocol's address is the client's when the listener reads it",
                ),
                other => run.manual(
                    d,
                    format!("client IP header `{other}` has no equivalent"),
                    "",
                ),
            },
            "real_ip_recursive" => run.approx(
                d,
                "ReverseDock walks `X-Forwarded-For` from the right past trusted proxies",
            ),
            "large_client_header_buffers" => {
                if let Some(bytes) = size(d.arg(1)) {
                    run.security
                        .insert("limits".to_owned(), json!({ "max_header_bytes": bytes }));
                    run.approx(d, format!("→ `security.limits.max_header_bytes: {bytes}` (with `--full`), one limit for the whole header"));
                } else {
                    run.manual(d, "not a size", "");
                }
            }
            "client_header_timeout"
            | "client_body_timeout"
            | "send_timeout"
            | "keepalive_timeout" => {
                run.approx(d, "client-side timeouts are per listener here (`listeners.<name>.timeouts`); written on the listeners with `--full`");
            }
            "merge_slashes" => {
                if d.arg(0) == "off" {
                    run.approx(d, "ReverseDock always matches on the normalised path (adjacent slashes merged)");
                } else {
                    run.exact(d, "adjacent slashes are merged for matching, as by default");
                }
            }
            // TLS settings are read per server; the rest are accounted after the servers.
            _ => {}
        }
    }
}

struct Http<'h, 't> {
    block: &'t [Directive],
    upstreams: &'h BTreeMap<String, Upstream>,
    ws_vars: &'h BTreeSet<String>,
    servers: &'h [&'t Directive],
    tls_hosts: &'h BTreeSet<String>,
}

/// `map $http_upgrade $connection_upgrade { default upgrade; '' close; }` (the WebSocket proxying
/// page, <https://nginx.org/en/docs/http/websocket.html>, read 2026-11-14), also with `''` mapped
/// to an empty value for kept-alive backends. Returns the variable.
fn websocket_map(d: &Directive, inner: &[Directive]) -> Option<String> {
    let args = d.values();
    let [source, var] = args.as_slice() else {
        return None;
    };
    if *source != "$http_upgrade" {
        return None;
    }
    let mut default = None;
    let mut empty = None;
    for e in inner {
        let key = e.name.as_str();
        let value = e.arg(0);
        if e.args.len() != 1 {
            return None;
        }
        match key {
            "default" => default = Some(value.to_ascii_lowercase()),
            "" => empty = Some(value.to_ascii_lowercase()),
            _ => return None,
        }
    }
    (default.as_deref() == Some("upgrade") && matches!(empty.as_deref(), Some("close" | "")))
        .then(|| (*var).to_owned())
}

/// One `listen`.
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)] // the flags of `listen`
struct Listen {
    address: Option<String>,
    port: u16,
    ssl: bool,
    default: bool,
    proxy_protocol: bool,
    http2: bool,
    quic: bool,
}

/// The `listen` directives of a server (`listen *:80 | *:8000` when there is none; this tool
/// assumes 80).
fn server_listens(s: &Directive) -> Vec<Listen> {
    let block = s.block.as_deref().unwrap_or_default();
    let listens: Vec<Listen> = block
        .iter()
        .filter(|d| d.name == "listen")
        .filter_map(parse_listen)
        .collect();
    if block.iter().any(|d| d.name == "listen") {
        listens
    } else {
        vec![Listen {
            address: Some(":80".to_owned()),
            port: 80,
            ssl: false,
            default: false,
            proxy_protocol: false,
            http2: false,
            quic: false,
        }]
    }
}

fn parse_listen(d: &Directive) -> Option<Listen> {
    let args = d.values();
    let first = *args.first()?;
    let (host, port) = if first.starts_with("unix:") {
        return Some(Listen {
            address: None,
            port: 0,
            ssl: false,
            default: false,
            proxy_protocol: false,
            http2: false,
            quic: false,
        });
    } else if let Ok(port) = first.parse::<u16>() {
        (String::new(), port)
    } else if let Some(rest) = first.strip_prefix('[') {
        let (h, p) = rest.split_once(']')?;
        let port = p.strip_prefix(':').map_or(Some(80), |p| p.parse().ok())?;
        (
            if h == "::" {
                String::new()
            } else {
                format!("[{h}]")
            },
            port,
        )
    } else if let Some((h, p)) = first.rsplit_once(':') {
        (
            if h == "*" || h == "0.0.0.0" {
                String::new()
            } else {
                h.to_owned()
            },
            p.parse().ok()?,
        )
    } else {
        (
            if first == "*" {
                String::new()
            } else {
                first.to_owned()
            },
            80,
        )
    };
    let flags: BTreeSet<&str> = args[1..].iter().copied().collect();
    let ssl = flags.contains("ssl") || flags.contains("quic");
    Some(Listen {
        address: Some(format!("{host}:{port}")),
        port,
        ssl,
        default: flags.contains("default_server") || flags.contains("default"),
        proxy_protocol: flags.contains("proxy_protocol"),
        http2: flags.contains("http2"),
        quic: flags.contains("quic"),
    })
}

fn server_names(s: &Directive) -> Vec<String> {
    s.block
        .as_deref()
        .unwrap_or_default()
        .iter()
        .filter(|d| d.name == "server_name")
        .flat_map(|d| d.values().into_iter().map(str::to_ascii_lowercase))
        .filter(|n| !n.is_empty())
        .collect()
}

/// A listener name: `web` (:80), `websecure` (:443 with TLS), else by protocol and address.
fn listener_name(l: &Listen) -> String {
    let address = l.address.clone().unwrap_or_default();
    match (l.port, l.ssl, address.starts_with(':')) {
        (80, false, true) => "web".to_owned(),
        (443, true, true) => "websecure".to_owned(),
        (port, ssl, true) => format!("{}-{port}", if ssl { "https" } else { "http" }),
        (_, ssl, false) => format!(
            "{}-{}",
            if ssl { "https" } else { "http" },
            output::slug(&address)
        ),
    }
}

/// A server name as a rule (nginx.org, "Server names": exact names; `*.example.org` matches
/// `www.example.org` and `www.sub.example.org`; `.example.org` is `example.org` and
/// `*.example.org`; `www.example.*`; `~` starts a regular expression;
/// <https://nginx.org/en/docs/http/server_names.html>, read 2026-11-14). `None` for regex names.
fn name_rule(name: &str) -> Option<String> {
    if name.starts_with('~') {
        return None;
    }
    if let Some(rest) = name.strip_prefix("*.") {
        return Some(format!("HostRegexp(`(?i)^.+\\.{}$`)", escape(rest)));
    }
    if let Some(rest) = name.strip_prefix('.') {
        return Some(format!(
            "Host(`{rest}`) || HostRegexp(`(?i)^.+\\.{}$`)",
            escape(rest)
        ));
    }
    if let Some(rest) = name.strip_suffix(".*") {
        return Some(format!("HostRegexp(`(?i)^{}\\..+$`)", escape(rest)));
    }
    if name.contains('`') || name.contains('*') {
        return None;
    }
    Some(format!("Host(`{name}`)"))
}

/// Whether the wildcard `pattern` (`*.a.com`, `.a.com`, `www.a.*`) matches the name `name`.
fn wildcard_matches(pattern: &str, name: &str) -> bool {
    if let Some(rest) = pattern.strip_prefix("*.") {
        return name.ends_with(&format!(".{rest}"));
    }
    if let Some(rest) = pattern.strip_prefix('.') {
        return name == rest || name.ends_with(&format!(".{rest}"));
    }
    if let Some(rest) = pattern.strip_suffix(".*") {
        return name.starts_with(&format!("{rest}."));
    }
    false
}

/// One route of a location.
#[derive(Debug, Clone, Default)]
struct RouteOut {
    label: Vec<String>,
    rule: String,
    priority: i64,
    middlewares: Vec<(String, Value)>,
    service: Option<(String, Value)>,
    max_body: Option<String>,
    timeouts: Map<String, Value>,
    blocked: Vec<String>,
}

#[allow(clippy::too_many_lines)] // one pass over a server
fn server(run: &mut Run<'_>, ctx: &Http<'_, '_>, s: &Directive, index: usize) {
    let block = s.block.as_deref().unwrap_or_default();
    run.exact(
        s,
        "a virtual server → routes for its names on its listeners",
    );
    let listens = server_listens(s);
    let names = server_names(s);
    // Listeners.
    let mut plain = Vec::new();
    let mut secure = Vec::new();
    for d in block.iter().filter(|d| d.name == "listen") {
        match parse_listen(d) {
            Some(l) if l.address.is_some() => {
                let name = listener_name(&l);
                let mut listener = json!({ "address": l.address });
                if l.ssl {
                    listener["tls"] = json!({});
                }
                let mut notes = vec![format!("→ listener `{name}`")];
                let mut approx = Vec::new();
                if l.proxy_protocol {
                    match run.security.get("trusted_proxies").cloned() {
                        Some(trusted) => {
                            listener["proxy_protocol"] = json!({ "trusted": trusted });
                            notes.push("PROXY protocol from the `set_real_ip_from` addresses".to_owned());
                        }
                        None => approx.push("`proxy_protocol` without `set_real_ip_from`: ReverseDock reads PROXY headers only from listed sources (`listeners.<name>.proxy_protocol.trusted`); not written".to_owned()),
                    }
                }
                if l.quic {
                    approx.push("QUIC (HTTP/3) is experimental here and not written (`listeners.<name>.http3`)".to_owned());
                }
                if l.http2 && !l.ssl {
                    approx.push(
                        "HTTP/2 without TLS (prior knowledge) is not offered on a plain listener"
                            .to_owned(),
                    );
                }
                let extra: Vec<&str> = d.values()[1..]
                    .iter()
                    .copied()
                    .filter(|f| {
                        ![
                            "ssl",
                            "http2",
                            "default_server",
                            "default",
                            "proxy_protocol",
                            "quic",
                        ]
                        .contains(f)
                    })
                    .collect();
                if !extra.is_empty() {
                    approx.push(format!(
                        "socket options {} are not carried over",
                        extra
                            .iter()
                            .map(|e| format!("`{e}`"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }
                run.listeners.entry(name.clone()).or_insert(listener);
                if l.ssl {
                    if !secure.contains(&name) {
                        secure.push(name);
                    }
                } else if !plain.contains(&name) {
                    plain.push(name);
                }
                if approx.is_empty() {
                    run.exact(d, notes.join("; "));
                } else {
                    run.approx(d, format!("{}; {}", notes.join("; "), approx.join("; ")));
                }
            }
            _ => run.manual(
                d,
                "a Unix socket or an address this tool cannot read: write the listener by hand",
                "",
            ),
        }
    }
    if !block.iter().any(|d| d.name == "listen") {
        run.listeners
            .entry("web".to_owned())
            .or_insert_with(|| json!({ "address": ":80" }));
        plain.push("web".to_owned());
    }
    if !secure.is_empty() {
        run.listeners
            .entry("web".to_owned())
            .or_insert_with(|| json!({ "address": ":80" }));
    }
    // Host condition, with the default server's catch-all.
    let mut host_parts = Vec::new();
    let mut blocked_server: Vec<String> = Vec::new();
    for d in block.iter().filter(|d| d.name == "server_name") {
        let mut regex = Vec::new();
        for name in d.values() {
            let lower = name.to_ascii_lowercase();
            if lower.is_empty() || lower == "_" {
                continue;
            }
            if let Some(rule) = name_rule(&lower) {
                host_parts.push(rule);
            } else {
                // Written as `HostRegexp` when the engine reads it; the routes stay disabled.
                let re = lower.trim_start_matches('~');
                if regex::Regex::new(re).is_ok() && !re.contains('`') {
                    host_parts.push(format!("HostRegexp(`(?i){re}`)"));
                }
                regex.push(lower);
            }
        }
        if regex.is_empty() {
            run.exact(
                d,
                "→ the routes' host matchers (exact names; wildcards of any depth as `HostRegexp`)",
            );
        } else {
            run.manual(d, format!("regular-expression names {} are not migrated (their captures may be used elsewhere)", regex.join(", ")), "write the names as `Host` or `HostRegexp` matchers");
            blocked_server.push("a regular-expression server name was not migrated".to_owned());
        }
    }
    // Other servers sharing a listener.
    let my_listeners: BTreeSet<String> = listens
        .iter()
        .filter(|l| l.address.is_some())
        .map(listener_name)
        .collect();
    let mut others: Vec<String> = Vec::new();
    let mut is_default = listens.iter().any(|l| l.default);
    for (j, other) in ctx.servers.iter().enumerate() {
        if j == index {
            continue;
        }
        let theirs: BTreeSet<String> = server_listens(other)
            .iter()
            .filter(|l| l.address.is_some())
            .map(listener_name)
            .collect();
        if theirs.is_disjoint(&my_listeners) {
            continue;
        }
        others.extend(
            server_names(other)
                .into_iter()
                .filter(|n| !n.is_empty() && n != "_"),
        );
        // The first server for a listener is its default unless another says `default_server`.
        if j < index
            && !server_listens(other).iter().any(|l| l.default)
            && !listens.iter().any(|l| l.default)
        {
            is_default = false;
        }
    }
    if !listens.iter().any(|l| l.default) {
        let earlier = ctx.servers[..index].iter().any(|o| {
            let theirs: BTreeSet<String> = server_listens(o)
                .iter()
                .filter(|l| l.address.is_some())
                .map(listener_name)
                .collect();
            !theirs.is_disjoint(&my_listeners)
        });
        let explicit_elsewhere = ctx.servers.iter().enumerate().any(|(j, o)| {
            j != index
                && server_listens(o).iter().any(|l| {
                    l.default && l.address.is_some() && my_listeners.contains(&listener_name(l))
                })
        });
        is_default = !earlier && !explicit_elsewhere;
    }
    // Names of more specific servers that this server's wildcards would also match.
    let mut exclude = Vec::new();
    let my_names: Vec<String> = names.iter().filter(|n| *n != "_").cloned().collect();
    for name in &my_names {
        if name.starts_with("*.") || name.starts_with('.') || name.ends_with(".*") {
            for other in &others {
                if !other.contains('*')
                    && !other.starts_with('.')
                    && !other.starts_with('~')
                    && wildcard_matches(name, other)
                {
                    exclude.push(format!("Host(`{other}`)"));
                }
            }
        }
    }
    let mut host_rule = match host_parts.len() {
        0 => String::new(),
        1 => host_parts[0].clone(),
        _ => format!("({})", host_parts.join(" || ")),
    };
    if host_parts.len() == 1 && host_rule.contains(" || ") {
        host_rule = format!("({host_rule})");
    }
    if !exclude.is_empty() && !host_rule.is_empty() {
        host_rule = format!("{host_rule} && !({})", exclude.join(" || "));
    }
    if is_default && host_rule.is_empty() {
        // A catch-all server (`server_name _;` or none): every host the other servers do not name.
        let other_rules: Vec<String> = others.iter().filter_map(|o| name_rule(o)).collect();
        if !other_rules.is_empty() {
            host_rule = format!("!({})", other_rules.join(" || "));
        }
    } else if is_default {
        // NGINX also answers unknown hosts with its default server; the routes keep the names.
        run.defaults_changed.insert("nginx.default.unmatched_host", "requests for hosts no `server_name` lists go to the default server of their listener in NGINX; the migrated routes keep the default server's names, so ReverseDock answers such requests with 404 (add a catch-all route if they mattered)".to_owned());
    } else if host_rule.is_empty() {
        // Not the default server and no name: no request reaches it.
        run.approx(s, "the server has no name and is not the default server of its listeners: no request reaches it, and no route is written");
        account_unreached(run, block);
        account_level(run, block);
        return;
    }
    let srv = Server {
        http: ctx,
        block,
        host_rule,
        label: my_names
            .first()
            .map_or_else(|| "default".to_owned(), |n| n.replace('*', "wildcard")),
        plain,
        secure,
        blocked: blocked_server,
    };
    server_tls(run, &srv);
    server_directives(run, &srv);
    let mut routes = Vec::new();
    // The server's rewrite-phase directives: `return`, `rewrite … redirect|permanent`, `if`, `set`.
    let mut server_return = false;
    let rewrite_dirs: Vec<&Directive> = block
        .iter()
        .filter(|d| ["rewrite", "return", "if", "set", "break"].contains(&d.name.as_str()))
        .collect();
    for (k, d) in rewrite_dirs.iter().enumerate() {
        if server_return {
            run.exact(d, "never reached: the server's `return` answers first");
            continue;
        }
        match d.name.as_str() {
            "return" => {
                server_return = true;
                if let Some(redirect) = https_redirect_idiom(&srv, d, &names)
                    && redirect
                {
                    run.approx(d, "the classic HTTP-to-HTTPS redirect: ReverseDock redirects these hosts by default (`defaults.redirect_http_to_https`); it answers 308 instead of 301 for methods other than GET, so they keep their method and body");
                    run.code(d, "nginx.server.https_redirect");
                    // The server's locations and other content are never reached.
                    mark_unreached(run, block, d);
                    account_level(run, block);
                    return;
                }
                let mut route = RouteOut {
                    label: vec![srv.label.clone(), "return".to_owned()],
                    rule: join_rule(&srv.host_rule, ""),
                    priority: TIER_SERVER_RETURN * SUB,
                    ..RouteOut::default()
                };
                return_route(run, d, &mut route);
                routes.push(route);
            }
            "rewrite" => {
                if let Some(route) = rewrite_redirect(
                    run,
                    d,
                    &srv.host_rule,
                    TIER_SERVER_REWRITE * SUB + i64::try_from(rewrite_dirs.len() - k).unwrap_or(0),
                    &srv.label,
                ) {
                    routes.push(route);
                } else {
                    srv_block(run, &srv, d);
                }
            }
            "if" => {
                refuse(
                    run,
                    d,
                    "`if` has no faithful translation (\"the request is assigned the configuration inside the if\")",
                    "write each case as a route with matchers (`Host`, `Method`, `Header`, `Query`)",
                );
                if let Some(inner) = &d.block {
                    refuse_all(run, inner, "inside an `if`, which is not migrated");
                }
            }
            "set" => refuse(run, d, "`set` (variables) has no equivalent", ""),
            _ => run.exact(d, "stops the rewrite directives"),
        }
    }
    let server_refused = rewrite_dirs.iter().any(|d| {
        d.name == "if" || d.name == "set" || (d.name == "rewrite" && !is_redirect_rewrite(d))
    });
    let mut srv = srv;
    if server_refused {
        srv.blocked
            .push("the server has `if`, `set` or a `rewrite` that is not migrated".to_owned());
    }
    if server_return {
        mark_unreached(
            run,
            block,
            rewrite_dirs
                .iter()
                .copied()
                .find(|d| d.name == "return")
                .unwrap_or(s),
        );
    } else {
        routes.extend(locations(run, &srv));
    }
    write_routes(run, &srv, routes);
    account_level(run, block);
}

fn srv_block(run: &mut Run<'_>, _srv: &Server<'_, '_, '_>, d: &Directive) {
    refuse(
        run,
        d,
        "a `rewrite` that re-runs location matching (`last`, or no flag) or uses variables has no faithful translation: ReverseDock picks a route once",
        "write the target as its own route, or a `redirect`",
    );
}

fn is_redirect_rewrite(d: &Directive) -> bool {
    matches!(d.arg(2), "permanent" | "redirect")
        || d.arg(1).starts_with("http://")
        || d.arg(1).starts_with("https://")
}

/// Accounts for everything in a server no request reaches.
fn account_unreached(run: &mut Run<'_>, block: &[Directive]) {
    for d in block {
        if !run.noted(d) {
            run.exact(d, "never used: no request reaches its server");
        }
        if let Some(inner) = &d.block {
            account_unreached(run, inner);
        }
    }
}

/// Everything in a server after its answering `return`.
fn mark_unreached(run: &mut Run<'_>, block: &[Directive], by: &Directive) {
    for d in block {
        if std::ptr::eq(d, by) || run.noted(d) {
            continue;
        }
        if d.name == "location" {
            run.exact(
                d,
                "never reached: the server's `return` answers every request first",
            );
            if let Some(inner) = &d.block {
                account_unreached(run, inner);
            }
        } else if d.block.is_none()
            && !["listen", "server_name", "include"].contains(&d.name.as_str())
            && !d.name.starts_with("ssl_")
        {
            run.exact(
                d,
                "never used: the server's `return` answers every request first",
            );
        }
    }
}

struct Server<'a, 'h, 't> {
    http: &'a Http<'h, 't>,
    block: &'t [Directive],
    host_rule: String,
    label: String,
    plain: Vec<String>,
    secure: Vec<String>,
    blocked: Vec<String>,
}

/// `return 301 https://$host$request_uri;` (or `$server_name` with one name, or a fixed host)
/// in a server that only listens without TLS: covered by ReverseDock's built-in redirect when
/// every name has a TLS route. `Some(true)` when recognised.
fn https_redirect_idiom(srv: &Server<'_, '_, '_>, d: &Directive, names: &[String]) -> Option<bool> {
    if !srv.secure.is_empty() || !matches!(d.arg(0), "301" | "308") {
        return None;
    }
    let url = d.arg(1);
    let ok = url == "https://$host$request_uri"
        || (url == "https://$server_name$request_uri" && names.len() == 1);
    let listed: Vec<&String> = names
        .iter()
        .filter(|n| *n != "_" && !n.is_empty())
        .collect();
    let covered = !listed.is_empty() && listed.iter().all(|n| srv.http.tls_hosts.contains(*n));
    Some(ok && covered && srv.block.iter().filter(|x| x.name == "location").count() == 0)
}

/// TLS settings of a server: certificates and the listener policy.
#[allow(clippy::too_many_lines)] // one pass, in reading order
fn server_tls(run: &mut Run<'_>, srv: &Server<'_, '_, '_>) {
    let levels: [&[Directive]; 2] = [srv.http.block, srv.block];
    let certs: Vec<&Directive> = list(&levels, &["ssl_certificate"]);
    let keys: Vec<&Directive> = list(&levels, &["ssl_certificate_key"]);
    for (i, cert) in certs.iter().enumerate() {
        let key = keys.get(i);
        let path = cert.arg(0);
        if path.contains('$')
            || key.is_none_or(|k| k.arg(0).contains('$'))
            || path.starts_with("data:")
        {
            run.manual(
                cert,
                "a certificate named with variables or written inline is not migrated",
                "list the files under `certificates`",
            );
            continue;
        }
        let name = output::slug(
            path.rsplit('/')
                .nth(usize::from(
                    path.ends_with("fullchain.pem") || path.ends_with("cert.pem"),
                ))
                .unwrap_or("certificate"),
        );
        let name = if name.is_empty() {
            "certificate".to_owned()
        } else {
            name
        };
        run.certificates.entry(name.clone()).or_insert_with(
            || json!({ "cert_file": path, "key_file": key.map(|k| k.arg(0)).unwrap_or_default() }),
        );
        run.exact(
            cert,
            format!("→ `certificates.{name}` (the files are named, never read)"),
        );
        if let Some(k) = key {
            run.exact(k, format!("→ `certificates.{name}.key_file` (never read)"));
        }
        if i > 0 {
            run.approx(cert, "a second certificate (another key type) for the same names: ReverseDock serves one per route");
        }
    }
    if let Some(protocols) = last(&levels, "ssl_protocols") {
        let values: BTreeSet<&str> = protocols.values().into_iter().collect();
        let weak: Vec<&&str> = values
            .iter()
            .filter(|v| matches!(**v, "SSLv2" | "SSLv3" | "TLSv1" | "TLSv1.1"))
            .collect();
        if !weak.is_empty() {
            run.manual(protocols, format!("{} {} weaker than ReverseDock's floor (TLS 1.2) and not written; the listeners keep `intermediate`", weak.iter().map(|w| format!("`{w}`")).collect::<Vec<_>>().join(", "), if weak.len() == 1 { "is" } else { "are" }), "keep TLS 1.2 and later; clients that need older versions cannot connect");
            run.code(protocols, "nginx.tls.weak");
            run.note(protocols, crate::output::Notes::security);
        } else if values.len() == 1 && values.contains("TLSv1.3") {
            for l in &srv.secure {
                if let Some(listener) = run.listeners.get_mut(l) {
                    listener["tls"]["policy"] = json!("modern");
                }
            }
            run.exact(
                protocols,
                "TLS 1.3 only → `tls.policy: modern` on the listeners",
            );
        } else {
            run.exact(
                protocols,
                "TLS 1.2 and 1.3: ReverseDock's default policy (`intermediate`)",
            );
        }
    }
    if let Some(ciphers) = last(&levels, "ssl_ciphers") {
        run.approx(ciphers, "cipher lists: TLS settings are two presets here (`intermediate`, `modern`, Mozilla's lists); the listeners keep `intermediate`");
    }
    let verify = last(&levels, "ssl_verify_client");
    let ca = last(&levels, "ssl_client_certificate");
    if let Some(v) = verify {
        let mode = match v.arg(0) {
            "on" => Some("required"),
            "optional" => Some("optional"),
            _ => None,
        };
        match (mode, ca) {
            (Some(mode), Some(ca)) => {
                for l in &srv.secure {
                    if let Some(listener) = run.listeners.get_mut(l) {
                        listener["tls"]["client_auth"] = json!({ "mode": mode, "ca_files": [ca.arg(0)] });
                    }
                }
                run.approx(v, format!("client certificates `{mode}` → `tls.client_auth` on the listener (per listener here, per server in NGINX)"));
                run.exact(ca, "→ `tls.client_auth.ca_files`");
            }
            (None, _) if v.arg(0) == "off" => run.exact(v, "no client certificates, as by default"),
            _ => run.manual(v, "client certificate verification `optional_no_ca`, or without `ssl_client_certificate`, has no equivalent", ""),
        }
    } else if let Some(ca) = ca {
        run.dropped(ca, "a client CA without `ssl_verify_client` has no effect");
    }
    for name in [
        "ssl_verify_depth",
        "ssl_password_file",
        "ssl_reject_handshake",
        "ssl_early_data",
        "ssl_conf_command",
        "ssl_crl",
        "ssl_ocsp",
        "ssl_ocsp_responder",
    ] {
        for d in levels
            .iter()
            .flat_map(|l| l.iter())
            .filter(|d| d.name == name)
        {
            if !run.noted(d) {
                run.manual(d, format!("`{name}` has no equivalent"), "");
            }
        }
    }
}

/// Server-level directives that are not content settings.
fn server_directives(run: &mut Run<'_>, srv: &Server<'_, '_, '_>) {
    for d in srv.block.iter().filter(|d| d.block.is_none()) {
        match d.name.as_str() {
            "http2" => run.exact(d, "HTTP/2 is on for TLS listeners by default"),
            "http3" | "quic_retry" | "quic_gso" => run.approx(
                d,
                "HTTP/3 is experimental here and not written (`listeners.<name>.http3`)",
            ),
            "access_log" => {
                if d.arg(0) == "off" {
                    run.approx(
                        d,
                        "access logs are global here (`observability.access_log`)",
                    );
                } else {
                    run.observability
                        .insert("access_log".to_owned(), json!({ "enabled": true }));
                    run.approx(d, "access logging is on: `observability.access_log.enabled: true` (with `--full`), global rather than per server");
                }
            }
            "error_log" => run.approx(d, "ReverseDock writes its own log to standard error"),
            "client_header_timeout"
            | "client_body_timeout"
            | "send_timeout"
            | "keepalive_timeout" => {
                run.approx(
                    d,
                    "client-side timeouts are per listener here (`listeners.<name>.timeouts`)",
                );
            }
            _ => {}
        }
    }
}

/// The locations of a server, with their routes.
#[allow(clippy::too_many_lines)] // the precedence rules in one place
fn locations(run: &mut Run<'_>, srv: &Server<'_, '_, '_>) -> Vec<RouteOut> {
    let mut locs: Vec<Loc<'_>> = Vec::new();
    for d in srv
        .block
        .iter()
        .filter(|d| d.name == "location" && d.block.is_some())
    {
        match parse_location(d) {
            Some((modifier, uri)) => locs.push(Loc { d, modifier, uri }),
            None => refuse(run, d, "a location this tool cannot read", ""),
        }
    }
    let named: BTreeMap<String, &Loc<'_>> = locs
        .iter()
        .filter(|l| l.modifier == Modifier::Named)
        .map(|l| (l.uri.clone(), l))
        .collect();
    let mut used_named: BTreeSet<String> = BTreeSet::new();
    let regexes: Vec<&Loc<'_>> = locs
        .iter()
        .filter(|l| matches!(l.modifier, Modifier::Regex { .. }))
        .collect();
    let plain_prefixes: Vec<&str> = locs
        .iter()
        .filter(|l| l.modifier == Modifier::Prefix)
        .map(|l| l.uri.as_str())
        .collect();
    let static_names: BTreeSet<&str> = locs
        .iter()
        .filter(|l| {
            matches!(
                l.modifier,
                Modifier::Prefix | Modifier::Preferential | Modifier::Exact
            )
        })
        .map(|l| l.uri.as_str())
        .collect();
    let mut out = Vec::new();
    for loc in &locs {
        let inner = loc.d.block.as_deref().unwrap_or_default();
        let (base, cond) = match loc.modifier {
            Modifier::Exact => (TIER_EXACT, format!("Path(`{}`)", loc.uri)),
            Modifier::Preferential => {
                let longer: Vec<String> = plain_prefixes
                    .iter()
                    .filter(|p| p.len() > loc.uri.len() && p.starts_with(loc.uri.as_str()))
                    .map(|p| format!("PathPrefix(`{p}`)"))
                    .collect();
                let rule = if longer.is_empty() {
                    format!("PathPrefix(`{}`)", loc.uri)
                } else {
                    format!("PathPrefix(`{}`) && !({})", loc.uri, longer.join(" || "))
                };
                (
                    TIER_PREFERENTIAL + i64::try_from(loc.uri.len()).unwrap_or(0),
                    rule,
                )
            }
            Modifier::Regex { case_insensitive } => {
                let position = regexes
                    .iter()
                    .position(|r| std::ptr::eq(r.d, loc.d))
                    .unwrap_or(0);
                let flag = if case_insensitive { "(?i)" } else { "" };
                let pattern = format!("{flag}{}", loc.uri);
                if regex::Regex::new(&pattern).is_err() || pattern.contains('`') {
                    refuse(run, loc.d, format!("the regular expression `{}` uses features ReverseDock's engine does not have (look-around, backreferences) or is invalid", loc.uri).as_str(), "rewrite it without look-around and backreferences");
                    account_unreached(run, inner);
                    continue;
                }
                (
                    TIER_REGEX + i64::try_from(regexes.len() - position).unwrap_or(0),
                    format!("PathRegexp(`{pattern}`)"),
                )
            }
            Modifier::Prefix => (
                TIER_PREFIX + i64::try_from(loc.uri.len()).unwrap_or(0),
                format!("PathPrefix(`{}`)", loc.uri),
            ),
            Modifier::Named => continue,
            Modifier::Predicate => {
                refuse(
                    run,
                    loc.d,
                    "predicate locations (`location $variable`, 1.31.5) have no equivalent",
                    "",
                );
                refuse_all(
                    run,
                    inner,
                    "inside a predicate location, which is not migrated",
                );
                continue;
            }
        };
        if loc.uri.contains('`') {
            refuse(run, loc.d, "a location with a backtick in its path", "");
            continue;
        }
        let mut cond = cond;
        // Nested locations are not migrated; the outer route leaves their requests out.
        let mut nested_excluded = Vec::new();
        for n in inner
            .iter()
            .filter(|d| d.name == "location" && d.block.is_some())
        {
            let rule = match parse_location(n) {
                Some((Modifier::Exact, u)) => Some(format!("Path(`{u}`)")),
                Some((Modifier::Prefix | Modifier::Preferential, u)) => {
                    Some(format!("PathPrefix(`{u}`)"))
                }
                Some((Modifier::Regex { case_insensitive }, u)) => Some(format!(
                    "PathRegexp(`{}{u}`)",
                    if case_insensitive { "(?i)" } else { "" }
                )),
                _ => None,
            };
            refuse(
                run,
                n,
                "nested locations are not migrated: requests for it are left out of the outer location's route (they get 404)",
                "write it as its own location",
            );
            if let Some(inner) = &n.block {
                refuse_all(
                    run,
                    inner,
                    "inside a nested location, which is not migrated",
                );
            }
            if let Some(rule) = rule.filter(|r| !r.contains('`') || r.matches('`').count() == 2) {
                nested_excluded.push(rule);
            }
        }
        if !nested_excluded.is_empty() {
            cond = format!("{cond} && !({})", nested_excluded.join(" || "));
        }
        let rule = join_rule(&srv.host_rule, &cond);
        run.exact(loc.d, match loc.modifier {
            Modifier::Exact => "exact match → `Path` at the highest location priority",
            Modifier::Preferential => "`^~` prefix → `PathPrefix` above every regular-expression location, unless a longer plain prefix matches",
            Modifier::Regex { .. } => "regular expression → `PathRegexp`, checked in file order below `=` and `^~`",
            _ => "prefix → `PathPrefix`, the longest first, below the regular expressions",
        });
        let levels: [&[Directive]; 3] = [srv.http.block, srv.block, inner];
        let mut routes = location_routes(
            run,
            srv,
            loc,
            &levels,
            &rule,
            base * SUB,
            &named,
            &mut used_named,
        );
        // The trailing-slash redirect: "If a location is defined by a prefix string that ends
        // with the slash character, and requests are processed by one of proxy_pass … then …
        // a permanent redirect with the code 301 will be returned to the requested URI with the
        // slash appended" (ngx_http_core_module, `location`).
        if matches!(loc.modifier, Modifier::Prefix | Modifier::Preferential)
            && loc.uri.ends_with('/')
            && loc.uri.len() > 1
            && inner
                .iter()
                .any(|d| d.name == "proxy_pass" || d.name == "grpc_pass")
            && !static_names.contains(loc.uri.trim_end_matches('/'))
        {
            let without = loc.uri.trim_end_matches('/').to_owned();
            let mut redirect = RouteOut {
                label: vec![srv.label.clone(), without.clone(), "slash".to_owned()],
                rule: join_rule(&srv.host_rule, &format!("Path(`{without}`)")),
                priority: TIER_EXACT * SUB,
                ..RouteOut::default()
            };
            redirect.middlewares.push((
                "slash".to_owned(),
                json!({ "type": "redirect", "path": loc.uri, "status": 301 }),
            ));
            redirect.service = Some((
                "not-found".to_owned(),
                json!({ "respond": { "status": 404 } }),
            ));
            routes.push(redirect);
        }
        out.extend(routes);
    }
    for (name, loc) in &named {
        if !used_named.contains(name) {
            refuse(
                run,
                loc.d,
                "a named location reached other than as a `try_files` fallback (`error_page`, `rewrite`, `X-Accel-Redirect`) has no equivalent",
                "",
            );
            if let Some(inner) = &loc.d.block {
                refuse_all(run, inner, "inside a named location, which is not migrated");
            }
        }
    }
    // The server's own content (requests no location matches): a static root, when set.
    let levels: [&[Directive]; 2] = [srv.http.block, srv.block];
    let has_root_location = locs
        .iter()
        .any(|l| matches!(l.modifier, Modifier::Prefix | Modifier::Preferential) && l.uri == "/");
    if !has_root_location
        && srv
            .block
            .iter()
            .any(|d| d.name == "root" || d.name == "try_files")
    {
        let pseudo = RouteOut {
            label: vec![srv.label.clone(), "files".to_owned()],
            rule: join_rule(&srv.host_rule, ""),
            priority: TIER_SERVER * SUB,
            ..RouteOut::default()
        };
        let mut route = pseudo;
        let try_files = srv.block.iter().find(|d| d.name == "try_files");
        static_content(
            run,
            &levels,
            None,
            try_files,
            &mut route,
            &named,
            &mut used_named,
            srv,
        );
        common(run, &levels, &mut route, false, srv);
        out.push(route);
    }
    out
}

fn join_rule(host: &str, cond: &str) -> String {
    match (host.is_empty(), cond.is_empty()) {
        (true, true) => "PathPrefix(`/`)".to_owned(),
        (true, false) => cond.to_owned(),
        (false, true) => host.to_owned(),
        (false, false) => format!("{host} && {cond}"),
    }
}

/// The routes of one location: its content (proxy, return, static files), the inherited
/// settings, and a route per redirecting `rewrite`.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn location_routes(
    run: &mut Run<'_>,
    srv: &Server<'_, '_, '_>,
    loc: &Loc<'_>,
    levels: &[&[Directive]; 3],
    rule: &str,
    priority: i64,
    named: &BTreeMap<String, &Loc<'_>>,
    used_named: &mut BTreeSet<String>,
) -> Vec<RouteOut> {
    let inner = levels[2];
    let label_path = loc
        .uri
        .trim_matches(|c: char| !c.is_ascii_alphanumeric())
        .to_owned();
    let mut route = RouteOut {
        label: vec![
            srv.label.clone(),
            if label_path.is_empty() {
                "root".to_owned()
            } else {
                label_path
            },
        ],
        rule: rule.to_owned(),
        priority,
        ..RouteOut::default()
    };
    let mut extra = Vec::new();
    // Refused constructs and the rewrite phase, in order.
    let mut answered_by_return = false;
    let mut content_refused = false;
    let mut rewrite_break = false;
    let mut redirects = 0i64;
    for d in inner {
        let name = d.name.as_str();
        if let Some((_, why, hint, blocks)) =
            REFUSED_PREFIX.iter().find(|(p, ..)| name.starts_with(p))
        {
            refuse(run, d, why, hint);
            if *blocks {
                route.blocked.push(format!("`{name}` was not migrated"));
            }
            if [
                "fastcgi_pass",
                "uwsgi_pass",
                "scgi_pass",
                "memcached_pass",
                "js_content",
                "perl",
            ]
            .contains(&name)
            {
                content_refused = true;
            }
            continue;
        }
        if name.ends_with("_by_lua_block")
            || name.ends_with("_by_lua")
            || name.ends_with("_by_lua_file")
        {
            refuse(
                run,
                d,
                "Lua scripting has no equivalent",
                "a native plugin (`type: plugin`) or a backend",
            );
            route
                .blocked
                .push("Lua scripting was not migrated".to_owned());
            if name.starts_with("content_by_lua") {
                content_refused = true;
            }
            continue;
        }
        match name {
            "if" => {
                refuse(run, d, "`if` has no faithful translation (inside a location it acts as a nested location)", "write each case as a route with matchers (`Method`, `Header`, `Query`)");
                if let Some(b) = &d.block {
                    refuse_all(run, b, "inside an `if`, which is not migrated");
                }
                route.blocked.push("an `if` was not migrated".to_owned());
            }
            "set" => {
                refuse(run, d, "`set` (variables) has no equivalent", "");
                route.blocked.push("a `set` was not migrated".to_owned());
            }
            "auth_request" | "auth_request_set" => {
                run.manual(d, "`auth_request` (a subrequest to an internal location) is not migrated", "use the `forward_auth` middleware with the internal location's backend as `address`");
                route.blocked.push("its `auth_request` was not migrated".to_owned());
            }
            "error_page" => run.manual(d, "`error_page` (an internal redirect) is not migrated", "for custom error pages, use the `errors` middleware (`status`, `file` or `service` and `path`)"),
            "return" if !answered_by_return => {
                if rewrite_break {
                    run.manual(d, "a `return` after a `rewrite … break` runs only when the rewrite did not match: not migrated", "");
                    route.blocked.push("a `return` after `rewrite … break`".to_owned());
                } else {
                    answered_by_return = true;
                    return_route(run, d, &mut route);
                }
            }
            "return" => run.exact(d, "never reached: an earlier `return` answers first"),
            "rewrite" if answered_by_return => run.exact(d, "never reached: an earlier `return` answers first"),
            "rewrite" => match d.arg(2) {
                "permanent" | "redirect" => {
                    redirects += 1;
                    if let Some(r) = rewrite_redirect(run, d, rule, priority + SUB - 1 - redirects.min(SUB - 2), &srv.label) {
                        extra.push(r);
                    } else {
                        route.blocked.push("a redirecting `rewrite` was not migrated".to_owned());
                    }
                }
                "break" if !rewrite_break => {
                    rewrite_break = true;
                    match rewrite_break_middleware(d) {
                        Ok(value) => {
                            run.exact(d, "`rewrite … break` → a `rewrite` middleware (the whole path is replaced, the query kept, as NGINX does)");
                            route.middlewares.push(("rewrite".to_owned(), value));
                        }
                        Err(why) => {
                            run.manual(d, why, "");
                            route.blocked.push("a `rewrite … break` was not migrated".to_owned());
                        }
                    }
                }
                _ if is_redirect_rewrite(d) => {
                    redirects += 1;
                    if let Some(r) = rewrite_redirect(run, d, rule, priority + SUB - 1 - redirects.min(SUB - 2), &srv.label) {
                        extra.push(r);
                    } else {
                        route.blocked.push("a redirecting `rewrite` was not migrated".to_owned());
                    }
                }
                _ => {
                    refuse(run, d, "a `rewrite` that re-runs location matching (`last`, no flag) or a second `rewrite … break` has no faithful translation: ReverseDock picks a route once", "write the target as its own route");
                    route.blocked.push("a `rewrite` was not migrated".to_owned());
                }
            },
            _ => {}
        }
    }
    let content = inner
        .iter()
        .find(|d| d.name == "proxy_pass" || d.name == "grpc_pass");
    if answered_by_return {
        if let Some(c) = content {
            run.exact(c, "never reached: `return` answers first");
        }
        for d in inner
            .iter()
            .filter(|d| d.name == "try_files" || d.name == "alias")
        {
            run.exact(d, "never reached: `return` answers first");
        }
    } else if content_refused && content.is_none() {
        // The content handler was refused: a placeholder keeps the disabled route valid.
        route.service = Some((
            "unmigrated".to_owned(),
            json!({ "respond": { "status": 502 } }),
        ));
        for d in inner.iter().filter(|d| {
            d.name == "try_files" || d.name == "alias" || d.name == "root" || d.name == "index"
        }) {
            if !run.noted(d) {
                run.exact(
                    d,
                    "not used: the location's content handler was not migrated",
                );
            }
        }
    } else if let Some(pass) = content {
        proxy(run, srv, loc, levels, pass, &mut route, rewrite_break);
        for d in inner
            .iter()
            .filter(|d| d.name == "try_files" || d.name == "alias" || d.name == "root")
        {
            if !run.noted(d) {
                run.exact(d, "not used: the location proxies");
            }
        }
    } else {
        let try_files = inner.iter().find(|d| d.name == "try_files");
        static_content(
            run,
            levels,
            Some(loc),
            try_files,
            &mut route,
            named,
            used_named,
            srv,
        );
    }
    common(
        run,
        levels,
        &mut route,
        content.is_some() && !answered_by_return,
        srv,
    );
    let mut out = vec![route];
    out.extend(extra);
    out
}

/// `return code [text]`, `return code URL`, `return URL` (`ngx_http_rewrite_module`, read
/// 2026-11-14).
fn return_route(run: &mut Run<'_>, d: &Directive, route: &mut RouteOut) {
    let args = d.values();
    let (code, target) = match args.as_slice() {
        [url]
            if url.starts_with("http://")
                || url.starts_with("https://")
                || url.starts_with("$scheme") =>
        {
            (302u16, Some(*url))
        }
        [code] => (code.parse().unwrap_or(0), None),
        [code, rest] => (code.parse().unwrap_or(0), Some(*rest)),
        _ => (0, None),
    };
    let fixed = |route: &mut RouteOut, status: u16| {
        route.service = Some((
            format!("respond-{status}"),
            json!({ "respond": { "status": status } }),
        ));
    };
    match (code, target) {
        (0, _) => {
            run.manual(d, "a `return` this tool cannot read", "");
            route.blocked.push("its `return` was not read".to_owned());
            fixed(route, 404);
        }
        (444, _) => {
            run.manual(
                d,
                "`return 444` (close the connection without an answer) has no equivalent",
                "answer with a status (`respond`) instead",
            );
            route
                .blocked
                .push("`return 444` has no equivalent".to_owned());
            fixed(route, 400);
        }
        (301 | 302 | 303 | 307 | 308, Some(url)) => match return_redirect(url, code) {
            Ok((value, note)) => {
                run.exact(d, note);
                route.middlewares.push(("redirect".to_owned(), value));
                route.service = Some((
                    "not-found".to_owned(),
                    json!({ "respond": { "status": 404 } }),
                ));
            }
            Err(why) => {
                run.manual(d, why, "");
                route
                    .blocked
                    .push("its redirect was not migrated".to_owned());
                fixed(route, code);
            }
        },
        (status, None) => {
            run.exact(
                d,
                format!("a fixed answer with status {status} (`respond`)"),
            );
            fixed(route, status);
        }
        (status, Some(text)) => {
            run.manual(d, format!("`return {status}` with a body (`{text}`) has no equivalent (a fixed-status service answers without a body)"), "serve the text from a backend or a static file");
            route
                .blocked
                .push("a `return` with a body has no equivalent".to_owned());
            fixed(route, status);
        }
    }
}

/// A `return` redirect target. Variables with an equivalent: `$host`, `$request_uri`,
/// `$scheme`, `$uri` at the end (with `$is_args$args`).
fn return_redirect(url: &str, code: u16) -> Result<(Value, String), String> {
    let status = json!(code);
    for (scheme, rest) in [
        ("https", url.strip_prefix("https://")),
        ("http", url.strip_prefix("http://")),
        ("", url.strip_prefix("$scheme://")),
    ] {
        let Some(rest) = rest else { continue };
        let Some(host) = rest
            .strip_suffix("$request_uri")
            .or_else(|| rest.strip_suffix("$uri$is_args$args"))
        else {
            continue;
        };
        let mut value = json!({ "type": "redirect", "status": status });
        if !scheme.is_empty() {
            value["scheme"] = json!(scheme);
        }
        if host == "$host" || host == "$http_host" {
            if scheme.is_empty() {
                return Err("a redirect to the same scheme and host loops".to_owned());
            }
            value["always"] = json!(true);
            return Ok((
                value,
                format!("redirect to `{scheme}://` on the same host, path and query kept"),
            ));
        }
        if host.contains('$') || host.is_empty() || host.contains('/') {
            break;
        }
        let (name, port) = match host.rsplit_once(':') {
            Some((n, p)) if p.parse::<u16>().is_ok() => (n, p.parse::<u16>().ok()),
            _ => (host, None),
        };
        value["hostname"] = json!(name);
        if let Some(port) = port {
            value["port"] = json!(port);
        }
        return Ok((
            value,
            format!("redirect to `{host}` with the path and query kept"),
        ));
    }
    if url.contains('$') {
        return Err(format!(
            "a redirect to `{url}` uses variables that have no equivalent"
        ));
    }
    let replacement = if url.starts_with('/') {
        format!("${{s}}://${{h}}{}", literal_replacement(url))
    } else if url.starts_with("http://") || url.starts_with("https://") {
        literal_replacement(url)
    } else {
        return Err(format!("a redirect to `{url}` has no equivalent"));
    };
    Ok((
        json!({ "type": "redirect", "regex": "^(?P<s>[a-z]+)://(?P<h>[^/]+)", "replacement": replacement, "status": status }),
        format!("redirect to `{url}` (the query is not added, as NGINX's `return`)"),
    ))
}

/// Splits a rewrite regex into its anchors and body; `None` when anchors appear elsewhere.
fn anchors(re: &str) -> Option<(bool, &str, bool)> {
    let start = re.starts_with('^');
    let body = re.strip_prefix('^').unwrap_or(re);
    let end = body.ends_with('$') && !body.ends_with("\\$");
    let body = if end { &body[..body.len() - 1] } else { body };
    let mut escaped = false;
    let mut class = false;
    for c in body.chars() {
        match (escaped, class, c) {
            (true, ..) => escaped = false,
            (false, _, '\\') => escaped = true,
            (false, false, '[') => class = true,
            (false, true, ']') => class = false,
            (false, false, '^' | '$') => return None,
            _ => {}
        }
    }
    Some((start, body, end))
}

/// `rewrite regex replacement break` → a `rewrite` middleware. NGINX replaces the whole URI
/// when the regex matches anywhere in it, and appends the query unless the replacement ends
/// with `?`; ReverseDock's `rewrite` replaces every match in the path and keeps the query, so
/// the regex is anchored around the original.
fn rewrite_break_middleware(d: &Directive) -> Result<Value, String> {
    let re = d.arg(0);
    let replacement = d.arg(1);
    if replacement.contains('?') {
        return Err("a `rewrite` replacement with a query string has no equivalent".to_owned());
    }
    if has_variable_other_than_captures(replacement) {
        return Err(format!(
            "the replacement `{replacement}` uses variables that have no equivalent"
        ));
    }
    let (start, body, end) = anchors(re)
        .ok_or_else(|| format!("the regular expression `{re}` has anchors inside it"))?;
    let pattern = format!(
        "^{}(?:{body}){}",
        if start { "" } else { ".*?" },
        if end { "$" } else { ".*$" }
    );
    regex::Regex::new(&pattern).map_err(|_| {
        format!("the regular expression `{re}` uses features ReverseDock's engine does not have")
    })?;
    Ok(
        json!({ "type": "rewrite", "regex": pattern, "replacement": captures_to_braces(replacement, 0) }),
    )
}

/// Whether a replacement uses `$name` variables other than numbered captures.
fn has_variable_other_than_captures(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'$' {
            let next = bytes.get(i + 1).copied().unwrap_or(b' ');
            if !next.is_ascii_digit() {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// `$1` → `${N}` shifted by `shift` groups (braces, so `$1x` stays `$1` followed by `x`).
fn captures_to_braces(text: &str, shift: usize) -> String {
    let mut out = String::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '$'
            && let Some(d) = chars.peek().copied().filter(char::is_ascii_digit)
        {
            chars.next();
            let n = d.to_digit(10).unwrap_or(0) as usize + shift;
            let _ = write!(out, "${{{n}}}");
        } else if c == '$' {
            out.push_str("$$");
        } else {
            out.push(c);
        }
    }
    out
}

/// The path part of a rewrite regex made to match within the path of a full URL: `.` and
/// negated classes cannot cross into the query.
fn confine_to_path(body: &str) -> String {
    let mut out = String::new();
    let mut chars = body.chars().peekable();
    let mut class = false;
    while let Some(c) = chars.next() {
        match (class, c) {
            (_, '\\') => {
                let next = chars.next().unwrap_or('\\');
                match (class, next) {
                    (false, 'S') => out.push_str("[^\\s?]"),
                    (false, 'W') => out.push_str("[^\\w?]"),
                    (false, 'D') => out.push_str("[^\\d?]"),
                    _ => {
                        out.push('\\');
                        out.push(next);
                    }
                }
            }
            (false, '.') => out.push_str("[^?]"),
            (false, '[') => {
                class = true;
                out.push('[');
                if chars.peek() == Some(&'^') {
                    chars.next();
                    out.push_str("^?");
                }
            }
            (true, ']') => {
                class = false;
                out.push(']');
            }
            (_, other) => out.push(other),
        }
    }
    out
}

/// `rewrite regex URL permanent|redirect` → a route (the location's or server's condition and
/// the regex on the path) with a `redirect` middleware. "If a replacement string starts with
/// `http://`, `https://`, or `$scheme`, the processing stops and the redirect is returned to the
/// client"; "If a replacement string includes the new request arguments, the previous request
/// arguments are appended after them. If this is undesired, putting a question mark at the end
/// of a replacement string avoids having them appended" (`ngx_http_rewrite_module`).
#[allow(clippy::too_many_lines)] // one pass, in reading order
fn rewrite_redirect(
    run: &mut Run<'_>,
    d: &Directive,
    rule: &str,
    priority: i64,
    label: &str,
) -> Option<RouteOut> {
    let re = d.arg(0);
    let mut replacement = d.arg(1).to_owned();
    let status = if d.arg(2) == "permanent" { 301 } else { 302 };
    let fail = |run: &mut Run<'_>, why: String| {
        run.manual(
            d,
            why,
            "write the redirect as a `redirect` middleware on its own route",
        );
        None
    };
    let Some((start, body, end)) = anchors(re) else {
        return fail(
            run,
            format!("the regular expression `{re}` has anchors inside it"),
        );
    };
    if regex::Regex::new(re).is_err() || re.contains('`') {
        return fail(
            run,
            format!(
                "the regular expression `{re}` uses features ReverseDock's engine does not have"
            ),
        );
    }
    let keep_query = !replacement.ends_with('?');
    if !keep_query {
        replacement.pop();
    }
    if replacement.contains('?') {
        return fail(run, "a redirect target with its own query string has no equivalent here (NGINX appends the original arguments after it)".to_owned());
    }
    // Groups before the original's: scheme, authority, host (3).
    let mut target = replacement
        .replace("$scheme", "${rdocks}")
        .replace("$host", "${rdockh}")
        .replace("$http_host", "${rdocka}");
    if target.contains("$request_uri") || target.contains("$uri") || target.contains("$args") || {
        let stripped = target
            .replace("${rdocks}", "")
            .replace("${rdockh}", "")
            .replace("${rdocka}", "");
        has_variable_other_than_captures(&stripped)
    } {
        return fail(
            run,
            format!(
                "the target `{}` uses variables that have no equivalent",
                d.arg(1)
            ),
        );
    }
    target = captures_to_braces_keep(&target, 3);
    if !(target.starts_with("http://")
        || target.starts_with("https://")
        || target.starts_with("${rdocks}://"))
    {
        if !target.starts_with('/') {
            return fail(
                run,
                format!("the relative target `{}` has no equivalent", d.arg(1)),
            );
        }
        target = format!("${{rdocks}}://${{rdocka}}{target}");
    }
    if keep_query {
        target.push_str("${rdockq}");
    }
    let path = format!(
        "{}(?:{}){}",
        if start { "" } else { "[^?]*?" },
        confine_to_path(body),
        if end { "" } else { "[^?]*" }
    );
    let full = format!(
        "^(?P<rdocks>[a-z][a-z0-9+.-]*)://(?P<rdocka>(?P<rdockh>[^/:?]+)(?::[0-9]+)?){path}(?P<rdockq>\\?.*)?$"
    );
    if regex::Regex::new(&full).is_err() {
        return fail(
            run,
            format!("the regular expression `{re}` cannot be confined to the path"),
        );
    }
    run.exact(
        d,
        format!(
            "a redirect ({status}) for paths matching `{re}`, as its own route above the location's"
        ),
    );
    let mut route = RouteOut {
        label: vec![label.to_owned(), "rewrite".to_owned()],
        rule: join_rule(rule, &format!("PathRegexp(`{re}`)")),
        priority,
        ..RouteOut::default()
    };
    route.middlewares.push((
        "redirect".to_owned(),
        json!({ "type": "redirect", "regex": full, "replacement": target, "status": status }),
    ));
    route.service = Some((
        "not-found".to_owned(),
        json!({ "respond": { "status": 404 } }),
    ));
    Some(route)
}

/// Like [`captures_to_braces`] but leaves `${name}` groups alone.
fn captures_to_braces_keep(text: &str, shift: usize) -> String {
    let mut out = String::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '$' {
            match chars.peek().copied() {
                Some(d) if d.is_ascii_digit() => {
                    chars.next();
                    let n = d.to_digit(10).unwrap_or(0) as usize + shift;
                    let _ = write!(out, "${{{n}}}");
                }
                Some('{') => out.push('$'),
                _ => out.push_str("$$"),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// `proxy_pass` / `grpc_pass`: the service and the upstream path.
#[allow(clippy::too_many_lines)] // the four URI cases and the service settings
fn proxy(
    run: &mut Run<'_>,
    srv: &Server<'_, '_, '_>,
    loc: &Loc<'_>,
    levels: &[&[Directive]; 3],
    pass: &Directive,
    route: &mut RouteOut,
    after_break: bool,
) {
    let url = pass.arg(0);
    let grpc = pass.name == "grpc_pass";
    let (scheme, rest) = if let Some(r) = url.strip_prefix("http://") {
        ("http", r)
    } else if let Some(r) = url.strip_prefix("https://") {
        ("https", r)
    } else if let Some(r) = url.strip_prefix("grpc://") {
        ("h2c", r)
    } else if let Some(r) = url.strip_prefix("grpcs://") {
        ("https", r)
    } else if grpc && !url.contains("://") {
        ("h2c", url)
    } else {
        refuse(run, pass, "a `proxy_pass` this tool cannot read", "");
        route
            .blocked
            .push("its `proxy_pass` was not read".to_owned());
        return;
    };
    if url.contains('$') {
        refuse(
            run,
            pass,
            "`proxy_pass` with variables resolves its target at run time (through `resolver`): no equivalent",
            "name the backend in a service",
        );
        route
            .blocked
            .push("its `proxy_pass` uses variables".to_owned());
        route.service = Some((
            "not-found".to_owned(),
            json!({ "respond": { "status": 502 } }),
        ));
        return;
    }
    // `http://unix:/path:/uri`, `http://host[:port][/uri]`.
    let (authority, uri) = if let Some(socket) = rest.strip_prefix("unix:") {
        match socket.split_once(':') {
            Some((path, uri)) => (format!("unix://{path}"), Some(uri.to_owned())),
            None => (format!("unix://{socket}"), None),
        }
    } else {
        match rest.find('/') {
            Some(i) => (rest[..i].to_owned(), Some(rest[i..].to_owned())),
            None => (rest.to_owned(), None),
        }
    };
    let mut notes: Vec<String> = Vec::new();
    let mut approx: Vec<String> = Vec::new();
    // The service: an upstream block, or the address itself.
    let upstream = srv.http.upstreams.get(&authority);
    let (base_name, mut service) = if let Some(up) = upstream {
        notes.push(format!("the `upstream {authority}` block → its service"));
        (authority.clone(), up.service.clone())
    } else {
        let address = if authority.starts_with("unix://")
            || authority.contains(':') && !authority.ends_with(']')
        {
            authority.clone()
        } else {
            format!("{authority}:{}", if scheme == "https" { 443 } else { 80 })
        };
        let mut service = Map::new();
        service.insert("backends".to_owned(), json!([{ "address": address }]));
        (output::slug(&address), service)
    };
    if scheme != "http" {
        service.insert("scheme".to_owned(), json!(scheme));
    }
    // Upstream TLS.
    if scheme == "https" {
        let mut tls = Map::new();
        let verify = last(levels, "proxy_ssl_verify");
        match verify.map(|d| d.arg(0)) {
            Some("on") => {
                if let Some(v) = verify {
                    run.exact(
                        v,
                        "backend certificates are verified, as ReverseDock always does",
                    );
                }
            }
            other => {
                run.defaults_changed.insert("nginx.default.upstream_tls", "NGINX does not verify backend certificates by default (`proxy_ssl_verify off`) and sends no server name (`proxy_ssl_server_name off`); ReverseDock verifies them and sends the name, and the migration keeps that".to_owned());
                if let (Some(v), Some("off")) = (verify, other) {
                    run.approx(v, "kept on: ReverseDock verifies backend certificates (opt out per service with `tls.verify: false`)");
                    run.note(v, crate::output::Notes::security);
                }
                approx.push(
                    "the backend's certificate is verified (NGINX's default is not to)".to_owned(),
                );
            }
        }
        if let Some(n) = last(levels, "proxy_ssl_name") {
            if n.arg(0).contains('$') {
                run.manual(n, "a TLS name with variables", "");
            } else {
                tls.insert("server_name".to_owned(), json!(n.arg(0)));
                run.exact(n, "→ `tls.server_name`");
            }
        }
        if let Some(n) = last(levels, "proxy_ssl_server_name") {
            run.exact(n, "ReverseDock sends the server name (SNI) to TLS backends");
        }
        if let Some(c) = last(levels, "proxy_ssl_trusted_certificate") {
            tls.insert("ca_file".to_owned(), json!(c.arg(0)));
            run.exact(c, "→ `tls.ca_file`");
        }
        if let Some(c) = last(levels, "proxy_ssl_certificate") {
            tls.insert("cert_file".to_owned(), json!(c.arg(0)));
            run.exact(c, "→ `tls.cert_file`");
        }
        if let Some(c) = last(levels, "proxy_ssl_certificate_key") {
            tls.insert("key_file".to_owned(), json!(c.arg(0)));
            run.exact(c, "→ `tls.key_file` (never read)");
        }
        for name in [
            "proxy_ssl_protocols",
            "proxy_ssl_ciphers",
            "proxy_ssl_session_reuse",
            "proxy_ssl_verify_depth",
        ] {
            if let Some(d) = last(levels, name) {
                run.approx(
                    d,
                    format!("`{name}`: TLS to backends uses ReverseDock's settings"),
                );
            }
        }
        if !tls.is_empty() {
            service.insert("tls".to_owned(), Value::Object(tls));
        }
    }
    // Headers to the backend: the effective `proxy_set_header` level, or the defaults.
    let headers = list(levels, &["proxy_set_header"]);
    let mut set = Map::new();
    let mut remove = Vec::new();
    let mut host_header = None;
    for h in &headers {
        let name = h.arg(0);
        let value = h.arg(1);
        let lower = name.to_ascii_lowercase();
        match (lower.as_str(), value) {
            ("host", "$host" | "$http_host") => {
                host_header = Some(true);
                run.exact(
                    h,
                    "the client's `Host` is passed (`pass_host_header`, the default)",
                );
            }
            ("host", "$proxy_host") => {
                host_header = Some(false);
                run.exact(
                    h,
                    "`Host` is the backend's address (`pass_host_header: false`)",
                );
            }
            ("host", other) => {
                run.manual(
                    h,
                    format!("a fixed or computed `Host` (`{other}`) has no equivalent"),
                    "",
                );
                route
                    .blocked
                    .push("its `Host` header was not migrated".to_owned());
            }
            ("x-real-ip", "$remote_addr")
            | ("x-forwarded-proto", "$scheme")
            | ("x-forwarded-host", "$host" | "$http_host")
            | ("x-forwarded-port", "$server_port") => {
                run.exact(h, "a forwarding header ReverseDock writes itself");
            }
            ("x-forwarded-for", "$proxy_add_x_forwarded_for" | "$remote_addr") => {
                run.approx(h, "a forwarding header ReverseDock writes itself; it keeps a client's `X-Forwarded-For` only from `security.trusted_proxies` (NGINX appends to whatever the client sent)");
            }
            ("upgrade", "$http_upgrade") => {
                run.exact(h, "WebSocket upgrades are forwarded by default");
            }
            ("connection", v) if v.starts_with('$') && srv.http.ws_vars.contains(v) => run.exact(
                h,
                "WebSocket upgrades are forwarded by default (the `map` idiom)",
            ),
            ("connection", v) if v.eq_ignore_ascii_case("upgrade") => {
                run.exact(h, "WebSocket upgrades are forwarded by default");
            }
            ("connection", "") => run.exact(h, "connections to backends are kept alive and pooled"),
            ("connection", v) if v.eq_ignore_ascii_case("close") => {
                run.approx(h, "ReverseDock keeps connections to backends open (pooled)");
            }
            (_, "") => {
                remove.push(json!(name));
                run.exact(
                    h,
                    "an empty value removes the header (`headers.request.remove`)",
                );
            }
            (_, v) if !v.contains('$') => {
                set.insert(name.to_owned(), json!(v));
                run.exact(h, "→ `headers.request.set`");
            }
            (_, v) => {
                run.manual(
                    h,
                    format!("the value `{v}` uses variables that have no equivalent here"),
                    "",
                );
                route
                    .blocked
                    .push(format!("its header `{name}` was not migrated"));
            }
        }
    }
    if let Some(true) = host_header {
        service.insert("pass_host_header".to_owned(), json!(true));
    } else {
        service.insert("pass_host_header".to_owned(), json!(false));
        if headers.is_empty() || host_header.is_none() {
            if upstream.is_some() {
                approx.push(format!("`Host` is NGINX's default `$proxy_host`, here the upstream name `{authority}`; ReverseDock sends the backend's address (`pass_host_header: false`)"));
            } else {
                notes.push(
                    "`Host` is the backend's address (NGINX's default `$proxy_host`)".to_owned(),
                );
            }
        }
    }
    if !set.is_empty() || !remove.is_empty() {
        let mut value = json!({ "type": "headers", "request": {} });
        if !set.is_empty() {
            value["request"]["set"] = Value::Object(set);
        }
        if !remove.is_empty() {
            value["request"]["remove"] = Value::Array(remove);
        }
        route.middlewares.push(("headers-up".to_owned(), value));
    }
    for h in list(levels, &["proxy_hide_header"]) {
        route.middlewares.push((
            "hide".to_owned(),
            json!({ "type": "headers", "response": { "remove": [h.arg(0)] } }),
        ));
        run.exact(h, "→ `headers.response.remove`");
    }
    // Timeouts: NGINX's 60s connect timeout written explicitly; read and send equal ours.
    let connect = last(levels, "proxy_connect_timeout");
    match connect.map(|d| (d, time(d.arg(0)))) {
        Some((d, Some(t))) => {
            route.timeouts.insert("connect".to_owned(), json!(t));
            run.exact(d, format!("→ `timeouts.connect: {t}` on the route"));
        }
        Some((d, None)) => run.manual(d, "not a time", ""),
        None => {
            route.timeouts.insert("connect".to_owned(), json!("1m"));
            run.defaults_changed.insert("nginx.default.connect_timeout", "NGINX's default connect timeout (`proxy_connect_timeout 60s`) is written as `timeouts.connect: 1m` on each proxied route (ReverseDock's default is 5s)".to_owned());
        }
    }
    for (name, field) in [
        ("proxy_read_timeout", "read"),
        ("proxy_send_timeout", "write"),
        ("grpc_read_timeout", "read"),
        ("grpc_send_timeout", "write"),
        ("grpc_connect_timeout", "connect"),
    ] {
        if let Some(d) = last(levels, name) {
            match time(d.arg(0)) {
                Some(t) => {
                    if t != "1m" {
                        route.timeouts.insert(field.to_owned(), json!(t));
                    }
                    run.exact(
                        d,
                        format!(
                            "→ `timeouts.{field}: {t}` (between two reads or writes, as in NGINX)"
                        ),
                    );
                }
                None => run.manual(d, "not a time", ""),
            }
        }
    }
    if let Some(d) = last(levels, "proxy_http_version") {
        match d.arg(0) {
            "1.1" => run.exact(d, "HTTP/1.1 to backends, as ReverseDock speaks"),
            "1.0" => run.approx(d, "ReverseDock speaks HTTP/1.1 to backends"),
            _ => run.approx(
                d,
                "HTTP/2 to backends is `scheme: h2c` or `https` here; written as HTTP/1.1",
            ),
        }
    }
    let buffering = last(levels, "proxy_buffering");
    let request_buffering = last(levels, "proxy_request_buffering");
    for d in [buffering, request_buffering].into_iter().flatten() {
        if d.arg(0) == "off" {
            run.exact(d, "streaming, as ReverseDock always does");
        } else {
            run.approx(d, "ReverseDock streams instead of buffering (add `hold_body` to buffer request bodies)");
        }
    }
    if buffering.is_none_or(|d| d.arg(0) != "off")
        || request_buffering.is_none_or(|d| d.arg(0) != "off")
    {
        run.defaults_changed.insert("nginx.default.buffering", "NGINX buffers requests and responses by default (`proxy_buffering on`, `proxy_request_buffering on`), which protects backends from slow clients; ReverseDock streams both".to_owned());
    }
    if let Some(d) = last(levels, "proxy_next_upstream") {
        if d.arg(0) == "off" {
            service.remove("retries");
            run.exact(d, "no retries on another server");
        } else {
            run.approx(d, "→ `retries` on connection failures and timeouts; `http_*` conditions are not carried over");
        }
    }
    for name in [
        "proxy_next_upstream_tries",
        "proxy_next_upstream_timeout",
        "proxy_intercept_errors",
        "proxy_method",
        "proxy_set_body",
        "proxy_pass_request_body",
        "proxy_pass_request_headers",
        "proxy_cookie_domain",
        "proxy_cookie_path",
        "proxy_cookie_flags",
        "proxy_bind",
        "proxy_socket_keepalive",
        "proxy_limit_rate",
        "proxy_force_ranges",
        "proxy_ignore_headers",
    ] {
        if let Some(d) = last(levels, name) {
            run.manual(d, format!("`{name}` has no equivalent"), "");
        }
    }
    run.defaults_changed.entry("nginx.default.proxy_redirect").or_insert_with(|| "NGINX rewrites `Location` and `Refresh` headers of backend redirects that point at the `proxy_pass` address (`proxy_redirect default`); ReverseDock passes them unchanged, so a backend that redirects to its own address must use relative or public URLs".to_owned());
    // The upstream path: the four cases of `proxy_pass` (ngx_http_proxy_module): "If the
    // proxy_pass directive is specified with a URI, then when a request is passed to the server,
    // the part of a normalized request URI matching the location is replaced by a URI specified
    // in the directive"; "If proxy_pass is specified without a URI, the request URI is passed to
    // the server in the same form as sent by a client"; with a regular-expression or named
    // location "proxy_pass should be specified without a URI"; after `rewrite … break` "the URI
    // specified in the directive is ignored and the full changed request URI is passed".
    match (uri.as_deref(), loc.modifier) {
        (None, _) => notes.push("the request URI is passed as it is".to_owned()),
        (Some(_), _) if after_break => notes.push(
            "the URI in `proxy_pass` is ignored after `rewrite … break`, as in NGINX".to_owned(),
        ),
        (Some(u), Modifier::Regex { .. } | Modifier::Named) => {
            run.manual(pass, format!("`proxy_pass` with a URI (`{u}`) inside a regular-expression or named location: NGINX refuses this (\"proxy_pass cannot have URI part\")"), "remove the URI, or rewrite the path with `rewrite … break`");
            route
                .blocked
                .push("its `proxy_pass` has a URI NGINX would refuse".to_owned());
        }
        (Some(u), Modifier::Exact) => {
            if u != loc.uri {
                route.middlewares.push((
                    "path".to_owned(),
                    json!({ "type": "replace_path", "path": u }),
                ));
            }
            notes.push(format!(
                "the matched URI `{}` becomes `{u}` (`replace_path`; the query is kept)",
                loc.uri
            ));
        }
        (Some(u), _) => {
            if let Some((value, exact, note)) = prefix_rewrite(&loc.uri, u) {
                if let Some(value) = value {
                    route.middlewares.push(("path".to_owned(), value));
                }
                if exact {
                    notes.push(note);
                } else {
                    approx.push(note);
                }
            } else {
                run.manual(
                    pass,
                    format!("the URI `{u}` cannot be written as a path rewrite"),
                    "",
                );
                route
                    .blocked
                    .push("its `proxy_pass` URI was not migrated".to_owned());
            }
        }
    }
    if !route.blocked.is_empty() && route.service.is_none() {
        // Keep the service so the disabled route validates.
    }
    route.service = Some((base_name.clone(), Value::Object(service)));
    if grpc {
        notes.push("gRPC to the backend".to_owned());
    }
    if approx.is_empty() {
        run.exact(pass, notes.join("; "));
    } else {
        run.approx(pass, format!("{}; {}", notes.join("; "), approx.join("; ")));
    }
}

/// The path rewrite for `location L { proxy_pass …U; }` with a prefix location: "the part of a
/// normalized request URI matching the location is replaced" by `U`. Returns the middleware
/// (none when the path is unchanged), whether it is exact, and a note.
fn prefix_rewrite(location: &str, uri: &str) -> Option<(Option<Value>, bool, String)> {
    if uri.contains('$') || location.contains('`') {
        return None;
    }
    if uri == location {
        return Some((None, true, format!("`{location}` is passed unchanged")));
    }
    if location.ends_with('/') && uri == "/" {
        return Some((
            Some(json!({ "type": "strip_prefix", "prefixes": [location] })),
            true,
            format!("`{location}` is replaced by `/` (`strip_prefix`)"),
        ));
    }
    if location == "/" && uri.ends_with('/') && uri.len() > 1 {
        return Some((
            Some(json!({ "type": "add_prefix", "prefix": uri.trim_end_matches('/') })),
            true,
            format!("`/` is replaced by `{uri}` (`add_prefix`)"),
        ));
    }
    let replacement = format!("{}${{1}}", literal_replacement(uri));
    if !location.ends_with('/') && uri.ends_with('/') {
        // `/a` + `/b/`: NGINX sends `/b//c` for `/a/c`; ReverseDock refuses a path with an empty
        // segment, so one slash is kept.
        return Some((
            Some(
                json!({ "type": "rewrite", "regex": format!("^{}/?(.*)$", escape(location)), "replacement": replacement }),
            ),
            false,
            format!(
                "`{location}` is replaced by `{uri}`; where NGINX sends a double slash (`{location}/x` → `{uri}/x`), ReverseDock sends one"
            ),
        ));
    }
    Some((
        Some(
            json!({ "type": "rewrite", "regex": format!("^{}(.*)$", escape(location)), "replacement": replacement }),
        ),
        true,
        format!("`{location}` is replaced by `{uri}` (a `rewrite`; the query is kept)"),
    ))
}

/// Static content: `root`/`alias`, `index`, `autoindex`, and the `try_files` idioms.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn static_content(
    run: &mut Run<'_>,
    levels: &[&[Directive]],
    loc: Option<&Loc<'_>>,
    try_files: Option<&Directive>,
    route: &mut RouteOut,
    named: &BTreeMap<String, &Loc<'_>>,
    used_named: &mut BTreeSet<String>,
    srv: &Server<'_, '_, '_>,
) {
    let inner = levels.last().copied().unwrap_or_default();
    let alias = loc.and_then(|_| inner.iter().find(|d| d.name == "alias"));
    let root = last(levels, "root");
    let mut value = Map::new();
    value.insert("type".to_owned(), json!("static"));
    match (alias, root) {
        (Some(a), _) => {
            let Some(l) = loc else { return };
            let ok = matches!(l.modifier, Modifier::Prefix | Modifier::Preferential)
                && !a.arg(0).contains('$')
                && (l.uri.ends_with('/') == a.arg(0).ends_with('/'));
            if ok {
                value.insert("root".to_owned(), json!(a.arg(0)));
                route.middlewares.push((
                    "alias".to_owned(),
                    json!({ "type": "strip_prefix", "prefixes": [l.uri.trim_end_matches('/')] }),
                ));
                run.exact(a, "`alias` replaces the location's prefix: `strip_prefix` then `static` with the alias as root");
            } else {
                run.manual(a, "`alias` in a regular-expression location, with variables, or with a trailing slash that differs from the location's is not migrated", "");
                route
                    .blocked
                    .push("its `alias` was not migrated".to_owned());
                value.insert("root".to_owned(), json!(a.arg(0)));
            }
        }
        (None, Some(r)) => {
            if r.arg(0).contains('$') {
                run.manual(r, "a root with variables has no equivalent", "");
                route.blocked.push("its `root` uses variables".to_owned());
            } else {
                run.exact(
                    r,
                    "→ the `static` root (the request path is appended, as with `root`)",
                );
            }
            value.insert("root".to_owned(), json!(r.arg(0)));
        }
        (None, None) => {
            route
                .blocked
                .push("no `root`: NGINX would serve its default `html` directory".to_owned());
            value.insert("root".to_owned(), json!("html"));
        }
    }
    match last(levels, "index") {
        Some(i) => {
            value.insert("index".to_owned(), json!(i.values()));
            if !run.noted(i) {
                run.exact(i, "→ the `static` index files");
            }
        }
        None => {
            value.insert("index".to_owned(), json!(["index.html"]));
        }
    }
    if let Some(a) = last(levels, "autoindex") {
        if a.arg(0) == "on" {
            value.insert("listing".to_owned(), json!(true));
            run.approx(
                a,
                "directory listings → `static.listing` (the page differs)",
            );
        } else {
            run.exact(a, "no directory listings, as by default");
        }
    }
    if let Some(e) = last(levels, "expires") {
        match e.values().as_slice() {
            ["off"] => run.exact(e, "no `Expires`, as by default"),
            ["epoch"] => {
                value.insert("cache_control".to_owned(), json!({ "default": "no-cache" }));
                run.approx(e, "→ `cache_control: no-cache` (no `Expires` header)");
            }
            [t] if time(t).is_some() => {
                let secs = time_secs(t).unwrap_or(0);
                value.insert(
                    "cache_control".to_owned(),
                    json!({ "default": format!("max-age={secs}") }),
                );
                run.approx(
                    e,
                    format!("→ `cache_control: max-age={secs}` (no `Expires` header)"),
                );
            }
            _ => run.manual(e, "this `expires` form has no equivalent", ""),
        }
    }
    // NGINX serves no precompressed sidecars unless `gzip_static on`; ReverseDock does by default.
    value.insert("precompressed".to_owned(), json!([]));
    if let Some(g) = last(levels, "gzip_static")
        && (g.arg(0) == "on" || g.arg(0) == "always")
    {
        value.insert("precompressed".to_owned(), json!(["gzip"]));
    }
    let mut service = None;
    if let Some(t) = try_files {
        let args = t.values();
        match args.as_slice() {
            ["$uri", "=404"] | ["$uri", "$uri/", "=404"] => {
                run.exact(t, "files, then 404: what `static` does");
            }
            ["$uri", "$uri/", fallback] | ["$uri", fallback]
                if fallback.starts_with('/')
                    && !fallback.contains('$')
                    && !fallback.contains('?') =>
            {
                value.insert("fallback".to_owned(), json!(fallback));
                run.approx(t, format!("the single-page-app idiom → `fallback: {fallback}`; ReverseDock serves it only for GET and HEAD requests whose last path segment has no `.`"));
            }
            ["$uri", "$uri/", target] | ["$uri", target] if target.starts_with('@') => {
                if let Some(n) = named.get(*target).copied() {
                    let nb = n.d.block.as_deref().unwrap_or_default();
                    if let Some(pass) = nb.iter().find(|d| d.name == "proxy_pass") {
                        used_named.insert((*target).to_owned());
                        run.exact(
                            n.d,
                            "the `try_files` fallback location: its backend is the route's service",
                        );
                        let nl: Vec<&[Directive]> = levels[..levels.len().saturating_sub(1)]
                            .iter()
                            .copied()
                            .chain(std::iter::once(nb))
                            .collect();
                        let nlevels: [&[Directive]; 3] = [
                            nl.first().copied().unwrap_or_default(),
                            nl.get(1).copied().unwrap_or_default(),
                            nb,
                        ];
                        let mut fallback = RouteOut::default();
                        proxy(run, srv, n, &nlevels, pass, &mut fallback, false);
                        route.blocked.extend(fallback.blocked);
                        route.middlewares.extend(fallback.middlewares);
                        route.timeouts = fallback.timeouts;
                        service = fallback.service;
                        value.insert("pass_through".to_owned(), json!(true));
                        run.approx(t, "files first, else the named location's backend → `static` with `pass_through`; requests with methods other than GET and HEAD always go to the backend");
                        for d in nb.iter().filter(|d| d.name != "proxy_pass") {
                            if !run.noted(d) {
                                run.exact(d, "part of the `try_files` fallback location");
                            }
                        }
                    } else {
                        run.manual(
                            t,
                            "a `try_files` fallback to a named location that does not proxy",
                            "",
                        );
                        route
                            .blocked
                            .push("its `try_files` was not migrated".to_owned());
                    }
                } else {
                    run.manual(
                        t,
                        format!("the named location `{target}` does not exist"),
                        "",
                    );
                    route
                        .blocked
                        .push("its `try_files` was not migrated".to_owned());
                }
            }
            _ => {
                run.manual(t, "this `try_files` form has no equivalent (only `$uri [$uri/] =404`, a fixed fallback file, or a named location that proxies)", "");
                route
                    .blocked
                    .push("its `try_files` was not migrated".to_owned());
            }
        }
    }
    route
        .middlewares
        .push(("static".to_owned(), Value::Object(value)));
    route.service = service;
}

fn time_secs(text: &str) -> Option<u64> {
    let d: rdock_model::values::Duration = time(text)?.parse().ok()?;
    Some(d.as_std().as_secs())
}

/// Settings every content kind shares: body size, access rules, basic auth, response headers,
/// compression.
#[allow(clippy::too_many_lines)]
fn common(
    run: &mut Run<'_>,
    levels: &[&[Directive]],
    route: &mut RouteOut,
    proxied: bool,
    srv: &Server<'_, '_, '_>,
) {
    // client_max_body_size: "Default: client_max_body_size 1m"; "Setting size to 0 disables
    // checking of client request body size" (ngx_http_core_module).
    if let Some(d) = last(levels, "client_max_body_size") {
        match size(d.arg(0)) {
            Some(0) => run.exact(d, "no limit (`0`), as ReverseDock by default"),
            Some(bytes) => {
                route.max_body = Some(size_text(bytes));
                run.exact(
                    d,
                    format!(
                        "→ `max_body: {}` (413 when exceeded, as NGINX)",
                        size_text(bytes)
                    ),
                );
            }
            None => run.manual(d, "not a size", ""),
        }
    } else {
        route.max_body = Some("1MiB".to_owned());
        run.defaults_changed.insert("nginx.default.body_limit", "NGINX's default request body limit (`client_max_body_size 1m`) is written as `max_body: 1MiB` on each route (ReverseDock has no limit by default)".to_owned());
    }
    // allow/deny: "The rules are checked in sequence until the first match is found"; the list is
    // inherited only when a level has none (ngx_http_access_module).
    let rules = list(levels, &["allow", "deny"]);
    if !rules.is_empty() {
        let mut allows = Vec::new();
        let mut denies = Vec::new();
        let mut final_rule = None;
        let mut pure = true;
        for (i, r) in rules.iter().enumerate() {
            let target = r.arg(0);
            let last_rule = i + 1 == rules.len();
            if target == "all" {
                if !last_rule {
                    pure = false;
                }
                final_rule = Some(r.name.as_str());
            } else if r.name == "allow" {
                allows.push(target.to_owned());
            } else {
                denies.push(target.to_owned());
            }
        }
        let shape = match (pure, final_rule, allows.is_empty(), denies.is_empty()) {
            (true, Some("deny"), false, true) => Some(("ip_allow", allows.clone())),
            (true, Some("allow") | None, true, false) => Some(("ip_deny", denies.clone())),
            (true, Some("deny"), true, true) => Some(("deny_all", Vec::new())),
            (true, Some("allow"), true, true) => Some(("allow_all", Vec::new())),
            _ => None,
        };
        match shape {
            Some(("ip_allow", cidrs)) => {
                route.middlewares.insert(
                    0,
                    (
                        "allow".to_owned(),
                        json!({ "type": "ip_allow", "cidrs": cidrs }),
                    ),
                );
                for r in &rules {
                    run.exact(
                        r,
                        "`allow …; deny all;` → `ip_allow` (403 for others, as NGINX)",
                    );
                }
            }
            Some(("ip_deny", cidrs)) => {
                route.middlewares.insert(
                    0,
                    (
                        "deny".to_owned(),
                        json!({ "type": "ip_deny", "cidrs": cidrs }),
                    ),
                );
                for r in &rules {
                    run.exact(r, "`deny …; [allow all;]` → `ip_deny` (403, as NGINX)");
                }
            }
            Some(("deny_all", _)) => {
                route.middlewares.clear();
                route.service = Some((
                    "respond-403".to_owned(),
                    json!({ "respond": { "status": 403 } }),
                ));
                for r in &rules {
                    run.exact(r, "`deny all` → a fixed 403 answer");
                }
            }
            Some(_) => {
                for r in &rules {
                    run.exact(r, "`allow all`: no restriction");
                }
            }
            None => {
                for r in &rules {
                    run.manual(r, "a mixed `allow`/`deny` list (not `allow …; deny all;` or `deny …; allow all;`) has no equivalent", "split it into an `ip_allow` and an `ip_deny` middleware if that keeps its meaning");
                }
                route
                    .blocked
                    .push("its `allow`/`deny` rules were not migrated".to_owned());
            }
        }
    }
    // auth_basic.
    if let Some(a) = last(levels, "auth_basic") {
        if a.arg(0) == "off" {
            run.exact(a, "no authentication here, as `auth_basic off`");
        } else {
            match last(levels, "auth_basic_user_file") {
                Some(f) if !f.arg(0).contains('$') => {
                    let pos = route
                        .middlewares
                        .iter()
                        .position(|(k, _)| k == "allow" || k == "deny")
                        .map_or(0, |p| p + 1);
                    route.middlewares.insert(pos, ("auth".to_owned(), json!({ "type": "basic_auth", "realm": a.arg(0), "users_file": f.arg(0) })));
                    run.exact(a, "→ `basic_auth` with this realm");
                    run.exact(f, "→ `basic_auth.users_file`: the file is named, never read (bcrypt and argon2id hashes; `$apr1$` and `{SHA}` are accepted with a warning)");
                }
                _ => {
                    run.manual(
                        a,
                        "`auth_basic` without a user file (or one named with variables)",
                        "",
                    );
                    route
                        .blocked
                        .push("its `auth_basic` was not migrated".to_owned());
                }
            }
        }
    }
    // add_header: inherited only when a level has none (unless `add_header_inherit merge`,
    // 1.29.3); without `always` only for 200, 201, 204, 206, 301, 302, 303, 304, 307 and 308
    // (ngx_http_headers_module).
    let merge = last(levels, "add_header_inherit").is_some_and(|d| d.arg(0) == "merge");
    if let Some(d) = last(levels, "add_header_inherit") {
        run.exact(d, "how `add_header` is inherited is applied here");
    }
    let adds: Vec<&Directive> = if merge {
        levels
            .iter()
            .flat_map(|l| l.iter())
            .filter(|d| d.name == "add_header")
            .collect()
    } else {
        list(levels, &["add_header"])
    };
    let mut add = Map::new();
    let mut not_always = false;
    for h in &adds {
        let name = h.arg(0);
        let value = h.arg(1);
        if value.contains('$') {
            run.manual(
                h,
                format!("the value `{value}` uses variables that have no equivalent"),
                "",
            );
            route
                .blocked
                .push(format!("its response header `{name}` was not migrated"));
            continue;
        }
        let always = h.arg(2) == "always";
        if !always {
            not_always = true;
        }
        match add.get(name).and_then(Value::as_str) {
            Some(existing) => {
                let combined = format!("{existing}, {value}");
                add.insert(name.to_owned(), json!(combined));
            }
            None => {
                add.insert(name.to_owned(), json!(value));
            }
        }
        if always {
            run.exact(h, "→ `headers.response.add` (every status, as `always`)");
        } else {
            run.approx(h, "→ `headers.response.add`; ReverseDock adds it to every answer, NGINX only to 200, 201, 204, 206, 301, 302, 303, 304, 307 and 308 without `always`");
        }
    }
    let _ = not_always;
    if !add.is_empty() {
        route.middlewares.push((
            "headers".to_owned(),
            json!({ "type": "headers", "response": { "add": add } }),
        ));
    }
    // gzip: off by default; `gzip_types` default `text/html`, `gzip_min_length` 20
    // (ngx_http_gzip_module).
    if let Some(g) = last(levels, "gzip") {
        if g.arg(0) == "on" {
            let mut types = vec!["text/html".to_owned()];
            if let Some(t) = last(levels, "gzip_types") {
                for v in t.values() {
                    if v == "*" {
                        types.clear();
                        break;
                    }
                    if !types.contains(&v.to_owned()) {
                        types.push(v.to_owned());
                    }
                }
                run.exact(
                    t,
                    "→ `compress.content_types` (with `text/html`, which NGINX always compresses)",
                );
            }
            let min = last(levels, "gzip_min_length")
                .and_then(|d| size(d.arg(0)))
                .unwrap_or(20);
            if let Some(m) = last(levels, "gzip_min_length") {
                run.exact(m, "→ `compress.min_size`");
            }
            let mut value = json!({ "type": "compress", "algorithms": ["gzip"], "min_size": format!("{min}B") });
            if !types.is_empty() {
                value["content_types"] = json!(types);
            }
            route.middlewares.push(("compress".to_owned(), value));
            run.approx(g, "→ `compress` with gzip; NGINX decides on `Content-Length` only and skips proxied requests (`gzip_proxied off`), ReverseDock compresses any matching answer");
            for name in [
                "gzip_comp_level",
                "gzip_vary",
                "gzip_proxied",
                "gzip_disable",
                "gzip_http_version",
                "gzip_buffers",
            ] {
                if let Some(d) = last(levels, name) {
                    run.approx(d, format!("`{name}` is not configurable here"));
                }
            }
        } else {
            run.exact(g, "no compression, as by default");
        }
    }
    for name in [
        "gzip_types",
        "gzip_min_length",
        "gzip_comp_level",
        "gzip_vary",
        "gzip_proxied",
        "gzip_disable",
        "gzip_http_version",
        "gzip_buffers",
    ] {
        for d in levels
            .iter()
            .flat_map(|l| l.iter())
            .filter(|d| d.name == name)
        {
            if !run.noted(d) {
                run.exact(d, "no effect: compression is off");
            }
        }
    }
    let _ = (proxied, srv);
    // Directives this function and the content handlers do not use are accounted at the end.
    account_level(run, levels.last().copied().unwrap_or_default());
}

/// Accounts for the directives of one level that nothing above used.
fn account_level(run: &mut Run<'_>, level: &[Directive]) {
    for d in level.iter().filter(|d| d.block.is_none()) {
        if run.noted(d) {
            continue;
        }
        let name = d.name.as_str();
        match name {
            "include" => include(run, d),
            "listen" | "server_name" => {}
            "proxy_ssl_verify"
            | "proxy_ssl_name"
            | "proxy_ssl_server_name"
            | "proxy_ssl_trusted_certificate"
            | "proxy_ssl_certificate"
            | "proxy_ssl_certificate_key"
            | "proxy_ssl_protocols"
            | "proxy_ssl_ciphers"
            | "proxy_ssl_session_reuse" => {
                run.exact(d, "no effect: no HTTPS backend here");
            }
            "proxy_set_header"
            | "proxy_hide_header"
            | "proxy_connect_timeout"
            | "proxy_read_timeout"
            | "proxy_send_timeout"
            | "proxy_http_version"
            | "proxy_buffering"
            | "proxy_request_buffering"
            | "proxy_next_upstream" => {
                run.exact(d, "not used here: no `proxy_pass` uses it at this level, or a level below overrides it");
            }
            "client_max_body_size"
            | "root"
            | "index"
            | "autoindex"
            | "auth_basic"
            | "auth_basic_user_file"
            | "add_header"
            | "allow"
            | "deny"
            | "expires"
            | "gzip" => {
                run.exact(
                    d,
                    "not used here: a level below overrides it, or no route uses it",
                );
            }
            _ => {
                if let Some((_, why)) = NO_EFFECT.iter().find(|(n, _)| *n == name) {
                    run.exact(d, format!("{why}: no equivalent needed"));
                } else if let Some((_, why, hint, _)) =
                    REFUSED_PREFIX.iter().find(|(p, ..)| name.starts_with(p))
                {
                    refuse(run, d, why, hint);
                } else if name.starts_with("ssl_") {
                    run.exact(d, "used by the listener's TLS settings");
                } else {
                    run.dropped(d, format!("`{name}` is not a directive this tool knows"));
                    run.code(d, "nginx.directive.unknown");
                }
            }
        }
    }
}

/// `upstream name { … }` → a service template (`ngx_http_upstream_module`: weighted round-robin by
/// default; `server` parameters `weight=1`, `max_fails=1`, `fail_timeout=10s`, `backup`, `down`,
/// `max_conns`; `keepalive 32 local` by default since 1.29.7).
#[allow(clippy::too_many_lines)]
fn upstream(run: &mut Run<'_>, d: &Directive, inner: &[Directive]) -> Upstream {
    run.exact(d, "an `upstream` block → a service");
    let mut backends = Vec::new();
    let mut failures: Option<u64> = None;
    let mut fail_timeout: Option<String> = None;
    let mut policy: Option<(&str, Option<String>)> = None;
    let mut max_conns: Option<u64> = None;
    for e in inner {
        let args = e.values();
        match e.name.as_str() {
            "server" => {
                let Some(address) = args.first() else {
                    run.manual(e, "a `server` without an address", "");
                    continue;
                };
                let address = if let Some(path) = address.strip_prefix("unix:") {
                    format!("unix://{path}")
                } else if address.contains(':') && !address.ends_with(']') {
                    (*address).to_owned()
                } else {
                    format!("{address}:80")
                };
                let mut backend = json!({ "address": address });
                let mut notes = Vec::new();
                let mut down = false;
                for param in &args[1..] {
                    if let Some(w) = param.strip_prefix("weight=") {
                        backend["weight"] = json!(w.parse::<u64>().unwrap_or(1));
                    } else if let Some(m) = param.strip_prefix("max_fails=") {
                        failures = Some(m.parse().unwrap_or(1));
                    } else if let Some(t) = param.strip_prefix("fail_timeout=") {
                        fail_timeout = time(t);
                    } else if *param == "backup" {
                        backend["backup"] = json!(true);
                    } else if *param == "down" {
                        down = true;
                    } else if let Some(m) = param.strip_prefix("max_conns=") {
                        max_conns = m.parse().ok();
                        notes.push("`max_conns` → the service's `max_connections_per_backend` (requests over it are refused instead of queued)".to_owned());
                    } else if *param == "resolve" {
                        notes.push("ReverseDock resolves backend names itself".to_owned());
                    } else {
                        notes.push(format!("`{param}` is not carried over"));
                    }
                }
                if down {
                    run.exact(e, "`down`: left out, as NGINX never uses it");
                    continue;
                }
                backends.push(backend);
                if notes.is_empty() {
                    run.exact(e, "→ a backend (weight and backup kept)");
                } else {
                    run.approx(e, format!("→ a backend; {}", notes.join("; ")));
                }
            }
            "least_conn" => {
                policy = Some(("least_conn", None));
                run.exact(e, "→ `least_conn`");
            }
            "ip_hash" => {
                policy = Some(("ip_hash", None));
                run.approx(e, "→ `ip_hash`: NGINX hashes the first three octets of an IPv4 address with its own function; clients keep a backend, but not the same one as before");
            }
            "random" => {
                if args.first() == Some(&"two") {
                    policy = Some(("p2c", None));
                    if args.get(1).is_some_and(|m| *m != "least_conn") {
                        run.approx(e, "→ `p2c` (the less loaded of two random backends, by requests in flight)");
                    } else {
                        run.exact(e, "→ `p2c` (the less loaded of two random backends)");
                    }
                } else {
                    policy = Some(("random", None));
                    run.exact(e, "→ `random`");
                }
            }
            "hash" => {
                let key = args.first().copied().unwrap_or("");
                if let Some(header) = key.strip_prefix("$http_") {
                    policy = Some(("header_hash", Some(header.replace('_', "-"))));
                    run.approx(e, "→ `header_hash` on the header: clients keep a backend, but not the same one as before");
                } else if let Some(cookie) = key.strip_prefix("$cookie_") {
                    policy = Some(("cookie_hash", Some(cookie.to_owned())));
                    run.approx(e, "→ `cookie_hash` on the cookie: clients keep a backend, but not the same one as before");
                } else if key == "$remote_addr" || key == "$binary_remote_addr" {
                    policy = Some(("ip_hash", None));
                    run.approx(
                        e,
                        "→ `ip_hash`: clients keep a backend, but not the same one as before",
                    );
                } else {
                    run.manual(e, format!("hashing on `{key}` has no equivalent (only `$http_*`, `$cookie_*` and the client address)"), "choose `header_hash`, `cookie_hash` or `ip_hash`");
                }
            }
            "keepalive" | "keepalive_timeout" | "keepalive_requests" | "keepalive_time" => {
                run.exact(e, "connections to backends are pooled by default");
            }
            "zone" => run.exact(e, "shared state across workers: ReverseDock is one process"),
            "least_time" => {
                policy = Some(("peak_ewma", None));
                run.approx(e, "→ `peak_ewma` (latency-aware, beta)");
            }
            name if REFUSED_PREFIX.iter().any(|(p, ..)| name.starts_with(p)) => {
                if let Some((_, why, hint, _)) =
                    REFUSED_PREFIX.iter().find(|(p, ..)| name.starts_with(p))
                {
                    refuse(run, e, why, hint);
                }
            }
            other => {
                run.dropped(e, format!("`{other}` in an upstream has no equivalent"));
            }
        }
    }
    let mut service = Map::new();
    let count = backends.len();
    service.insert("backends".to_owned(), Value::Array(backends));
    if let Some((p, key)) = policy {
        let mut lb = json!({ "policy": p });
        if let Some(key) = key {
            lb["hash_on"] = json!(key);
        }
        service.insert("load_balancer".to_owned(), lb);
    }
    if let Some(n) = max_conns {
        service.insert("max_connections_per_backend".to_owned(), json!(n));
    }
    // Passive checks: one failure within 10s marks a server unavailable for 10s by default;
    // "max_fails=0 disables the accounting"; a group of one server is never marked unavailable.
    if count > 1 && failures != Some(0) {
        let window = fail_timeout.unwrap_or_else(|| "10s".to_owned());
        service.insert("health".to_owned(), json!({ "passive": { "failures": failures.unwrap_or(1), "window": window, "ejection": window } }));
        service.insert(
            "retries".to_owned(),
            json!({ "attempts": count - 1, "on": ["connect", "timeout"] }),
        );
        run.defaults_changed.insert("nginx.default.passive_health", "NGINX marks an upstream server unavailable after one failure for 10s by default (`max_fails=1 fail_timeout=10s`): written as `health.passive` on services with several backends; ReverseDock doubles the ejection for repeated failures and never ejects more than half the pool".to_owned());
        run.defaults_changed.insert("nginx.default.next_upstream", "NGINX passes a request to the next upstream server after a connection error or timeout (`proxy_next_upstream error timeout`): written as `retries` on services with several backends".to_owned());
    }
    Upstream { service }
}

/// Writes the routes of one server, one per listener kind (plain HTTP routes with `tls: off`).
fn write_routes(run: &mut Run<'_>, srv: &Server<'_, '_, '_>, routes: Vec<RouteOut>) {
    let kinds: Vec<(bool, &Vec<String>)> = [(false, &srv.plain), (true, &srv.secure)]
        .into_iter()
        .filter(|(_, l)| !l.is_empty())
        .collect();
    let both = kinds.len() == 2;
    for route in routes {
        for (secure, listeners) in &kinds {
            let mut label: Vec<&str> = route.label.iter().map(String::as_str).collect();
            if both && !secure {
                label.push("http");
            }
            let name = run.route_names.unique(&label);
            let mut out = Map::new();
            out.insert("match".to_owned(), json!(route.rule));
            out.insert("listeners".to_owned(), json!(listeners));
            out.insert("priority".to_owned(), json!(route.priority));
            let mut middlewares = Vec::new();
            for (kind, value) in &route.middlewares {
                middlewares.push(run.middlewares.add(&[&srv.label, kind], value.clone()));
            }
            if !middlewares.is_empty() {
                out.insert("middlewares".to_owned(), json!(middlewares));
            }
            if let Some((parts, value)) = &route.service {
                let parts: Vec<&str> = parts.split('|').collect();
                let service = run.services.add(&parts, value.clone());
                out.insert("service".to_owned(), json!(service));
            }
            if let Some(size) = &route.max_body {
                out.insert("max_body".to_owned(), json!(size));
            }
            if !route.timeouts.is_empty() {
                out.insert("timeouts".to_owned(), Value::Object(route.timeouts.clone()));
            }
            if *secure {
                let certs: Vec<&Directive> =
                    list(&[srv.http.block, srv.block], &["ssl_certificate"]);
                match certs.first().map(|c| c.arg(0)) {
                    Some(path) if !path.contains('$') => {
                        let cert = output::slug(
                            path.rsplit('/')
                                .nth(usize::from(
                                    path.ends_with("fullchain.pem") || path.ends_with("cert.pem"),
                                ))
                                .unwrap_or("certificate"),
                        );
                        let cert = if cert.is_empty() {
                            "certificate".to_owned()
                        } else {
                            cert
                        };
                        out.insert("tls".to_owned(), json!({ "certificate": cert }));
                    }
                    _ => {}
                }
            } else {
                out.insert("tls".to_owned(), json!("off"));
            }
            let mut blocked = srv.blocked.clone();
            blocked.extend(route.blocked.iter().cloned());
            blocked.dedup();
            if !blocked.is_empty() {
                out.insert("enabled".to_owned(), json!(false));
                run.disabled.push((name.clone(), blocked.join("; ")));
            }
            run.routes.insert(name, Value::Object(out));
        }
    }
}
