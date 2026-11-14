//! Handlers and matchers: one Caddy module at a time.
//!
//! Field names and defaults are those of the JSON reference for Caddy v2.11.9
//! (<https://caddyserver.com/docs/json/apps/http/servers/routes/handle/> and
//! `…/routes/match/`, read 2026-11-14); the shapes the Caddyfile adapter writes (for
//! `forward_auth`, `handle_path`, `redir`, `root`, `try_files`, `basic_auth`) are those of its
//! tests at the `v2.11.9` tag (`caddytest/integration/caddyfile_adapt/`).

use serde_json::{Map, Value, json};

use super::routes::{Atom, Set, group_or};
use super::{Notes, Run};
use crate::output::{escape, literal_replacement};

/// A handler that does not answer: it changes the request or the response and passes it on.
#[derive(Debug, Clone)]
pub(crate) enum Step {
    /// A middleware object.
    Middleware { kind: String, value: Value },
    /// `request_body.max_size` → the route's `max_body`.
    MaxBody(String),
    /// `vars.root` → the root of a later `file_server`.
    Root(String),
    /// The single-page-app `try_files` idiom → the `fallback` of a later `file_server`.
    Spa(String),
    /// `file_server` with `pass_thru`: a `static` middleware with `pass_through`.
    FileServer(Map<String, Value>),
    /// A handler that could not be translated: the route is written disabled.
    Blocked(String),
}

/// A handler that answers.
#[derive(Debug, Clone)]
pub(crate) enum Responder {
    /// A service (`reverse_proxy`, or `static_response` with a status only).
    Service { kind: String, value: Value },
    /// A `redirect` middleware (`static_response` with `Location`).
    Redirect(Value),
    /// `file_server` → a `static` middleware.
    FileServer(Map<String, Value>),
    /// Could not be translated: the route is written disabled with a placeholder service.
    Blocked { reason: String, service: Value },
}

impl Responder {
    pub(crate) fn is_blocked(&self) -> bool {
        matches!(self, Self::Blocked { .. })
    }
}

/// What a handler turns into.
#[derive(Debug, Clone)]
pub(crate) enum Handled {
    Steps(Vec<Step>),
    Respond(Vec<Step>, Responder),
    Subroute(Vec<Value>),
    Invoke(String),
    Nothing,
}

/// A Caddy duration (nanoseconds, or a Go duration string such as `1m30s`; Caddy also reads
/// `d` for days) as a ReverseDock duration, to the millisecond.
pub(crate) fn duration(value: &Value) -> Option<String> {
    let nanos: u128 = match value {
        Value::Number(n) => u128::from(n.as_u64()?),
        Value::String(s) => go_duration(s)?,
        _ => return None,
    };
    let millis = u64::try_from(nanos / 1_000_000).ok()?;
    if millis == 0 && nanos > 0 {
        return None;
    }
    Some(rdock_model::values::Duration::from_millis(millis).to_string())
}

fn go_duration(s: &str) -> Option<u128> {
    let mut total: f64 = 0.0;
    let mut rest = s.trim();
    if rest == "0" {
        return Some(0);
    }
    while !rest.is_empty() {
        let end = rest.find(|c: char| !(c.is_ascii_digit() || c == '.'))?;
        let number: f64 = rest[..end].parse().ok()?;
        rest = &rest[end..];
        let unit_end = rest
            .find(|c: char| c.is_ascii_digit() || c == '.')
            .unwrap_or(rest.len());
        let factor = match &rest[..unit_end] {
            "ns" => 1.0,
            "us" | "µs" => 1e3,
            "ms" => 1e6,
            "s" => 1e9,
            "m" => 60e9,
            "h" => 3600e9,
            "d" => 86400e9,
            _ => return None,
        };
        total += number * factor;
        rest = &rest[unit_end..];
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    Some(total as u128)
}

/// A Caddy `WeakString` status (`404`, `"404"`).
fn status(value: Option<&Value>) -> Result<u16, String> {
    match value {
        None => Ok(200),
        Some(Value::Number(n)) => n
            .as_u64()
            .and_then(|n| u16::try_from(n).ok())
            .ok_or_else(|| "not a status code".to_owned()),
        Some(Value::String(s)) if s.contains('{') => {
            Err(format!("the status `{s}` is a placeholder"))
        }
        Some(Value::String(s)) => s.parse().map_err(|_| format!("`{s}` is not a status code")),
        Some(_) => Err("not a status code".to_owned()),
    }
}

fn strings(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// Whether a value holds a Caddy placeholder (`{…}` that is not an escaped brace).
pub(crate) fn has_placeholder(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes
        .iter()
        .enumerate()
        .any(|(i, b)| *b == b'{' && (i == 0 || bytes[i - 1] != b'\\') && text[i..].contains('}'))
}

/// Translates one handler and accounts for it.
#[allow(clippy::too_many_lines)] // one arm per handler module
pub(crate) fn handler(run: &mut Run<'_>, server: &str, h: &Value, pointer: &str) -> Handled {
    let kind = h.get("handler").and_then(Value::as_str).unwrap_or("");
    let mut notes = Notes::default();
    let mut target: Option<String> = None;
    let handled = match kind {
        "subroute" => {
            notes.exact("its routes are flattened into the enclosing routes, in order");
            if h.get("errors").is_some() {
                notes.manual("its error routes (`handle_errors`) are not migrated");
                notes.hint("for custom error pages, use the `errors` middleware");
            }
            Handled::Subroute(
                h.get("routes")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default(),
            )
        }
        "invoke" => {
            if let Some(name) = h.get("name").and_then(Value::as_str) {
                notes.exact(format!(
                    "the named route `{name}` is inlined where it is invoked"
                ));
                Handled::Invoke(name.to_owned())
            } else {
                notes.manual("`invoke` without a name");
                Handled::Steps(vec![Step::Blocked("an `invoke` without a name".to_owned())])
            }
        }
        "vars" => vars(h, &mut notes),
        "headers" => {
            let (value, blocked) = header_ops(h, &mut notes, false);
            let mut steps = Vec::new();
            if let Some(value) = value {
                steps.push(Step::Middleware {
                    kind: "headers".to_owned(),
                    value,
                });
            }
            if let Some(why) = blocked {
                steps.push(Step::Blocked(why));
            }
            Handled::Steps(steps)
        }
        "rewrite" => rewrite(h, &mut notes),
        "encode" => encode(h, &mut notes),
        "authentication" => authentication(h, &mut notes),
        "request_body" => {
            if let Some(size) = h.get("max_size").and_then(Value::as_u64) {
                notes.exact(format!(
                    "written as the route's `max_body: {size}` (413 when exceeded, as in Caddy)"
                ));
                for key in ["read_timeout", "write_timeout"] {
                    if h.get(key).is_some() {
                        notes.approx(format!("`{key}` (experimental in Caddy) has no per-route equivalent; the listener's timeouts apply"));
                    }
                }
                Handled::Steps(vec![Step::MaxBody(format!("{size}B"))])
            } else {
                notes.exact("no `max_size`: nothing to migrate");
                Handled::Nothing
            }
        }
        "static_response" => static_response(h, &mut notes),
        "error" => match status(h.get("status_code")) {
            Ok(code) => {
                let code = if h.get("status_code").is_none() {
                    500
                } else {
                    code
                };
                notes.approx(format!("answered with status {code} (`respond`); Caddy hands the error to `handle_errors` when there is one, and writes its message only there"));
                Handled::Respond(
                    Vec::new(),
                    Responder::Service {
                        kind: format!("respond-{code}"),
                        value: json!({ "respond": { "status": code } }),
                    },
                )
            }
            Err(why) => {
                notes.manual(why.clone());
                Handled::Respond(
                    Vec::new(),
                    Responder::Blocked {
                        reason: why,
                        service: json!({ "respond": { "status": 500 } }),
                    },
                )
            }
        },
        "file_server" => file_server(h, &mut notes),
        "reverse_proxy" => {
            let handled = super::proxy::reverse_proxy(run, h, &mut notes);
            target = Some("services".to_owned());
            handled
        }
        "templates" => blocked_step(
            &mut notes,
            "`templates` (server-side templates) has no equivalent",
            "render the pages in the application, or keep Caddy for them",
        ),
        "map" => {
            notes.dropped("`map` has no equivalent: it only sets placeholders, which are reported where they are used");
            Handled::Nothing
        }
        "push" => {
            notes.dropped("HTTP/2 server push has no equivalent (browsers removed support)");
            Handled::Nothing
        }
        "tracing" => {
            notes.dropped("per-route tracing: ReverseDock traces every request when `observability.tracing` is set");
            notes.hint("set `observability.tracing.otlp`");
            Handled::Nothing
        }
        "log_append" | "log_skip" | "log_name" => {
            notes.dropped(format!("`{kind}` (access log fields) has no equivalent"));
            Handled::Nothing
        }
        "metrics" => {
            notes.manual("a metrics endpoint: ReverseDock serves its metrics on the admin listener (`/metrics`), not on a route");
            notes.hint("set `admin.enabled: true` and scrape the admin listener");
            Handled::Respond(
                Vec::new(),
                Responder::Blocked {
                    reason: "it served Caddy's metrics".to_owned(),
                    service: json!({ "respond": { "status": 404 } }),
                },
            )
        }
        "acme_server" => {
            notes.manual("`acme_server` (an ACME CA) has no equivalent");
            Handled::Respond(
                Vec::new(),
                Responder::Blocked {
                    reason: "it ran Caddy's ACME server".to_owned(),
                    service: json!({ "respond": { "status": 404 } }),
                },
            )
        }
        "intercept" | "copy_response" | "copy_response_headers" => blocked_step(
            &mut notes,
            &format!("`{kind}` (response interception) has no equivalent"),
            "for custom error pages, use the `errors` middleware",
        ),
        "" => blocked_step(&mut notes, "a handler without a `handler` name", ""),
        other => blocked_step(
            &mut notes,
            &format!(
                "handler `{other}` is not a standard Caddy module (a plugin) and has no equivalent"
            ),
            "replace it by hand",
        ),
    };
    let finding = notes.finding("caddy.handler", target.as_deref());
    run.account(Some(server), pointer, finding);
    handled
}

fn blocked_step(notes: &mut Notes, why: &str, hint: &str) -> Handled {
    notes.manual(why);
    if !hint.is_empty() {
        notes.hint(hint);
    }
    Handled::Steps(vec![Step::Blocked(why.to_owned())])
}

/// `vars`: `root` (the `root` directive) feeds `file_server`; anything else only feeds
/// placeholders.
fn vars(h: &Value, notes: &mut Notes) -> Handled {
    let mut steps = Vec::new();
    let mut others = Vec::new();
    if let Some(map) = h.as_object() {
        for (key, value) in map {
            match (key.as_str(), value) {
                ("handler", _) => {}
                ("root", Value::String(root)) => steps.push(Step::Root(root.clone())),
                _ => others.push(key.clone()),
            }
        }
    }
    if !steps.is_empty() {
        notes.exact("`root`: the directory of the `file_server` that follows");
    }
    if !others.is_empty() {
        notes.dropped(format!("variables {} have no equivalent: they only feed placeholders, which are reported where they are used", others.iter().map(|o| format!("`{o}`")).collect::<Vec<_>>().join(", ")));
    }
    if steps.is_empty() && others.is_empty() {
        notes.exact("no variables: nothing to migrate");
    }
    Handled::Steps(steps)
}

/// A header value with Caddy placeholders: `Ok(None)` when ReverseDock already sends the same
/// thing (forwarding headers), `Ok(Some(text))` for a literal, `Err` otherwise.
fn header_value(field: &str, values: &[String]) -> Result<Option<String>, String> {
    let joined = values.join(", ");
    if !has_placeholder(&joined) {
        return Ok(Some(joined));
    }
    let builtin = matches!(
        (field.to_ascii_lowercase().as_str(), joined.as_str()),
        (
            "x-real-ip" | "x-forwarded-for",
            "{http.request.remote.host}" | "{http.vars.client_ip}"
        ) | ("x-forwarded-proto", "{http.request.scheme}")
            | (
                "x-forwarded-host",
                "{http.request.host}" | "{http.request.hostport}"
            )
    );
    if builtin {
        Ok(None)
    } else {
        Err(format!(
            "`{field}: {joined}` uses a placeholder, which ReverseDock does not evaluate in header values"
        ))
    }
}

/// `headers` operations (also `reverse_proxy.headers`). Returns the middleware, and why the route
/// must be disabled when an operation has no equivalent. In `proxy`, `Host` decides the
/// service's `pass_host_header` instead (handled by the caller).
pub(crate) fn header_ops(
    h: &Value,
    notes: &mut Notes,
    proxy: bool,
) -> (Option<Value>, Option<String>) {
    let mut out = json!({ "type": "headers" });
    let mut blocked = None;
    let mut any = false;
    for side in ["request", "response"] {
        let Some(ops) = h.get(side) else { continue };
        let mut rules = Map::new();
        for (op, field) in [("set", "set"), ("add", "add")] {
            if let Some(Value::Object(map)) = ops.get(op) {
                let mut written = Map::new();
                for (name, values) in map {
                    if proxy && side == "request" && name.eq_ignore_ascii_case("host") {
                        continue;
                    }
                    let values = strings(Some(values));
                    match header_value(name, &values) {
                        Ok(Some(text)) => {
                            if values.len() > 1 {
                                notes.approx(format!("`{name}` has several values: written as one comma-separated value"));
                            }
                            written.insert(name.clone(), json!(text));
                        }
                        Ok(None) => notes.exact(format!("`{name}` is a forwarding header ReverseDock writes itself (from trusted proxies only)")),
                        Err(why) => {
                            notes.manual(why.clone());
                            blocked = Some(why);
                        }
                    }
                }
                if !written.is_empty() {
                    rules.insert(field.to_owned(), Value::Object(written));
                }
            }
        }
        let deletes = strings(ops.get("delete"));
        let mut remove = Vec::new();
        for name in deletes {
            if name.contains('*') {
                let why = format!("deleting `{name}` (a wildcard) has no equivalent");
                notes.manual(why.clone());
                blocked = Some(why);
            } else {
                remove.push(json!(name));
            }
        }
        if !remove.is_empty() {
            rules.insert("remove".to_owned(), Value::Array(remove));
        }
        if ops.get("replace").is_some() {
            let why = format!("a {side} header replacement (search and replace) has no equivalent");
            notes.manual(why.clone());
            blocked = Some(why);
        }
        if side == "response" {
            if ops.get("require").is_some() {
                let why = "a response header operation that depends on the status or other headers (`require`, Caddyfile `?` or `match`) has no equivalent".to_owned();
                notes.manual(why.clone());
                blocked = Some(why);
            } else if !proxy
                && ops.get("set").is_some()
                && ops.get("deferred").and_then(Value::as_bool) != Some(true)
            {
                notes.approx("a response header set without deferral: Caddy sets it before the next handler, so a header the backend also sends keeps both values; ReverseDock replaces the backend's value");
            }
        }
        if !rules.is_empty() {
            any = true;
            out[side] = Value::Object(rules);
        }
    }
    if any {
        notes.exact("header operations → a `headers` middleware");
    } else if blocked.is_none() {
        notes.exact("no header operation left to migrate");
    }
    (any.then_some(out), blocked)
}

/// `rewrite`, in Caddy's order: method, uri, `strip_path_prefix`, `strip_path_suffix`,
/// `uri_substring`, `path_regexp`, query (`modules/caddyhttp/rewrite/rewrite.go` at v2.11.9).
#[allow(clippy::too_many_lines)] // one pass, in reading order
fn rewrite(h: &Value, notes: &mut Notes) -> Handled {
    let mut steps = Vec::new();
    let block = |notes: &mut Notes, why: String, steps: &mut Vec<Step>| {
        notes.manual(why.clone());
        steps.push(Step::Blocked(why));
    };
    if h.get("method").is_some() {
        block(
            notes,
            "changing the request method has no equivalent".to_owned(),
            &mut steps,
        );
    }
    if let Some(uri) = h.get("uri").and_then(Value::as_str) {
        if uri == "{http.request.uri}" {
            notes.exact("a rewrite to the request's own URI changes nothing");
        } else if let Some(prefix) = uri
            .strip_suffix("{http.request.uri.path}")
            .filter(|p| !has_placeholder(p) && p.starts_with('/') && !p.contains('?'))
        {
            steps.push(Step::Middleware {
                kind: "add-prefix".to_owned(),
                value: json!({ "type": "add_prefix", "prefix": prefix }),
            });
            notes.exact(format!("`{uri}` → `add_prefix: {prefix}`"));
        } else if !has_placeholder(uri) && uri.starts_with('/') && !uri.contains('?') {
            steps.push(Step::Middleware {
                kind: "replace-path".to_owned(),
                value: json!({ "type": "replace_path", "path": uri }),
            });
            notes.exact(format!(
                "`{uri}` → `replace_path` (the query string is kept, as in Caddy)"
            ));
        } else {
            block(
                notes,
                format!("a rewrite to `{uri}` (placeholders or a query string) has no equivalent"),
                &mut steps,
            );
        }
    }
    if let Some(prefix) = h.get("strip_path_prefix").and_then(Value::as_str) {
        if has_placeholder(prefix) {
            block(
                notes,
                format!("stripping `{prefix}` (a placeholder) has no equivalent"),
                &mut steps,
            );
        } else {
            let prefix = if prefix.starts_with('/') {
                prefix.to_owned()
            } else {
                format!("/{prefix}")
            };
            steps.push(strip_prefix_step(&prefix));
            notes.exact(format!(
                "strips `{prefix}` case-insensitively, as Caddy does"
            ));
        }
    }
    if let Some(suffix) = h.get("strip_path_suffix").and_then(Value::as_str) {
        if has_placeholder(suffix) {
            block(
                notes,
                format!("stripping `{suffix}` (a placeholder) has no equivalent"),
                &mut steps,
            );
        } else {
            steps.push(Step::Middleware {
                kind: "strip-suffix".to_owned(),
                value: json!({ "type": "rewrite", "regex": format!("(?i)^(.*){}$", escape(suffix)), "replacement": "$1" }),
            });
            notes.exact(format!(
                "strips the suffix `{suffix}` case-insensitively with a `rewrite`"
            ));
        }
    }
    if h.get("uri_substring").is_some() {
        block(
            notes,
            "substring replacement in the URI has no equivalent".to_owned(),
            &mut steps,
        );
    }
    if let Some(list) = h.get("path_regexp").and_then(Value::as_array) {
        for rep in list {
            let find = rep.get("find").and_then(Value::as_str).unwrap_or("");
            let replace = rep.get("replace").and_then(Value::as_str).unwrap_or("");
            if has_placeholder(replace) || regex::Regex::new(find).is_err() {
                block(
                    notes,
                    format!(
                        "the path rewrite `{find}` → `{replace}` (a placeholder, or a regular expression ReverseDock's engine does not read) has no equivalent"
                    ),
                    &mut steps,
                );
            } else {
                steps.push(Step::Middleware {
                    kind: "rewrite".to_owned(),
                    value: json!({ "type": "rewrite", "regex": find, "replacement": replace }),
                });
                notes.exact(format!(
                    "`{find}` → `{replace}` as a `rewrite` (every match replaced, as in Caddy)"
                ));
            }
        }
    }
    if h.get("query").is_some() {
        block(
            notes,
            "query string operations have no equivalent".to_owned(),
            &mut steps,
        );
    }
    if steps.is_empty() && notes.level() == crate::report::Level::Exact && notes.parts_empty() {
        notes.exact("no rewrite operation");
    }
    Handled::Steps(steps)
}

/// Removes `prefix` case-insensitively (Caddy's `trimPathPrefix` compares with `EqualFold`).
pub(crate) fn strip_prefix_step(prefix: &str) -> Step {
    if prefix.chars().any(|c| c.is_ascii_alphabetic()) {
        Step::Middleware {
            kind: "strip-prefix".to_owned(),
            value: json!({ "type": "rewrite", "regex": format!("(?i)^{}", escape(prefix)), "replacement": "" }),
        }
    } else {
        Step::Middleware {
            kind: "strip-prefix".to_owned(),
            value: json!({ "type": "strip_prefix", "prefixes": [prefix] }),
        }
    }
}

/// `encode` → `compress`.
fn encode(h: &Value, notes: &mut Notes) -> Handled {
    let encodings: Vec<String> = h
        .get("encodings")
        .and_then(Value::as_object)
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    let prefer = strings(h.get("prefer"));
    let mut order: Vec<String> = prefer
        .into_iter()
        .filter(|p| encodings.contains(p))
        .collect();
    for e in &encodings {
        if !order.contains(e) {
            order.push(e.clone());
        }
    }
    let mut algorithms = Vec::new();
    for e in &order {
        match e.as_str() {
            "gzip" | "zstd" => algorithms.push(json!(e)),
            "br" => algorithms.push(json!("br")),
            other => notes.approx(format!(
                "encoding `{other}` has no equivalent and is left out"
            )),
        }
    }
    let mut value = json!({ "type": "compress" });
    if !algorithms.is_empty() {
        value["algorithms"] = Value::Array(algorithms);
    }
    match h.get("minimum_length").and_then(Value::as_u64) {
        Some(n) => value["min_size"] = json!(format!("{n}B")),
        None => {
            // Caddy's default minimum length is 512 bytes (`encode.go`, `defaultMinLength`).
            value["min_size"] = json!("512B");
        }
    }
    if let Some(m) = h.get("match") {
        let types = strings(m.pointer("/headers/Content-Type"));
        if !types.is_empty() {
            value["content_types"] = json!(
                types
                    .iter()
                    .map(|t| t.trim_end_matches('*').to_owned())
                    .collect::<Vec<_>>()
            );
        }
        if m.get("status_code").is_some() {
            notes.approx("the status codes that are compressed are not configurable here");
        }
    }
    notes.approx("written as `compress`: Caddy's default content types and its level settings differ from ReverseDock's (content types are matched by prefix)");
    Handled::Steps(vec![Step::Middleware {
        kind: "compress".to_owned(),
        value,
    }])
}

/// `authentication` with `http_basic` → `basic_auth` (hashes kept; Caddy stores bcrypt or
/// argon2id hashes, which ReverseDock reads).
fn authentication(h: &Value, notes: &mut Notes) -> Handled {
    let providers = h
        .get("providers")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let mut steps = Vec::new();
    for (name, provider) in &providers {
        if name != "http_basic" {
            let why = format!("authentication provider `{name}` has no equivalent");
            notes.manual(why.clone());
            steps.push(Step::Blocked(why));
            continue;
        }
        let algorithm = provider
            .pointer("/hash/algorithm")
            .and_then(Value::as_str)
            .unwrap_or("bcrypt");
        if algorithm != "bcrypt" && algorithm != "argon2id" {
            let why = format!("password hash algorithm `{algorithm}` has no equivalent");
            notes.manual(why.clone());
            steps.push(Step::Blocked(why));
            continue;
        }
        let mut users = Vec::new();
        let mut bad = false;
        for account in provider
            .get("accounts")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
        {
            let user = account
                .get("username")
                .and_then(Value::as_str)
                .unwrap_or("");
            let password = account
                .get("password")
                .and_then(Value::as_str)
                .unwrap_or("");
            let hash = if password.starts_with('$') {
                Some(password.to_owned())
            } else {
                base64_text(password).filter(|h| h.starts_with('$'))
            };
            match hash {
                Some(hash) if !user.is_empty() && !user.contains(':') => {
                    users.push(json!(format!("{user}:{hash}")));
                }
                _ => bad = true,
            }
        }
        if bad || users.is_empty() {
            let why = "an account whose password is not a bcrypt or argon2id hash".to_owned();
            notes.manual(why.clone());
            steps.push(Step::Blocked(why));
            continue;
        }
        // Caddy's default realm is `restricted`.
        let realm = provider
            .get("realm")
            .and_then(Value::as_str)
            .unwrap_or("restricted");
        notes.exact("`http_basic` → `basic_auth`: the password hashes are kept as they are (never plaintext)");
        if provider.get("hash_cache").is_some() {
            notes.exact("the hash cache is ReverseDock's behaviour too");
        }
        steps.push(Step::Middleware {
            kind: "auth".to_owned(),
            value: json!({ "type": "basic_auth", "users": users, "realm": realm }),
        });
    }
    if providers.is_empty() {
        let why = "`authentication` without providers refuses every request in Caddy".to_owned();
        notes.manual(why.clone());
        steps.push(Step::Blocked(why));
    }
    Handled::Steps(steps)
}

/// Standard base64 (Caddy also reads base64-encoded hashes).
fn base64_text(text: &str) -> Option<String> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut bits: u32 = 0;
    let mut count = 0;
    let mut out = Vec::new();
    for c in text.trim_end_matches('=').bytes() {
        let v = u32::try_from(ALPHABET.iter().position(|a| *a == c)?).ok()?;
        bits = (bits << 6) | v;
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push(u8::try_from((bits >> count) & 0xff).ok()?);
        }
    }
    String::from_utf8(out).ok()
}

/// `static_response`: a redirect (`Location`), a status, or a body (no equivalent).
fn static_response(h: &Value, notes: &mut Notes) -> Handled {
    let code = match status(h.get("status_code")) {
        Ok(code) => code,
        Err(why) => {
            notes.manual(why.clone());
            return Handled::Respond(
                Vec::new(),
                Responder::Blocked {
                    reason: why,
                    service: json!({ "respond": { "status": 200 } }),
                },
            );
        }
    };
    if h.get("abort").and_then(Value::as_bool) == Some(true) {
        let why = "`abort` (close the connection without an answer) has no equivalent".to_owned();
        notes.manual(why.clone());
        return Handled::Respond(
            Vec::new(),
            Responder::Blocked {
                reason: why,
                service: json!({ "respond": { "status": 400 } }),
            },
        );
    }
    let headers = h
        .get("headers")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let location = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("location"))
        .and_then(|(_, v)| v.as_array())
        .and_then(|a| a.first())
        .and_then(Value::as_str);
    let others: Vec<&String> = headers
        .keys()
        .filter(|k| !k.eq_ignore_ascii_case("location"))
        .collect();
    let body = h.get("body").and_then(Value::as_str).unwrap_or("");
    if h.get("close").and_then(Value::as_bool) == Some(true) {
        notes.approx("Caddy closes the connection after the answer; ReverseDock keeps it open");
    }
    if let Some(location) = location
        && (300..400).contains(&code)
    {
        return match redirect(location, code) {
            Ok((value, note)) => {
                notes.exact(note);
                if !body.is_empty() || !others.is_empty() {
                    notes.approx("the redirect's body and extra headers are not written");
                }
                Handled::Respond(Vec::new(), Responder::Redirect(value))
            }
            Err(why) => {
                notes.manual(why.clone());
                Handled::Respond(
                    Vec::new(),
                    Responder::Blocked {
                        reason: why,
                        service: json!({ "respond": { "status": code } }),
                    },
                )
            }
        };
    }
    if !body.is_empty() || !others.is_empty() || location.is_some() {
        let why = format!(
            "a response with {} has no equivalent (a fixed-status service answers without a body or headers)",
            if body.is_empty() { "headers" } else { "a body" }
        );
        notes.manual(why.clone());
        notes.hint("serve the content from a backend or a `static` directory");
        return Handled::Respond(
            Vec::new(),
            Responder::Blocked {
                reason: why,
                service: json!({ "respond": { "status": code } }),
            },
        );
    }
    notes.exact(format!("a fixed answer with status {code} (`respond`)"));
    Handled::Respond(
        Vec::new(),
        Responder::Service {
            kind: format!("respond-{code}"),
            value: json!({ "respond": { "status": code } }),
        },
    )
}

/// A `Location` with placeholders as a `redirect` middleware (the `redir` directive adapts to a
/// `static_response` with `Location`, `redir` default status 302, per
/// `caddyconfig/httpcaddyfile/builtins.go` at v2.11.9).
fn redirect(location: &str, code: u16) -> Result<(Value, String), String> {
    let status = json!(code);
    if let Some(rest) = location.strip_suffix("{http.request.uri}") {
        // `https://example.com{uri}`, `https://{host}{uri}`.
        for scheme in ["https", "http"] {
            if let Some(host) = rest.strip_prefix(&format!("{scheme}://")) {
                if host == "{http.request.host}" {
                    return Ok((
                        json!({ "type": "redirect", "scheme": scheme, "always": true, "status": status }),
                        format!("redirect to `{scheme}://` on the same host, path and query kept"),
                    ));
                }
                if !has_placeholder(host) && !host.contains('/') && !host.is_empty() {
                    let (name, port) = match host.rsplit_once(':') {
                        Some((n, p)) if p.parse::<u16>().is_ok() => (n, p.parse::<u16>().ok()),
                        _ => (host, None),
                    };
                    let mut value = json!({ "type": "redirect", "scheme": scheme, "hostname": name, "status": status });
                    if let Some(port) = port {
                        value["port"] = json!(port);
                    }
                    return Ok((
                        value,
                        format!("redirect to `{scheme}://{host}` with the path and query kept"),
                    ));
                }
            }
        }
    }
    if has_placeholder(location) {
        return Err(format!(
            "a redirect to `{location}` uses placeholders that have no equivalent"
        ));
    }
    // A fixed target, absolute or relative: replace the whole URL (no query added, as Caddy).
    let replacement = if location.starts_with('/') {
        format!("${{s}}://${{h}}{}", literal_replacement(location))
    } else if location.starts_with("http://") || location.starts_with("https://") {
        literal_replacement(location)
    } else {
        return Err(format!(
            "a redirect to the relative target `{location}` has no equivalent"
        ));
    };
    Ok((
        json!({ "type": "redirect", "regex": "^(?P<s>[a-z]+)://(?P<h>[^/]+)", "replacement": replacement, "status": status }),
        format!("redirect to `{location}`"),
    ))
}

/// `file_server` → `static` (the root comes from `root`/`vars` when not set here).
fn file_server(h: &Value, notes: &mut Notes) -> Handled {
    let mut config = Map::new();
    if let Some(root) = h.get("root").and_then(Value::as_str) {
        config.insert("root".to_owned(), json!(root));
    }
    let index = strings(h.get("index_names"));
    // Caddy's default index names are index.html and index.txt.
    config.insert(
        "index".to_owned(),
        if index.is_empty() {
            json!(["index.html", "index.txt"])
        } else {
            json!(index)
        },
    );
    if h.get("browse").is_some() {
        config.insert("listing".to_owned(), json!(true));
        notes.approx("directory listings (`browse`) are on; the page and its template differ");
    }
    if let Some(Value::Object(pre)) = h.get("precompressed") {
        let order = strings(h.get("precompressed_order"));
        let mut names: Vec<String> = if order.is_empty() {
            pre.keys().cloned().collect()
        } else {
            order
        };
        names.retain(|n| ["gzip", "br", "zstd"].contains(&n.as_str()));
        config.insert("precompressed".to_owned(), json!(names));
        notes.exact("precompressed sidecar files are served");
    } else {
        // Caddy serves no precompressed files unless asked; ReverseDock does by default.
        config.insert("precompressed".to_owned(), json!([]));
    }
    if h.get("canonical_uris").and_then(Value::as_bool) == Some(false) {
        config.insert("directory_redirect".to_owned(), json!(false));
    }
    let hide = strings(h.get("hide"));
    let hidden: Vec<&String> = hide.iter().filter(|p| !p.ends_with("Caddyfile")).collect();
    if !hidden.is_empty() {
        notes.approx(format!("hidden paths {} are not configurable: ReverseDock refuses files and directories whose name starts with `.`", hidden.iter().map(|h| format!("`{h}`")).collect::<Vec<_>>().join(", ")));
    }
    if h.get("status_code").is_some() {
        let why = "serving a file with another status code has no equivalent".to_owned();
        notes.manual(why.clone());
        return Handled::Steps(vec![Step::Blocked(why)]);
    }
    if h.get("fs").is_some() {
        let why = "a file system module other than the disk has no equivalent".to_owned();
        notes.manual(why.clone());
        return Handled::Steps(vec![Step::Blocked(why)]);
    }
    notes.exact("`file_server` → a `static` middleware");
    notes.approx("ReverseDock does not serve files and directories whose name starts with `.` (Caddy serves them unless hidden)");
    if h.get("pass_thru").and_then(Value::as_bool) == Some(true) {
        notes.exact(
            "`pass_thru`: requests that name no file continue to the next handler (`pass_through`)",
        );
        Handled::Steps(vec![Step::FileServer(config)])
    } else {
        Handled::Respond(Vec::new(), Responder::FileServer(config))
    }
}

/// The `static` middleware of a `file_server`, with the root from `vars` and an SPA fallback.
pub(crate) fn static_config(
    config: &Map<String, Value>,
    vars_root: Option<&str>,
    spa: Option<String>,
    pass_through: bool,
) -> Result<Value, String> {
    let mut value = Map::new();
    value.insert("type".to_owned(), json!("static"));
    let root = match config.get("root").and_then(Value::as_str) {
        None | Some("{http.vars.root}") => vars_root.map(str::to_owned),
        Some(root) => Some(root.to_owned()),
    };
    let Some(root) = root else {
        return Err("`file_server` without a root (Caddy serves the current directory)".to_owned());
    };
    if has_placeholder(&root) {
        return Err(format!("the file root `{root}` uses a placeholder"));
    }
    value.insert("root".to_owned(), json!(root));
    for (k, v) in config {
        if k != "root" {
            value.insert(k.clone(), v.clone());
        }
    }
    if let Some(fallback) = spa {
        value.insert("fallback".to_owned(), json!(fallback));
    }
    if pass_through {
        value.insert("pass_through".to_owned(), json!(true));
    }
    Ok(Value::Object(value))
}

/// One matcher set (its matchers are AND-ed), each matcher accounted as an item.
pub(crate) fn matcher_set(run: &mut Run<'_>, server: &str, set: &Value, pointer: &str) -> Set {
    let mut out = Set::default();
    let Some(map) = set.as_object() else {
        out.unsupported = true;
        run.account(
            Some(server),
            pointer,
            Notes::manual_finding("caddy.matcher", "a matcher set that is not an object"),
        );
        return out;
    };
    for (module, config) in map {
        let mp = format!("{pointer}/{module}");
        let mut notes = Notes::default();
        match matcher(run, server, module, config, &mp, &mut notes) {
            Some(atom) => out.atoms.push(atom),
            None => out.unsupported = true,
        }
        let finding = notes.finding("caddy.matcher", None);
        run.account(Some(server), &mp, finding);
    }
    out
}

/// One matcher module as a rule expression, or `None` (the set cannot be written).
#[allow(clippy::too_many_lines)] // one arm per matcher module
fn matcher(
    run: &mut Run<'_>,
    server: &str,
    module: &str,
    config: &Value,
    pointer: &str,
    notes: &mut Notes,
) -> Option<Atom> {
    match module {
        "host" => {
            let hosts: Vec<String> = strings(Some(config))
                .iter()
                .map(|h| h.to_ascii_lowercase())
                .collect();
            if hosts.is_empty() || hosts.iter().any(|h| has_placeholder(h) || h.contains('`')) {
                notes.manual("a host matcher with placeholders has no equivalent");
                return None;
            }
            notes.exact("`Host` (case-insensitive; `*` is one label in both)");
            Some(Atom::Hosts(hosts))
        }
        "path" => {
            let patterns = strings(Some(config));
            let mut rules = Vec::new();
            for p in &patterns {
                if let Some(rule) = path_rule(p) {
                    rules.push(rule);
                } else {
                    notes.manual(format!("path pattern `{p}` (escape sequences, placeholders or a character class) has no exact equivalent"));
                    return None;
                }
            }
            if rules.is_empty() {
                notes.manual("an empty path matcher");
                return None;
            }
            notes.exact("Caddy matches paths case-insensitively: written as a case-insensitive `PathRegexp` (or `Path`/`PathPrefix` when the pattern has no letters)");
            let label = patterns
                .first()
                .map(|p| p.trim_matches(|c| c == '*' || c == '/').to_owned())
                .filter(|l| !l.is_empty());
            let paths: Option<Vec<(String, bool)>> =
                patterns.iter().map(|p| path_literal(p)).collect();
            Some(Atom::Rule {
                text: group_or(&rules),
                label,
                uri: true,
                paths,
            })
        }
        "path_regexp" => {
            let pattern = config.get("pattern").and_then(Value::as_str).unwrap_or("");
            if regex::Regex::new(pattern).is_err() || pattern.contains('`') {
                notes.manual(format!(
                    "the regular expression `{pattern}` is not one ReverseDock's engine reads"
                ));
                return None;
            }
            notes.exact("`PathRegexp` (RE2 and ReverseDock's engine share the syntax used); captures used in placeholders are reported where they are used");
            Some(Atom::Rule {
                text: format!("PathRegexp(`{pattern}`)"),
                label: None,
                uri: true,
                paths: None,
            })
        }
        "method" => {
            let methods = strings(Some(config));
            if methods.is_empty() {
                notes.manual("an empty method matcher");
                return None;
            }
            notes.exact("`Method`");
            let rules: Vec<String> = methods
                .iter()
                .map(|m| format!("Method(`{}`)", m.to_ascii_uppercase()))
                .collect();
            Some(Atom::Rule {
                text: group_or(&rules),
                label: None,
                uri: false,
                paths: None,
            })
        }
        "header" => {
            let Some(fields) = config.as_object() else {
                notes.manual("a header matcher that is not an object");
                return None;
            };
            let mut all = Vec::new();
            for (field, values) in fields {
                if field.contains('`') {
                    notes.manual("a header name with a backtick");
                    return None;
                }
                match values {
                    Value::Null => all.push(format!("!HeaderRegexp(`{field}`, `.*`)")),
                    Value::Array(list) if list.is_empty() => {
                        all.push(format!("HeaderRegexp(`{field}`, `.*`)"));
                    }
                    Value::Array(list) => {
                        let mut any = Vec::new();
                        for v in list.iter().filter_map(Value::as_str) {
                            if has_placeholder(v) || v.contains('`') {
                                notes.manual(format!("header value `{v}` uses a placeholder"));
                                return None;
                            }
                            any.push(wildcard_rule("Header", "HeaderRegexp", field, v));
                        }
                        all.push(group_or(&any));
                    }
                    _ => {
                        notes.manual("a header matcher value that is not a list");
                        return None;
                    }
                }
            }
            notes.exact("`Header`/`HeaderRegexp` (`*` wildcards as regular expressions; a null list as a missing header)");
            Some(Atom::Rule {
                text: all.join(" && "),
                label: None,
                uri: false,
                paths: None,
            })
        }
        "header_regexp" => {
            let Some(fields) = config.as_object() else {
                notes.manual("a header_regexp matcher that is not an object");
                return None;
            };
            let mut all = Vec::new();
            for (field, re) in fields {
                let pattern = re.get("pattern").and_then(Value::as_str).unwrap_or("");
                if regex::Regex::new(pattern).is_err()
                    || pattern.contains('`')
                    || field.contains('`')
                {
                    notes.manual(format!(
                        "the regular expression `{pattern}` is not one ReverseDock's engine reads"
                    ));
                    return None;
                }
                all.push(format!("HeaderRegexp(`{field}`, `{pattern}`)"));
            }
            notes.exact("`HeaderRegexp`");
            Some(Atom::Rule {
                text: all.join(" && "),
                label: None,
                uri: false,
                paths: None,
            })
        }
        "query" => {
            let Some(keys) = config.as_object() else {
                notes.manual("a query matcher that is not an object");
                return None;
            };
            let mut all = Vec::new();
            for (key, values) in keys {
                let list = strings(Some(values));
                if list.is_empty() || key.contains('`') || has_placeholder(key) {
                    notes.manual(format!("the query matcher for `{key}` has no equivalent"));
                    return None;
                }
                let mut any = Vec::new();
                for v in &list {
                    if has_placeholder(v) || v.contains('`') {
                        notes.manual(format!("query value `{v}` uses a placeholder"));
                        return None;
                    }
                    any.push(wildcard_rule("Query", "QueryRegexp", key, v));
                }
                all.push(group_or(&any));
            }
            notes.exact("`Query`/`QueryRegexp`");
            Some(Atom::Rule {
                text: all.join(" && "),
                label: None,
                uri: true,
                paths: None,
            })
        }
        "client_ip" | "remote_ip" => {
            let ranges = strings(config.get("ranges"));
            if ranges.is_empty()
                || config.get("forwarded").is_some()
                || ranges.iter().any(|r| r.contains('`') || has_placeholder(r))
            {
                notes.manual("an IP matcher with placeholders or the deprecated `forwarded` option has no equivalent");
                return None;
            }
            if module == "remote_ip" {
                notes.approx("`remote_ip` matches the connection's address; `ClientIP` matches the client address resolved through `security.trusted_proxies` (the same unless trusted proxies are set)");
            } else {
                notes
                    .exact("`ClientIP` (resolved through trusted proxies, as Caddy's `client_ip`)");
            }
            let rules: Vec<String> = ranges.iter().map(|r| format!("ClientIP(`{r}`)")).collect();
            Some(Atom::Rule {
                text: group_or(&rules),
                label: None,
                uri: false,
                paths: None,
            })
        }
        "not" => {
            let sets = config.as_array().cloned().unwrap_or_default();
            let mut alternatives = Vec::new();
            let mut ok = true;
            for (i, set) in sets.iter().enumerate() {
                let inner = matcher_set(run, server, set, &format!("{pointer}/{i}"));
                if inner.unsupported {
                    ok = false;
                }
                let parts: Vec<String> = inner
                    .atoms
                    .iter()
                    .map(|a| match a {
                        Atom::Hosts(h) => {
                            group_or(&h.iter().map(|h| format!("Host(`{h}`)")).collect::<Vec<_>>())
                        }
                        Atom::Rule { text, .. } => text.clone(),
                    })
                    .collect();
                if !parts.is_empty() {
                    alternatives.push(if parts.len() > 1 {
                        format!("({})", parts.join(" && "))
                    } else {
                        parts.join("")
                    });
                }
            }
            if !ok || alternatives.is_empty() {
                notes.manual("a `not` matcher whose inner matchers cannot all be written");
                return None;
            }
            notes.exact("`!(…)`");
            let uri = alternatives
                .iter()
                .any(|a| a.contains("Path") || a.contains("Query"));
            let text = match alternatives.as_slice() {
                [one] if !one.contains(" && ") && !one.contains(" || ") => format!("!{one}"),
                _ => format!("!({})", alternatives.join(" || ")),
            };
            Some(Atom::Rule {
                text,
                label: None,
                uri,
                paths: None,
            })
        }
        "protocol" => {
            notes.manual(format!(
                "the protocol matcher (`{}`) has no equivalent",
                config.as_str().unwrap_or("?")
            ));
            None
        }
        "expression" => {
            notes.manual("a CEL expression matcher has no equivalent");
            notes.hint("rewrite it with Host, Path, Header, Query, Method and ClientIP matchers");
            None
        }
        "file" => {
            notes.manual("the `file` matcher (does a file exist) has no equivalent; it is how `try_files` and `php_fastcgi` are expanded");
            None
        }
        "vars" | "vars_regexp" => {
            notes.manual(format!(
                "the `{module}` matcher (placeholders) has no equivalent"
            ));
            None
        }
        "tls" => {
            notes.manual("the `tls` matcher (early data, handshake state) has no equivalent");
            None
        }
        other => {
            notes.manual(format!(
                "matcher `{other}` is not a standard Caddy module (a plugin) and has no equivalent"
            ));
            None
        }
    }
}

/// `Header(field, value)` for an exact value, `HeaderRegexp` for `*` wildcards (Caddy: prefix,
/// suffix and substring by a leading and/or trailing `*`; a lone `*` is any value).
fn wildcard_rule(exact: &str, regexp: &str, field: &str, value: &str) -> String {
    if value == "*" {
        return format!("{regexp}(`{field}`, `.*`)");
    }
    let (start, end) = (value.starts_with('*'), value.ends_with('*'));
    let core = value.trim_start_matches('*').trim_end_matches('*');
    if !start && !end {
        return format!("{exact}(`{field}`, `{value}`)");
    }
    let mut re = String::new();
    if !start {
        re.push('^');
    }
    re.push_str(&escape(core));
    if !end {
        re.push('$');
    }
    format!("{regexp}(`{field}`, `{re}`)")
}

/// A Caddy path pattern as a rule. Caddy lower-cases both sides and matches: `*` everything;
/// `*x*` a substring; `*x` a suffix; `x*` a prefix (only when it is the only `*`); otherwise a
/// glob (`path.Match`: `*` is any run of characters but `/`, `?` one character), which is an
/// exact match without wildcards (`MatchPath` in `modules/caddyhttp/matchers.go` at v2.11.9).
/// Patterns with `%` (escaped space), `{` (placeholders) or `[` (classes) are not translated.
pub(crate) fn path_rule(pattern: &str) -> Option<String> {
    if pattern.is_empty() || pattern.contains(['%', '{', '[', '\\', '`']) {
        return None;
    }
    let lower = pattern.to_ascii_lowercase();
    let letters = lower.chars().any(|c| c.is_ascii_alphabetic());
    let stars = lower.matches('*').count();
    if lower == "*" {
        return Some("PathPrefix(`/`)".to_owned());
    }
    let re = if stars == 2 && lower.starts_with('*') && lower.ends_with('*') {
        escape(&lower[1..lower.len() - 1])
    } else if stars == 1 && lower.starts_with('*') {
        format!("{}$", escape(&lower[1..]))
    } else if stars == 1 && lower.ends_with('*') {
        let prefix = &lower[..lower.len() - 1];
        if !letters && !lower.contains('?') {
            return Some(format!("PathPrefix(`{prefix}`)"));
        }
        format!("^{}", escape(prefix))
    } else {
        if stars == 0 && !lower.contains('?') && !letters {
            return Some(format!("Path(`{lower}`)"));
        }
        let mut re = String::from("^");
        for c in lower.chars() {
            match c {
                '*' => re.push_str("[^/]*"),
                '?' => re.push_str("[^/]"),
                other => re.push_str(&escape(&other.to_string())),
            }
        }
        re.push('$');
        re
    };
    Some(format!("PathRegexp(`(?i){re}`)"))
}

/// The literal of an exact (`/a`) or prefix (`/a*`) path pattern, lower-cased, with whether it
/// is exact; `None` for other patterns.
fn path_literal(pattern: &str) -> Option<(String, bool)> {
    let lower = pattern.to_ascii_lowercase();
    if lower.contains(['?', '[', '%', '{']) {
        return None;
    }
    match lower.matches('*').count() {
        0 => Some((lower, true)),
        1 if lower.ends_with('*') => Some((lower.trim_end_matches('*').to_owned(), false)),
        _ => None,
    }
}
