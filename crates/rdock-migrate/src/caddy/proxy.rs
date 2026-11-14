//! `reverse_proxy` → a service (and a `headers` middleware for `header_up`/`header_down`), and
//! the expanded `forward_auth` shape → a `forward_auth` middleware.
//!
//! Fields and defaults: <https://caddyserver.com/docs/json/apps/http/servers/routes/handle/reverse_proxy/>
//! and `…/reverse_proxy/transport/http/` (Caddy v2.11.9, read 2026-11-14): the default selection
//! policy is `random`, `dial_timeout` defaults to 3s, there is no response timeout by default, and
//! for an HTTPS transport Caddy sets `Host` to the upstream's address unless `header_up Host`
//! overrides it (`HTTPTransport.RequestHeaderOps` in `modules/caddyhttp/reverseproxy/httptransport.go`
//! at v2.11.9: "when TLS is enabled for this transport, return an operation to set the Host header
//! to the upstream host:port placeholder"; applied before the user's header operations).

use serde_json::{Map, Value, json};

use super::handlers::{Handled, Responder, Step, duration, has_placeholder, header_ops};
use super::{Notes, Run};

/// The `forward_auth` directive's expansion (`caddyconfig/httpcaddyfile` and the
/// `forward_auth_*.caddyfiletest` files at v2.11.9): a `reverse_proxy` that rewrites the copy of
/// the request to `GET <uri>`, sets `X-Forwarded-Method` and `X-Forwarded-Uri`, and on a 2xx
/// answer runs routes that copy each listed header from the answer to the request (deleting the
/// client's own first). Returns the auth address and the copied headers.
fn forward_auth_shape(h: &Value) -> Option<(String, Vec<String>)> {
    let rewrite = h.get("rewrite")?.as_object()?;
    if rewrite.get("method").and_then(Value::as_str) != Some("GET") || rewrite.len() != 2 {
        return None;
    }
    let uri = rewrite.get("uri")?.as_str()?;
    if has_placeholder(uri) {
        return None;
    }
    let set = h.pointer("/headers/request/set")?.as_object()?;
    let method = set.get("X-Forwarded-Method")?.as_array()?;
    let fwd_uri = set.get("X-Forwarded-Uri")?.as_array()?;
    if method != &vec![json!("{http.request.method}")]
        || fwd_uri != &vec![json!("{http.request.uri}")]
        || set.len() != 2
    {
        return None;
    }
    let responses = h.get("handle_response")?.as_array()?;
    let [response] = responses.as_slice() else {
        return None;
    };
    if response.pointer("/match/status_code")? != &json!([2]) {
        return None;
    }
    let mut copied = Vec::new();
    for route in response.get("routes")?.as_array()? {
        let handlers = route.get("handle")?.as_array()?;
        let [handler] = handlers.as_slice() else {
            return None;
        };
        match handler.get("handler")?.as_str()? {
            "vars" if handler.as_object()?.len() == 1 => {}
            "headers" => {
                let request = handler.get("request")?.as_object()?;
                if let Some(delete) = request.get("delete") {
                    let [name] = delete.as_array()?.as_slice() else {
                        return None;
                    };
                    copied.push(name.as_str()?.to_owned());
                } else {
                    let set = request.get("set")?;
                    let set = set.as_object()?;
                    let (name, value) = set.iter().next()?;
                    // `copy_headers A>B` renames: not the same header, not this shape.
                    if set.len() != 1
                        || value != &json!([format!("{{http.reverse_proxy.header.{name}}}")])
                        || !copied.contains(name)
                    {
                        return None;
                    }
                }
            }
            _ => return None,
        }
    }
    let upstreams = h.get("upstreams")?.as_array()?;
    let [upstream] = upstreams.as_slice() else {
        return None;
    };
    let dial = upstream.get("dial")?.as_str()?;
    if has_placeholder(dial) || dial.contains('/') {
        return None;
    }
    let scheme = if h.pointer("/transport/tls").is_some() {
        "https"
    } else {
        "http"
    };
    Some((format!("{scheme}://{dial}{uri}"), copied))
}

/// Translates a `reverse_proxy` handler.
#[allow(clippy::too_many_lines)] // one block per field family
pub(crate) fn reverse_proxy(run: &mut Run<'_>, h: &Value, notes: &mut Notes) -> Handled {
    if let Some((address, copy)) = forward_auth_shape(h) {
        notes.approx(format!("the expanded `forward_auth` directive → a `forward_auth` middleware asking `{address}`; the authentication service gets `Host` set to its own address (Caddy passes the client's) and no request body"));
        let mut value = json!({ "type": "forward_auth", "address": address });
        if !copy.is_empty() {
            value["copy_headers"] = json!(copy);
        }
        return Handled::Steps(vec![Step::Middleware {
            kind: "forward-auth".to_owned(),
            value,
        }]);
    }
    let mut blocked: Vec<String> = Vec::new();
    if h.get("handle_response").is_some() {
        block(notes, &mut blocked, "`handle_response` (handling the backend's answer with other handlers) has no equivalent".to_owned());
        notes.hint("for custom error pages, use the `errors` middleware; for authentication, `forward_auth`");
    }
    if h.get("rewrite").is_some() {
        block(
            notes,
            &mut blocked,
            "a rewrite of the request copy sent to the backend has no equivalent".to_owned(),
        );
    }
    let transport = h.get("transport").cloned().unwrap_or(Value::Null);
    let protocol = transport
        .get("protocol")
        .and_then(Value::as_str)
        .unwrap_or("http");
    if protocol != "http" {
        block(
            notes,
            &mut blocked,
            format!(
                "the `{protocol}` transport has no equivalent (FastCGI is how `php_fastcgi` is expanded; F-WEB-04 is not implemented)"
            ),
        );
    }
    let mut service = Map::new();
    let mut backends = Vec::new();
    let mut first_address = String::from("backend");
    for upstream in h
        .get("upstreams")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        let dial = upstream.get("dial").and_then(Value::as_str).unwrap_or("");
        match dial_address(dial) {
            Some(address) => {
                if backends.is_empty() {
                    first_address.clone_from(&address);
                }
                backends.push(json!({ "address": address }));
            }
            None => block(
                notes,
                &mut blocked,
                format!(
                    "upstream `{dial}` (placeholders, a port range or a network type) has no equivalent"
                ),
            ),
        }
        if upstream.get("max_requests").is_some() {
            notes.approx(
                "`max_requests` per upstream is a service-wide `max_connections_per_backend` here",
            );
            if let Some(n) = upstream.get("max_requests").and_then(Value::as_u64) {
                service.insert("max_connections_per_backend".to_owned(), json!(n));
            }
        }
    }
    if let Some(dynamic) = h.get("dynamic_upstreams") {
        match dynamic.get("source").and_then(Value::as_str) {
            Some("a") => {
                let name = dynamic.get("name").and_then(Value::as_str).unwrap_or("");
                let port = dynamic
                    .get("port")
                    .and_then(|p| {
                        p.as_str()
                            .map(str::to_owned)
                            .or_else(|| p.as_u64().map(|n| n.to_string()))
                    })
                    .unwrap_or_else(|| "80".to_owned());
                if name.is_empty() || has_placeholder(name) {
                    block(
                        notes,
                        &mut blocked,
                        "dynamic A/AAAA upstreams without a name".to_owned(),
                    );
                } else {
                    first_address = format!("{name}:{port}");
                    backends.push(json!({ "address": first_address }));
                    notes.approx(format!("dynamic A/AAAA upstreams → the backend `{name}:{port}`, which ReverseDock resolves itself (refresh settings differ)"));
                }
            }
            Some("srv") => {
                let full = match (
                    dynamic.get("service").and_then(Value::as_str),
                    dynamic.get("proto").and_then(Value::as_str),
                    dynamic.get("name").and_then(Value::as_str),
                ) {
                    (Some(s), Some(p), Some(n)) => Some(format!("_{s}._{p}.{n}")),
                    (None, None, Some(n)) => Some(n.to_owned()),
                    _ => None,
                };
                match full {
                    Some(full) if !has_placeholder(&full) => {
                        first_address = format!("srv://{full}");
                        backends.push(json!({ "address": first_address }));
                        notes.approx(format!("dynamic SRV upstreams → the backend `srv://{full}` (refresh settings differ)"));
                    }
                    _ => block(
                        notes,
                        &mut blocked,
                        "dynamic SRV upstreams without a full name".to_owned(),
                    ),
                }
            }
            other => block(
                notes,
                &mut blocked,
                format!(
                    "dynamic upstreams from `{}` have no equivalent",
                    other.unwrap_or("?")
                ),
            ),
        }
    }
    if backends.is_empty() && blocked.is_empty() {
        block(
            notes,
            &mut blocked,
            "a `reverse_proxy` without upstreams".to_owned(),
        );
    }
    // Transport.
    let tls = transport.get("tls");
    let versions: Vec<String> = transport
        .get("versions")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let https = tls.is_some();
    if versions.iter().any(|v| v == "h2c") {
        service.insert("scheme".to_owned(), json!("h2c"));
        notes.exact("HTTP/2 in cleartext (`scheme: h2c`)");
    } else if versions.iter().any(|v| v == "3") {
        block(
            notes,
            &mut blocked,
            "HTTP/3 to backends has no equivalent".to_owned(),
        );
    } else if https {
        service.insert("scheme".to_owned(), json!("https"));
        notes.exact("HTTPS to the backends (`scheme: https`), certificates verified as in Caddy");
    }
    if let Some(tls) = tls {
        let mut upstream_tls = Map::new();
        for (key, value) in tls.as_object().cloned().unwrap_or_default() {
            match key.as_str() {
                "server_name" => {
                    upstream_tls.insert("server_name".to_owned(), value.clone());
                }
                "insecure_skip_verify" if value == json!(true) => {
                    upstream_tls.insert("verify".to_owned(), json!(false));
                    notes.exact("certificate verification is off, as configured (`verify: false`)");
                    notes.security();
                    notes.hint("turn verification back on with `ca_file` naming the backend's CA");
                }
                "ca" => {
                    let files: Vec<&str> = value
                        .get("pem_files")
                        .and_then(Value::as_array)
                        .map(|a| a.iter().filter_map(Value::as_str).collect())
                        .unwrap_or_default();
                    match (value.get("provider").and_then(Value::as_str), files.as_slice()) {
                        (Some("file"), [file]) => {
                            upstream_tls.insert("ca_file".to_owned(), json!(file));
                        }
                        _ => block(notes, &mut blocked, "a CA pool other than one PEM file has no equivalent (`tls.ca_file` names one file)".to_owned()),
                    }
                }
                "root_ca_pem_files" => match value.as_array().map(Vec::as_slice) {
                    Some([file]) => {
                        upstream_tls.insert("ca_file".to_owned(), file.clone());
                    }
                    _ => block(
                        notes,
                        &mut blocked,
                        "several CA files: `tls.ca_file` names one file (concatenate them)"
                            .to_owned(),
                    ),
                },
                "client_certificate_file" => {
                    upstream_tls.insert("cert_file".to_owned(), value.clone());
                }
                "client_certificate_key_file" => {
                    upstream_tls.insert("key_file".to_owned(), value.clone());
                }
                "insecure_skip_verify" => {}
                "handshake_timeout" | "renegotiation" | "curves" => {
                    notes.approx(format!("TLS `{key}` to backends is not configurable here"));
                }
                other => block(
                    notes,
                    &mut blocked,
                    format!("backend TLS setting `{other}` has no equivalent"),
                ),
            }
        }
        if !upstream_tls.is_empty() {
            service.insert("tls".to_owned(), Value::Object(upstream_tls));
        }
    }
    let mut timeouts = Map::new();
    if let Some(d) = transport.get("dial_timeout").and_then(duration) {
        timeouts.insert("connect".to_owned(), json!(d));
    } else {
        timeouts.insert("connect".to_owned(), json!("3s"));
        run.defaults_changed.insert("caddy.default.dial_timeout", "Caddy's default dial timeout (3s) is written as `timeouts.connect: 3s` on each service (ReverseDock's default is 5s)".to_owned());
    }
    let read = transport.get("read_timeout").and_then(duration);
    let header = transport.get("response_header_timeout").and_then(duration);
    match (read, header) {
        (Some(r), _) => {
            timeouts.insert("read".to_owned(), json!(r));
        }
        (None, Some(hd)) => {
            timeouts.insert("read".to_owned(), json!(hd));
            notes.approx(format!("`response_header_timeout` → `timeouts.read: {hd}`, which also bounds each wait for response data"));
        }
        (None, None) => {
            run.defaults_changed.insert("caddy.default.response_timeout", "Caddy waits for a backend's answer without a time limit by default; ReverseDock's `timeouts.read` is 60s between two reads (raise it on services with slow answers)".to_owned());
        }
    }
    if let Some(w) = transport.get("write_timeout").and_then(duration) {
        timeouts.insert("write".to_owned(), json!(w));
    }
    if let Some(i) = transport
        .pointer("/keep_alive/idle_timeout")
        .and_then(duration)
    {
        timeouts.insert("idle".to_owned(), json!(i));
    }
    service.insert("timeouts".to_owned(), Value::Object(timeouts));
    for (key, value) in transport.as_object().cloned().unwrap_or_default() {
        match key.as_str() {
            "protocol"
            | "tls"
            | "versions"
            | "dial_timeout"
            | "read_timeout"
            | "response_header_timeout"
            | "write_timeout" => {}
            "keep_alive" => {
                if value.get("enabled") == Some(&json!(false)) {
                    notes.approx("keep-alive to backends cannot be turned off: ReverseDock pools connections");
                }
            }
            "max_conns_per_host" => {
                if let Some(n) = value.as_u64() {
                    service.insert("max_connections_per_backend".to_owned(), json!(n));
                    notes.approx(format!("`max_conns_per_host` → `max_connections_per_backend: {n}` (requests over the limit wait in Caddy, are refused here)"));
                }
            }
            "proxy_protocol" => block(
                notes,
                &mut blocked,
                "sending the PROXY protocol to an HTTP backend has no equivalent".to_owned(),
            ),
            "forward_proxy_url" | "network_proxy" => block(
                notes,
                &mut blocked,
                "an outbound forward proxy has no equivalent".to_owned(),
            ),
            "local_address" => block(
                notes,
                &mut blocked,
                "binding outgoing connections to a local address has no equivalent".to_owned(),
            ),
            other => notes.approx(format!(
                "transport setting `{other}` has no equivalent and is left out"
            )),
        }
    }
    // Load balancing.
    let lb = h.get("load_balancing").cloned().unwrap_or(Value::Null);
    let policy = lb
        .pointer("/selection_policy/policy")
        .and_then(Value::as_str);
    let mut balancer = Map::new();
    match policy {
        None | Some("random") => {
            balancer.insert("policy".to_owned(), json!("random"));
            if policy.is_none() && backends.len() > 1 {
                run.defaults_changed.insert("caddy.default.lb_policy", "Caddy's default selection policy `random` is written explicitly as `load_balancer.policy: random` (ReverseDock's default is `round_robin`)".to_owned());
            }
        }
        Some("round_robin") => {
            balancer.insert("policy".to_owned(), json!("round_robin"));
        }
        Some("weighted_round_robin") => {
            balancer.insert("policy".to_owned(), json!("round_robin"));
            let weights: Vec<u64> = lb
                .pointer("/selection_policy/weights")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_u64).collect())
                .unwrap_or_default();
            for (backend, weight) in backends.iter_mut().zip(weights) {
                backend["weight"] = json!(weight);
            }
            notes.exact("weighted round-robin → `round_robin` with backend weights");
        }
        Some("least_conn") => {
            balancer.insert("policy".to_owned(), json!("least_conn"));
        }
        Some("random_choose") => {
            balancer.insert("policy".to_owned(), json!("p2c"));
            let choose = lb
                .pointer("/selection_policy/choose")
                .and_then(Value::as_u64)
                .unwrap_or(2);
            if choose == 2 {
                notes.exact("`random_choose 2` → `p2c` (the less loaded of two random backends)");
            } else {
                notes.approx(format!(
                    "`random_choose {choose}` → `p2c`, which chooses from two"
                ));
            }
        }
        Some("ip_hash" | "client_ip_hash") => {
            balancer.insert("policy".to_owned(), json!("ip_hash"));
            notes.approx("`ip_hash` hashes the client address resolved through trusted proxies, with another hash function: each client keeps a backend, but not the one Caddy chose");
        }
        Some("header") => {
            let field = lb
                .pointer("/selection_policy/field")
                .and_then(Value::as_str)
                .unwrap_or("");
            balancer.insert("policy".to_owned(), json!("header_hash"));
            balancer.insert("hash_on".to_owned(), json!(field));
            notes.approx(format!(
                "hashing on `{field}` keeps clients on one backend, but not the one Caddy chose"
            ));
        }
        Some("cookie") => {
            let name = lb
                .pointer("/selection_policy/name")
                .and_then(Value::as_str)
                .unwrap_or("lb");
            balancer.insert("policy".to_owned(), json!("cookie_hash"));
            balancer.insert("hash_on".to_owned(), json!(name));
            notes.approx(format!("Caddy sets an HMAC cookie `{name}` naming the backend; ReverseDock hashes the cookie's value instead, so existing sessions move once"));
        }
        Some("first") => {
            for (i, backend) in backends.iter_mut().enumerate() {
                if i > 0 {
                    backend["backup"] = json!(true);
                }
            }
            notes.approx(
                "`first` → the first upstream, the others as backups (used only while it is down)",
            );
        }
        Some(other) => {
            balancer.insert("policy".to_owned(), json!("random"));
            notes.approx(format!("selection policy `{other}` has no equivalent: written as `random`, Caddy's fallback"));
        }
    }
    if policy.is_none_or(|p| p != "random" && p != "first") {
        service.insert("load_balancer".to_owned(), Value::Object(balancer));
    } else if policy == Some("random") {
        service.insert("load_balancer".to_owned(), json!({ "policy": "random" }));
    }
    if lb.get("retries").is_some() || lb.get("try_duration").is_some() {
        let attempts = lb.get("retries").and_then(Value::as_u64).unwrap_or(2);
        service.insert(
            "retries".to_owned(),
            json!({ "attempts": attempts, "on": ["connect"] }),
        );
        notes.approx(format!("retrying another upstream → `retries: {{ attempts: {attempts}, on: [connect] }}`; Caddy's time-bounded retrying (`try_duration`, `try_interval`) has no equivalent"));
        if lb.get("retry_match").is_some() {
            notes.approx("which requests may be retried (`retry_match`) is not configurable: ReverseDock retries only idempotent requests and connection failures");
        }
    }
    // Health checks.
    if let Some(active) = h.pointer("/health_checks/active") {
        let mut a = Map::new();
        let uri = active
            .get("uri")
            .or_else(|| active.get("path"))
            .and_then(Value::as_str)
            .unwrap_or("/");
        a.insert("path".to_owned(), json!(uri));
        if let Some(p) = active.get("port").and_then(Value::as_u64) {
            a.insert("port".to_owned(), json!(p));
        }
        // Caddy's defaults: every 30s, 5s timeout, one pass and one failure.
        a.insert(
            "interval".to_owned(),
            json!(
                active
                    .get("interval")
                    .and_then(duration)
                    .unwrap_or_else(|| "30s".to_owned())
            ),
        );
        a.insert(
            "timeout".to_owned(),
            json!(
                active
                    .get("timeout")
                    .and_then(duration)
                    .unwrap_or_else(|| "5s".to_owned())
            ),
        );
        a.insert(
            "healthy".to_owned(),
            json!(active.get("passes").and_then(Value::as_u64).unwrap_or(1)),
        );
        a.insert(
            "unhealthy".to_owned(),
            json!(active.get("fails").and_then(Value::as_u64).unwrap_or(1)),
        );
        if let Some(m) = active.get("method").and_then(Value::as_str) {
            a.insert("method".to_owned(), json!(m.to_ascii_uppercase()));
        }
        if let Some(code) = active.get("expect_status").and_then(Value::as_u64) {
            a.insert(
                "expected_status".to_owned(),
                json!(if code < 10 {
                    format!("{code}xx")
                } else {
                    code.to_string()
                }),
            );
        }
        if let Some(Value::Object(headers)) = active.get("headers") {
            let mut out = Map::new();
            for (k, v) in headers {
                let text = v
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(Value::as_str)
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .unwrap_or_default();
                if has_placeholder(&text) {
                    notes.approx(format!(
                        "health check header `{k}` uses a placeholder and is left out"
                    ));
                } else if k.eq_ignore_ascii_case("host") {
                    a.insert("hostname".to_owned(), json!(text));
                } else {
                    out.insert(k.clone(), json!(text));
                }
            }
            if !out.is_empty() {
                a.insert("headers".to_owned(), Value::Object(out));
            }
        }
        if active.get("expect_body").is_some() {
            notes.approx("`expect_body` is a regular expression in Caddy; `expected_body` is a substring here");
            a.insert(
                "expected_body".to_owned(),
                active.get("expect_body").cloned().unwrap_or(Value::Null),
            );
        }
        for key in ["body", "follow_redirects", "upstream", "max_size"] {
            if active.get(key).is_some() {
                notes.approx(format!(
                    "active health check `{key}` has no equivalent and is left out"
                ));
            }
        }
        notes.exact("active health checks with Caddy's defaults written explicitly (30s, 5s, one pass, one failure)");
        service.insert("health".to_owned(), json!({ "active": a }));
    }
    if let Some(passive) = h.pointer("/health_checks/passive") {
        if let Some(window) = passive.get("fail_duration").and_then(duration) {
            let failures = passive
                .get("max_fails")
                .and_then(Value::as_u64)
                .unwrap_or(1);
            let mut p = json!({ "failures": failures, "window": window, "ejection": window });
            if let Some(statuses) = passive.get("unhealthy_status").and_then(Value::as_array) {
                p["statuses"] = Value::Array(statuses.clone());
            }
            notes.approx(format!("passive health checks: {failures} failure(s) within {window} eject a backend for {window}; ReverseDock doubles the ejection for each ejection in a row and never ejects more than half the pool"));
            let health = service
                .entry("health".to_owned())
                .or_insert_with(|| json!({}));
            health["passive"] = p;
        }
        if passive.get("unhealthy_latency").is_some() {
            notes.approx(
                "counting slow answers as failures (`unhealthy_latency`) has no equivalent",
            );
        }
        if let Some(n) = passive
            .get("unhealthy_request_count")
            .and_then(Value::as_u64)
        {
            service.insert("max_connections_per_backend".to_owned(), json!(n));
            notes.approx(format!("`unhealthy_request_count` → `max_connections_per_backend: {n}` (requests over it are refused instead of the backend being marked down)"));
        }
    }
    // Headers and Host.
    let header_up_host = h
        .pointer("/headers/request/set")
        .and_then(Value::as_object)
        .and_then(|m| m.iter().find(|(k, _)| k.eq_ignore_ascii_case("host")))
        .and_then(|(_, v)| v.as_array())
        .and_then(|a| a.first())
        .and_then(Value::as_str)
        .map(str::to_owned);
    match header_up_host.as_deref() {
        None if https => {
            service.insert("pass_host_header".to_owned(), json!(false));
            run.defaults_changed.insert("caddy.default.host_header", "since 2.11 Caddy sends the upstream's address as `Host` to HTTPS backends: written as `pass_host_header: false` on those services".to_owned());
        }
        None => {}
        Some("{http.reverse_proxy.upstream.hostport}" | "{http.reverse_proxy.upstream.host}") => {
            service.insert("pass_host_header".to_owned(), json!(false));
            notes.exact("`header_up Host {upstream_hostport}` → `pass_host_header: false`");
        }
        Some("{http.request.host}" | "{http.request.hostport}") => {
            notes.exact("`header_up Host {host}` → the client's `Host` is passed (`pass_host_header`, the default)");
        }
        Some(other) => block(
            notes,
            &mut blocked,
            format!("`header_up Host {other}` (a fixed or computed Host) has no equivalent"),
        ),
    }
    let mut steps = Vec::new();
    if let Some(headers) = h.get("headers") {
        let (value, why) = header_ops(headers, notes, true);
        if let Some(value) = value {
            steps.push(Step::Middleware {
                kind: "headers".to_owned(),
                value,
            });
        }
        if let Some(why) = why {
            blocked.push(why);
        }
    }
    for (key, value) in h.as_object().cloned().unwrap_or_default() {
        match key.as_str() {
            "handler" | "upstreams" | "dynamic_upstreams" | "transport" | "load_balancing" | "health_checks" | "headers" | "handle_response" | "rewrite" => {}
            "flush_interval" => {
                if value.as_i64().is_some_and(|n| n < 0) {
                    notes.exact("responses are streamed (`flush_interval: -1`), as ReverseDock always does");
                } else {
                    notes.approx("ReverseDock streams responses as they arrive instead of flushing at an interval");
                }
            }
            "request_buffers" => notes.approx("buffering the request body (`request_buffers`) is the `hold_body` middleware here; it is not added"),
            "response_buffers" => notes.approx("buffering the response (`response_buffers`) has no equivalent: ReverseDock streams"),
            "trusted_proxies" => {
                if let Some(ranges) = value.as_array() {
                    run.security.insert("trusted_proxies".to_owned(), Value::Array(ranges.clone()));
                }
                notes.approx("`trusted_proxies` → `security.trusted_proxies` (with `--full`), which applies to every route");
            }
            "stream_timeout" | "stream_close_delay" => notes.approx(format!("`{key}` for upgraded connections has no equivalent")),
            "circuit_breaker" => notes.approx("a circuit breaker has no direct equivalent (passive health checks and `admission` are the nearest)"),
            "verbose_logs" => notes.exact("verbose logs: nothing to migrate"),
            other => notes.approx(format!("`{other}` has no equivalent and is left out")),
        }
    }
    service.insert("backends".to_owned(), Value::Array(backends));
    if blocked.is_empty() {
        notes.exact("`reverse_proxy` → a service");
        Handled::Respond(
            steps,
            Responder::Service {
                kind: first_address,
                value: Value::Object(service),
            },
        )
    } else {
        Handled::Respond(
            steps,
            Responder::Blocked {
                reason: blocked.join("; "),
                service: Value::Object(service),
            },
        )
    }
}

/// A Caddy network address as a backend address: `host:port` (port 80 when missing, as the
/// Caddyfile adapter adds it), `unix//path` as `unix:///path`.
fn dial_address(dial: &str) -> Option<String> {
    if dial.is_empty() || has_placeholder(dial) {
        return None;
    }
    if let Some(path) = dial.strip_prefix("unix/") {
        return path.starts_with('/').then(|| format!("unix://{path}"));
    }
    let dial = dial.strip_prefix("tcp/").unwrap_or(dial);
    if dial.contains('/') {
        return None;
    }
    match dial.rsplit_once(':') {
        Some((_, port)) if port.contains('-') => None,
        Some((host, port)) if port.parse::<u16>().is_ok() && !host.ends_with(':') => {
            Some(dial.to_owned())
        }
        _ if dial.starts_with('[') && dial.ends_with(']') => Some(format!("{dial}:80")),
        Some(_) if dial.starts_with('[') => None,
        _ => Some(format!("{dial}:80")),
    }
}

/// Notes a reason the route must be written disabled.
fn block(notes: &mut Notes, blocked: &mut Vec<String>, why: String) {
    notes.manual(why.clone());
    blocked.push(why);
}
