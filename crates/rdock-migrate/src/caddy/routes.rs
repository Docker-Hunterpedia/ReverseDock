//! Servers and routes: Caddy's ordered route lists flattened into ReverseDock routes.
//!
//! Semantics followed (Caddy v2.11.9, read 2026-11-14): "Routes are executed sequentially.
//! First a route's matchers are evaluated, then its grouping. If it matches and has not been
//! mutually-excluded by its grouping, then its handlers are executed sequentially"; "Each matcher
//! set is OR'ed, but matchers within a set are AND'ed together"; a route in a `group` is skipped
//! once another route of the same group has matched; `terminal: true` stops the route list after
//! the route; handlers "are chained together in a middleware fashion" until one answers
//! (<https://caddyserver.com/docs/json/apps/http/servers/routes/>). A request no handler answers
//! gets an empty `200` (`modules/caddyhttp/server.go` at v2.11.9: the chain ends in an empty
//! handler).

use std::collections::{BTreeSet, HashMap};

use serde_json::{Map, Value, json};

use super::handlers::{self, Handled, Responder, Step};
use super::{Notes, Ports, Run};
use crate::report::Finding;

/// The most paths followed through one server before giving up (each conditional route that
/// does not always answer doubles them).
const MAX_STATES: usize = 64;

/// One translated matcher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Atom {
    /// `host`: names, lower-cased; `*` stands for one label in Caddy and here.
    Hosts(Vec<String>),
    /// Any other matcher as a rule expression, with a short label for route names, and
    /// whether it looks at the path or query (which a rewrite before it changes).
    Rule {
        text: String,
        label: Option<String>,
        uri: bool,
        paths: Option<Vec<(String, bool)>>,
    },
}

impl Atom {
    fn render(&self) -> String {
        match self {
            Self::Hosts(hosts) => {
                let parts: Vec<String> = hosts.iter().map(|h| format!("Host(`{h}`)")).collect();
                group_or(&parts)
            }
            Self::Rule { text, .. } => text.clone(),
        }
    }
}

/// `a || b` in parentheses when there is more than one.
pub(crate) fn group_or(parts: &[String]) -> String {
    match parts {
        [one] => one.clone(),
        _ => format!("({})", parts.join(" || ")),
    }
}

/// One matcher set: its matchers must all match.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Set {
    pub(crate) atoms: Vec<Atom>,
    /// Matchers that could not be translated (the set cannot be written exactly).
    pub(crate) unsupported: bool,
}

impl Set {
    fn render(&self) -> Option<String> {
        let parts: Vec<String> = self.atoms.iter().map(Atom::render).collect();
        match parts.len() {
            0 => None,
            1 => parts.into_iter().next(),
            _ => Some(parts.join(" && ")),
        }
    }

    fn hosts(&self) -> Option<&[String]> {
        self.atoms.iter().find_map(|a| match a {
            Atom::Hosts(h) => Some(h.as_slice()),
            Atom::Rule { .. } => None,
        })
    }

    /// The literals of a path matcher whose patterns are all exact or prefixes.
    fn paths(&self) -> Option<&[(String, bool)]> {
        self.atoms.iter().find_map(|a| match a {
            Atom::Rule { paths: Some(p), .. } => Some(p.as_slice()),
            _ => None,
        })
    }

    fn only_hosts(&self) -> Option<&[String]> {
        match self.atoms.as_slice() {
            [Atom::Hosts(h)] if !self.unsupported => Some(h.as_slice()),
            _ => None,
        }
    }
}

/// A route's matcher sets (any may match), possibly negated.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Term {
    sets: Vec<Set>,
    negated: bool,
}

impl Term {
    /// Whether a matcher of the term looks at the path or query.
    fn uses_uri(&self) -> bool {
        self.sets
            .iter()
            .flat_map(|s| s.atoms.iter())
            .any(|a| matches!(a, Atom::Rule { uri: true, .. }))
    }

    fn exact(&self) -> bool {
        self.sets.iter().all(|s| !s.unsupported)
    }

    fn render(&self) -> Option<String> {
        let sets: Vec<String> = self.sets.iter().filter_map(Set::render).collect();
        let body = match sets.len() {
            0 => return None,
            1 => sets.into_iter().next().unwrap_or_default(),
            _ => sets
                .iter()
                .map(|s| {
                    if s.contains(" && ") {
                        format!("({s})")
                    } else {
                        s.clone()
                    }
                })
                .collect::<Vec<_>>()
                .join(" || "),
        };
        Some(if self.negated {
            if let Some(inner) = body.strip_prefix('!')
                && ((!inner.contains(" && ") && !inner.contains(" || ") && !inner.starts_with('!'))
                    || (inner.starts_with('(')
                        && inner.ends_with(')')
                        && balanced(&inner[1..inner.len() - 1])))
            {
                return Some(inner.to_owned());
            }
            let single = !body.contains(" && ") && !body.contains(" || ") && !body.starts_with('!');
            if single
                || (body.starts_with('(')
                    && body.ends_with(')')
                    && balanced(&body[1..body.len() - 1]))
            {
                format!("!{body}")
            } else {
                format!("!({body})")
            }
        } else {
            body
        })
    }
}

/// Whether parentheses in `text` are balanced (so `(text)` is one group).
fn balanced(text: &str) -> bool {
    let mut depth = 0i32;
    let mut quoted = false;
    for c in text.chars() {
        match c {
            '`' => quoted = !quoted,
            '(' if !quoted => depth += 1,
            ')' if !quoted => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            _ => {}
        }
    }
    depth == 0
}

/// Whether two host patterns can match the same name (`*` is one label).
fn hosts_overlap(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    let matches = |pattern: &str, name: &str| {
        let p: Vec<&str> = pattern.split('.').collect();
        let n: Vec<&str> = name.split('.').collect();
        p.len() == n.len()
            && p.iter()
                .zip(&n)
                .all(|(p, n)| *p == "*" || *n == "*" || p == n)
    };
    matches(a, b)
}

/// Whether every name `a` matches is matched by `b`.
fn host_within(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    let p: Vec<&str> = b.split('.').collect();
    let n: Vec<&str> = a.split('.').collect();
    p.len() == n.len() && p.iter().zip(&n).all(|(p, n)| *p == "*" || p == n)
}

/// Two path literals (exact or prefix) that no path matches both of.
fn paths_disjoint((a, a_exact): &(String, bool), (b, b_exact): &(String, bool)) -> bool {
    match (a_exact, b_exact) {
        (true, true) => a != b,
        (true, false) => !a.starts_with(b.as_str()),
        (false, true) => !b.starts_with(a.as_str()),
        (false, false) => !a.starts_with(b.as_str()) && !b.starts_with(a.as_str()),
    }
}

/// `p` and `n` cannot both match one request (by their host or path matchers).
fn disjoint(p: &Term, n: &Term) -> bool {
    p.sets.iter().all(|ps| {
        n.sets.iter().all(|ns| {
            let hosts = match (ps.hosts(), ns.hosts()) {
                (Some(a), Some(b)) => a.iter().all(|x| b.iter().all(|y| !hosts_overlap(x, y))),
                _ => false,
            };
            let paths = match (ps.paths(), ns.paths()) {
                (Some(a), Some(b)) => a.iter().all(|x| b.iter().all(|y| paths_disjoint(x, y))),
                _ => false,
            };
            hosts || paths
        })
    })
}

/// Every request `p` matches is matched by `n` (when `n` is a plain host matcher).
fn implies(p: &Term, n: &Term) -> bool {
    let [single] = n.sets.as_slice() else {
        return false;
    };
    let Some(within) = single.only_hosts() else {
        return false;
    };
    !p.sets.is_empty()
        && p.sets.iter().all(|ps| {
            ps.hosts()
                .is_some_and(|hs| hs.iter().all(|h| within.iter().any(|w| host_within(h, w))))
        })
}

/// One path through a route list.
#[derive(Debug, Clone, Default)]
pub(crate) struct State {
    terms: Vec<Term>,
    pub(crate) chain: Vec<Step>,
    /// `(scope, group)` pairs already matched.
    groups: BTreeSet<(usize, String)>,
    /// Hosts and paths for the route's name.
    label: Vec<String>,
    /// Why the route must be written disabled.
    pub(crate) blocked: Vec<String>,
    /// A handler on the path changed the request URI.
    pub(crate) rewritten: bool,
}

impl State {
    /// The state with `term` added, or `None` when no request can match both.
    fn with(&self, term: Term) -> Option<Self> {
        let mut next = self.clone();
        if term.sets.is_empty() {
            return (!term.negated).then_some(next);
        }
        if next.terms.contains(&term) {
            return Some(next);
        }
        if term.negated {
            for existing in next.terms.iter().filter(|t| !t.negated) {
                if disjoint(existing, &term) {
                    return Some(next);
                }
                if implies(existing, &term) {
                    return None;
                }
            }
        } else {
            if next
                .terms
                .iter()
                .any(|t| !t.negated && t.exact() && term.exact() && disjoint(t, &term))
            {
                return None;
            }
            let mut keep = Vec::with_capacity(next.terms.len());
            for existing in next.terms {
                if existing.negated {
                    if implies(&term, &existing) {
                        return None;
                    }
                    if disjoint(&term, &existing) {
                        continue;
                    }
                }
                keep.push(existing);
            }
            next.terms = keep;
            for set in &term.sets {
                if let Some(hosts) = set.hosts()
                    && let Some(first) = hosts.first()
                    && !next.label.iter().any(|l| l.contains('.'))
                {
                    next.label.insert(0, first.replace('*', "wildcard"));
                }
                for atom in &set.atoms {
                    if let Atom::Rule {
                        label: Some(label), ..
                    } = atom
                    {
                        next.label.push(label.clone());
                    }
                }
            }
        }
        next.terms.push(term);
        Some(next)
    }

    fn rule(&self) -> String {
        let parts: Vec<String> = self.terms.iter().filter_map(Term::render).collect();
        if parts.is_empty() {
            return "PathPrefix(`/`)".to_owned();
        }
        parts
            .iter()
            .map(|p| {
                if parts.len() > 1
                    && p.contains(" || ")
                    && !(p.starts_with('(') || p.starts_with('!'))
                {
                    format!("({p})")
                } else {
                    p.clone()
                }
            })
            .collect::<Vec<_>>()
            .join(" && ")
    }

    pub(crate) fn hosts(&self) -> BTreeSet<String> {
        self.terms
            .iter()
            .filter(|t| !t.negated)
            .flat_map(|t| t.sets.iter())
            .filter_map(Set::hosts)
            .flatten()
            .cloned()
            .collect()
    }
}

/// A path that ends in a handler that answers.
struct Leaf {
    state: State,
    responder: Responder,
}

/// What one server contributes.
struct ServerRun<'s> {
    name: &'s str,
    /// Translations of handlers and matcher sets, by JSON pointer (each is accounted once).
    handled: HashMap<String, Handled>,
    sets: HashMap<String, Set>,
    leaves: Vec<Leaf>,
    /// Requests that reach the end of the route list (Caddy answers an empty 200).
    unanswered: bool,
    scopes: usize,
    overflow: bool,
    /// Named routes, for `invoke`.
    named: Map<String, Value>,
    /// The server uses TLS.
    https: bool,
}

/// One server: its listener settings and its routes.
#[allow(clippy::too_many_lines)] // listeners, settings and routes of one server in order
pub(crate) fn server(run: &mut Run<'_>, name: &str, server: &Value, ports: &mut Ports) {
    let Value::Object(fields) = server else {
        run.account(
            Some(name),
            &format!("/apps/http/servers/{name}"),
            Finding::new("caddy.server.manual", "the server is not an object"),
        );
        return;
    };
    let base = format!("/apps/http/servers/{name}");
    let listen: Vec<String> = fields.get("listen").and_then(Value::as_array).map_or_else(
        || vec![":443".to_owned()],
        |l| {
            l.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        },
    );
    let routes = fields
        .get("routes")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let auto = fields
        .get("automatic_https")
        .cloned()
        .unwrap_or(Value::Null);
    let auto_disabled = auto
        .get("disable")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let has_policies = fields
        .get("tls_connection_policies")
        .and_then(Value::as_array)
        .is_some_and(|p| !p.is_empty());
    // Which listeners the server's addresses become, and whether they use TLS: a server on the
    // HTTP port is plain HTTP; another one uses TLS when automatic HTTPS applies (a host
    // matcher in its routes) or it has connection policies (Caddy's automatic HTTPS docs).
    let has_hosts = routes.iter().any(|r| {
        r.get("match")
            .and_then(Value::as_array)
            .is_some_and(|sets| sets.iter().any(|s| s.get("host").is_some()))
    });
    let mut listener_names = Vec::new();
    let mut listen_notes = Notes::default();
    let mut https = false;
    for address in &listen {
        match listener_address(address) {
            Some((addr, port)) => {
                let tls = port != ports.http && ((has_hosts && !auto_disabled) || has_policies);
                https |= tls;
                let lname = match (port, tls) {
                    (p, false) if p == ports.http => "web".to_owned(),
                    (p, true) if p == ports.https => "websecure".to_owned(),
                    (p, false) => format!("http-{p}"),
                    (p, true) => format!("https-{p}"),
                };
                let mut listener = json!({ "address": addr });
                if tls {
                    listener["tls"] = json!({});
                }
                run.listeners.insert(lname.clone(), listener);
                listener_names.push(lname.clone());
                listen_notes.exact(format!("`{address}` → listener `{lname}`{}", if tls { " (HTTPS)" } else { "" }));
            }
            None => listen_notes.manual(format!(
                "`{address}` is not an address ReverseDock listens on (a Unix socket, a port range or a network type): write the listener by hand"
            )),
        }
    }
    if https {
        // The automatic redirect of HTTP to HTTPS needs the HTTP listener.
        run.listeners
            .entry("web".to_owned())
            .or_insert_with(|| json!({ "address": format!(":{}", ports.http) }));
    }
    let mut sr = ServerRun {
        name,
        handled: HashMap::new(),
        sets: HashMap::new(),
        leaves: Vec::new(),
        unanswered: false,
        scopes: 0,
        overflow: false,
        named: fields
            .get("named_routes")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default(),
        https,
    };
    for (key, value) in fields {
        let pointer = format!("{base}/{key}");
        match key.as_str() {
            "listen" => {
                run.account(
                    Some(name),
                    &pointer,
                    listen_notes.finding("caddy.server", Some("listeners")),
                );
            }
            // Routes are run below; named routes are accounted as `invoke` uses them.
            "routes" | "named_routes" => {}
            "automatic_https" => super::tls::automatic_https(run, name, &pointer, value),
            "tls_connection_policies" => {
                super::tls::connection_policies(run, name, &pointer, value, &listener_names);
            }
            _ => server_setting(run, name, &pointer, key, value, &listener_names),
        }
    }
    let mut states = vec![State::default()];
    let rest = sr.exec(
        run,
        &routes,
        &format!("{base}/routes"),
        std::mem::take(&mut states),
    );
    if rest.iter().any(|s| !https || !s.hosts().is_empty()) {
        // Over HTTPS a request for a name no route has fails the TLS handshake in both.
        sr.unanswered = true;
    }
    for (rname, route) in sr.named.clone() {
        if !sr
            .handled
            .keys()
            .any(|k| k.starts_with(&format!("{base}/named_routes/{rname}/")))
        {
            let mut notes = Notes::default();
            notes.exact("a named route no `invoke` uses: nothing to migrate");
            let _ = route;
            run.account(
                Some(name),
                &format!("{base}/named_routes/{rname}"),
                notes.finding("caddy.server", None),
            );
        }
    }
    if sr.overflow {
        run.b.result(
            Finding::new(
                "caddy.server.manual",
                format!("server `{name}`: its routes have too many conditional handlers to follow every path (more than {MAX_STATES}); the routes from its later handlers are not written"),
            )
            .hint("split the configuration into fewer conditional handlers, or write the remaining routes by hand"),
        );
    }
    if sr.unanswered && !sr.leaves.is_empty() {
        run.defaults_changed.insert(
            "caddy.route.unanswered",
            "requests that no handler answers (for example a path a site does not handle) get an empty `200` from Caddy; ReverseDock answers `404`".to_owned(),
        );
    }
    write_leaves(run, &sr, &listener_names, https);
}

/// `:443`, `0.0.0.0:80`, `[::]:8443` → (listen address, port). Unix sockets, ranges and network
/// prefixes other than `tcp` are not listener addresses here.
fn listener_address(address: &str) -> Option<(String, u16)> {
    let address = address
        .strip_prefix("tcp/")
        .or_else(|| address.strip_prefix("tcp4/"))
        .or_else(|| address.strip_prefix("tcp6/"))
        .unwrap_or(address);
    if address.contains('/') {
        return None;
    }
    let (host, port) = address.rsplit_once(':')?;
    if port.contains('-') {
        return None;
    }
    let port: u16 = port.parse().ok()?;
    let host = if host == "[::]" || host == "0.0.0.0" {
        ""
    } else {
        host
    };
    Some((format!("{host}:{port}"), port))
}

/// A server setting other than listeners, routes and TLS.
#[allow(clippy::too_many_lines)] // one arm per server setting
fn server_setting(
    run: &mut Run<'_>,
    server: &str,
    pointer: &str,
    key: &str,
    value: &Value,
    listeners: &[String],
) {
    let mut notes = Notes::default();
    let mut target = None;
    match key {
        "read_timeout" | "read_header_timeout" | "write_timeout" | "idle_timeout" => {
            let field = match key {
                "read_timeout" => "read",
                "read_header_timeout" => "request_header",
                "write_timeout" => "write",
                _ => "idle",
            };
            match handlers::duration(value) {
                Some(d) => {
                    for l in listeners {
                        if let Some(listener) = run.listeners.get_mut(l) {
                            listener["timeouts"][field] = json!(d);
                        }
                    }
                    target = Some("listeners");
                    if key == "read_timeout" {
                        notes.approx(format!("written as the listeners' `timeouts.read: {d}`: Caddy bounds the whole request read, ReverseDock the wait for each piece of data"));
                    } else {
                        notes.exact(format!("written as the listeners' `timeouts.{field}: {d}`"));
                    }
                }
                None => notes.manual("not a duration"),
            }
        }
        "max_header_bytes" => match value.as_u64() {
            Some(n) => {
                run.security.insert("limits".to_owned(), json!({ "max_header_bytes": n }));
                target = Some("security.limits.max_header_bytes");
                notes.approx(format!("written as `security.limits.max_header_bytes: {n}` (with `--full`), which applies to every listener"));
            }
            None => notes.manual("not a number"),
        },
        "trusted_proxies" => {
            let ranges: Vec<Value> = value.get("ranges").and_then(Value::as_array).cloned().unwrap_or_default();
            if value.get("source").and_then(Value::as_str) == Some("static") && !ranges.is_empty() {
                run.security.insert("trusted_proxies".to_owned(), Value::Array(ranges));
                target = Some("security.trusted_proxies");
                notes.approx("written as `security.trusted_proxies` (with `--full`), which applies to every listener");
            } else {
                notes.manual("a trusted-proxies source other than a static list: write `security.trusted_proxies` by hand");
            }
        }
        "client_ip_headers" => {
            let first = value.as_array().and_then(|a| a.first()).and_then(Value::as_str).unwrap_or("");
            match first.to_ascii_lowercase().as_str() {
                "x-forwarded-for" => notes.exact("`X-Forwarded-For` is ReverseDock's default client-IP header"),
                "x-real-ip" => {
                    run.security.insert("client_ip_header".to_owned(), json!("x_real_ip"));
                    notes.approx("written as `security.client_ip_header: x_real_ip` (with `--full`)");
                }
                other => notes.manual(format!("client IP header `{other}` has no equivalent")),
            }
        }
        "logs" => {
            run.observability.insert("access_log".to_owned(), json!({ "enabled": true }));
            target = Some("observability.access_log");
            notes.approx("access logging is on: written as `observability.access_log.enabled: true` (with `--full`), global rather than per server; per-host logger names have no equivalent");
        }
        "protocols" | "listen_protocols" => {
            notes.approx("HTTP versions are per listener here (`listeners.<name>.http2`, `http3`); HTTP/1.1 and HTTP/2 are on by default");
        }
        "strict_sni_host" => notes.approx("ReverseDock checks that the Host matches the TLS server name where it matters (ADR-0014) without this switch"),
        "errors" => {
            notes.manual("error routes (`handle_errors`) are not migrated");
            notes.hint("for custom error pages, use the `errors` middleware (`status`, `file` or `service`)");
        }
        "metrics" => {
            notes.dropped("per-server metrics: ReverseDock's metrics are always on, served by the admin listener (`observability.metrics`)");
        }
        "listener_wrappers" => {
            let wrappers: Vec<&str> = value.as_array().map(|a| a.iter().filter_map(|w| w.get("wrapper").and_then(Value::as_str)).collect()).unwrap_or_default();
            for wrapper in wrappers {
                match wrapper {
                    "tls" | "http_redirect" => notes.exact(format!("`{wrapper}` is ReverseDock's behaviour")),
                    "proxy_protocol" => {
                        let allow: Vec<Value> = value.as_array().and_then(|a| a.iter().find(|w| w.get("wrapper").and_then(Value::as_str) == Some("proxy_protocol"))).and_then(|w| w.get("allow")).and_then(Value::as_array).cloned().unwrap_or_default();
                        if allow.is_empty() {
                            notes.manual("the PROXY protocol without an `allow` list: ReverseDock reads PROXY headers only from listed sources (`listeners.<name>.proxy_protocol.trusted`)");
                        } else {
                            for l in listeners {
                                if let Some(listener) = run.listeners.get_mut(l) {
                                    listener["proxy_protocol"] = json!({ "trusted": allow });
                                }
                            }
                            notes.exact("written as `proxy_protocol.trusted` on the listeners");
                        }
                    }
                    other => notes.manual(format!("listener wrapper `{other}` has no equivalent")),
                }
            }
            target = Some("listeners");
        }
        "keepalive_interval" | "enable_full_duplex" | "trusted_proxies_strict" | "keepalive_idle" | "keepalive_count" => {
            notes.dropped(format!("`{key}` has no equivalent; ReverseDock's behaviour is fixed"));
        }
        other => notes.dropped(format!("server setting `{other}` has no equivalent")),
    }
    let id = run.item(Some(server), pointer);
    run.b.account(id, notes.finding("caddy.server", target));
}

impl ServerRun<'_> {
    /// Runs a route list from `states`; returns the states that fall through it.
    #[allow(clippy::too_many_lines)] // one pass, in reading order
    fn exec(
        &mut self,
        run: &mut Run<'_>,
        routes: &[Value],
        pointer: &str,
        states: Vec<State>,
    ) -> Vec<State> {
        self.scopes += 1;
        let scope = self.scopes;
        let mut states = states;
        for (i, route) in routes.iter().enumerate() {
            let rp = format!("{pointer}/{i}");
            if self.overflow || states.is_empty() {
                // Still account for everything in the remaining routes.
                self.account_unreached(run, route, &rp);
                continue;
            }
            if let Some(fallback) = spa_idiom(route) {
                let mut notes = Notes::default();
                notes.approx(format!("the single-page-app `try_files` idiom → the `fallback: {fallback}` of the `static` middleware that follows; ReverseDock serves the fallback only for GET and HEAD requests whose last path segment has no `.`"));
                run.account(
                    Some(self.name),
                    &format!("{rp}/match/0/file"),
                    notes.finding("caddy.matcher", None),
                );
                let mut notes = Notes::default();
                notes.approx("part of the `try_files` idiom (see its matcher)");
                run.account(
                    Some(self.name),
                    &format!("{rp}/handle/0"),
                    notes.finding("caddy.handler", None),
                );
                for state in &mut states {
                    state.chain.push(Step::Spa(fallback.clone()));
                }
                continue;
            }
            let term = self.matcher(run, route, &rp);
            let group = route
                .get("group")
                .and_then(Value::as_str)
                .map(str::to_owned);
            let terminal = route
                .get("terminal")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let handlers = route
                .get("handle")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let mut next = Vec::new();
            for state in states {
                if let Some(g) = &group
                    && state.groups.contains(&(scope, g.clone()))
                {
                    next.push(state);
                    continue;
                }
                let Some(mut matched) = state.with(term.clone()) else {
                    next.push(state);
                    continue;
                };
                if !term.exact() {
                    matched
                        .blocked
                        .push(format!("a matcher at `{rp}/match` could not be translated"));
                }
                if state.rewritten && term.uses_uri() {
                    matched.blocked.push(format!("the matcher at `{rp}/match` sees the rewritten URI in Caddy, ReverseDock matches the request's own URI"));
                }
                if let Some(g) = &group {
                    matched.groups.insert((scope, g.clone()));
                }
                let before = self.leaves.len();
                let continuing =
                    self.handlers(run, &handlers, &format!("{rp}/handle"), vec![matched]);
                let answered = continuing.is_empty();
                let always = answered
                    && self.leaves[before..]
                        .iter()
                        .all(|l| l.state.blocked.is_empty() && !l.responder.is_blocked());
                if terminal {
                    if continuing
                        .iter()
                        .any(|s| !self.https || !s.hosts().is_empty())
                    {
                        self.unanswered = true;
                    }
                } else {
                    next.extend(continuing);
                }
                // A request this route matched never reaches the routes after it when the
                // route always answers; otherwise the routes after it exclude its matchers.
                if term.sets.is_empty() {
                    continue;
                }
                let unmatched = if always && term.exact() {
                    Some(state)
                } else {
                    let negated = Term {
                        sets: term.sets.clone(),
                        negated: true,
                    };
                    let rewritten = state.rewritten && term.uses_uri();
                    state.with(negated).map(|mut s| {
                        if !term.exact() {
                            s.blocked.push(format!("follows a matcher at `{rp}/match` that could not be translated"));
                        }
                        if rewritten {
                            s.blocked.push(format!("follows the matcher at `{rp}/match`, which sees the rewritten URI in Caddy"));
                        }
                        s
                    })
                };
                if let Some(mut s) = unmatched {
                    s.blocked.dedup();
                    next.push(s);
                }
            }
            if next.len() > MAX_STATES {
                self.overflow = true;
                next.clear();
            }
            states = next;
        }
        states
    }

    /// The handlers of one route, from `states`; returns the states that continue after them.
    fn handlers(
        &mut self,
        run: &mut Run<'_>,
        handlers: &[Value],
        pointer: &str,
        states: Vec<State>,
    ) -> Vec<State> {
        let mut states = states;
        for (j, handler) in handlers.iter().enumerate() {
            let hp = format!("{pointer}/{j}");
            if states.is_empty() || self.overflow {
                self.account_handler_tree(run, handler, &hp);
                continue;
            }
            let handled = self.handle(run, handler, &hp);
            match handled {
                Handled::Steps(steps) => {
                    for state in &mut states {
                        for step in &steps {
                            match step {
                                Step::Blocked(reason) => state.blocked.push(reason.clone()),
                                Step::Middleware { kind, .. }
                                    if [
                                        "strip-prefix",
                                        "add-prefix",
                                        "replace-path",
                                        "rewrite",
                                        "strip-suffix",
                                    ]
                                    .contains(&kind.as_str()) =>
                                {
                                    state.rewritten = true;
                                }
                                _ => {}
                            }
                        }
                        state.chain.extend(steps.iter().cloned());
                    }
                }
                Handled::Respond(steps, responder) => {
                    for mut state in std::mem::take(&mut states) {
                        state.chain.extend(steps.iter().cloned());
                        self.leaves.push(Leaf {
                            state,
                            responder: responder.clone(),
                        });
                    }
                }
                Handled::Subroute(routes) => {
                    states = self.exec(run, &routes, &format!("{hp}/routes"), states);
                }
                Handled::Invoke(name) => {
                    let route = self.named.get(&name).cloned();
                    match route {
                        Some(route) => {
                            let base = format!("/apps/http/servers/{}/named_routes", self.name);
                            states = self.exec(run, &[route], &base, states);
                        }
                        None => {
                            for state in &mut states {
                                state
                                    .blocked
                                    .push(format!("`invoke` of an unknown named route `{name}`"));
                            }
                        }
                    }
                }
                Handled::Nothing => {}
            }
        }
        states
    }

    /// The translation of one handler (accounted the first time it is seen).
    fn handle(&mut self, run: &mut Run<'_>, handler: &Value, pointer: &str) -> Handled {
        if let Some(handled) = self.handled.get(pointer) {
            return handled.clone();
        }
        let translated = handlers::handler(run, self.name, handler, pointer);
        self.handled.insert(pointer.to_owned(), translated.clone());
        translated
    }

    /// A route's matcher sets as one term (each set accounted the first time it is seen).
    fn matcher(&mut self, run: &mut Run<'_>, route: &Value, pointer: &str) -> Term {
        let sets = route
            .get("match")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut out = Vec::new();
        for (k, set) in sets.iter().enumerate() {
            let sp = format!("{pointer}/match/{k}");
            let translated = if let Some(s) = self.sets.get(&sp) {
                s.clone()
            } else {
                let s = handlers::matcher_set(run, self.name, set, &sp);
                self.sets.insert(sp.clone(), s.clone());
                s
            };
            out.push(translated);
        }
        Term {
            sets: out,
            negated: false,
        }
    }

    /// Accounts for the items of a route no path reaches.
    fn account_unreached(&mut self, run: &mut Run<'_>, route: &Value, pointer: &str) {
        let _ = self.matcher(run, route, pointer);
        if let Some(handlers) = route.get("handle").and_then(Value::as_array) {
            for (j, handler) in handlers.iter().enumerate() {
                self.account_handler_tree(run, handler, &format!("{pointer}/handle/{j}"));
            }
        }
    }

    fn account_handler_tree(&mut self, run: &mut Run<'_>, handler: &Value, pointer: &str) {
        if let Handled::Subroute(routes) = self.handle(run, handler, pointer) {
            for (i, route) in routes.iter().enumerate() {
                self.account_unreached(run, route, &format!("{pointer}/routes/{i}"));
            }
        }
    }
}

/// Writes the server's routes, highest priority first, in Caddy's order.
#[allow(clippy::too_many_lines)] // one pass, in reading order
fn write_leaves(run: &mut Run<'_>, sr: &ServerRun<'_>, listeners: &[String], https: bool) {
    let count = sr.leaves.len();
    for (index, leaf) in sr.leaves.iter().enumerate() {
        let state = &leaf.state;
        let mut blocked = state.blocked.clone();
        let mut middlewares = Vec::new();
        let mut max_body = None;
        let mut root: Option<String> = None;
        let mut spa: Option<String> = None;
        for step in &state.chain {
            match step {
                Step::Middleware { kind, value } => {
                    let label = state.label.first().map_or("site", String::as_str);
                    middlewares.push(run.middlewares.add(&[label, kind], value.clone()));
                }
                Step::MaxBody(size) => max_body = Some(size.clone()),
                Step::Root(r) => root = Some(r.clone()),
                Step::Spa(fallback) => spa = Some(fallback.clone()),
                Step::FileServer(config) => {
                    let label = state.label.first().map_or("site", String::as_str);
                    match handlers::static_config(config, root.as_deref(), spa.take(), true) {
                        Ok(value) => {
                            middlewares.push(run.middlewares.add(&[label, "static"], value));
                        }
                        Err(why) => blocked.push(why),
                    }
                }
                Step::Blocked(_) => {}
            }
        }
        let label: Vec<&str> = state.label.iter().map(String::as_str).collect();
        let mut route = Map::new();
        let mut service = None;
        match &leaf.responder {
            Responder::Service { kind, value } => {
                service = Some(run.services.add(&[kind.as_str()], value.clone()));
            }
            Responder::Redirect(value) => {
                let l = label.first().copied().unwrap_or("site");
                middlewares.push(run.middlewares.add(&[l, "redirect"], value.clone()));
                service = Some(
                    run.services
                        .add(&["not-found"], json!({ "respond": { "status": 404 } })),
                );
            }
            Responder::FileServer(config) => {
                let l = label.first().copied().unwrap_or("site");
                match handlers::static_config(config, root.as_deref(), spa.clone(), false) {
                    Ok(value) => middlewares.push(run.middlewares.add(&[l, "static"], value)),
                    Err(why) => {
                        blocked.push(why);
                        service = Some(
                            run.services
                                .add(&["not-found"], json!({ "respond": { "status": 404 } })),
                        );
                    }
                }
            }
            Responder::Blocked {
                reason,
                service: placeholder,
            } => {
                blocked.push(reason.clone());
                let parts: Vec<&str> = label.iter().copied().chain(["unmigrated"]).collect();
                service = Some(run.services.add(&parts, placeholder.clone()));
            }
        }
        if spa.is_some() && !matches!(leaf.responder, Responder::FileServer(_)) {
            blocked.push(
                "`try_files` rewrites to a fallback file before a handler other than `file_server`"
                    .to_owned(),
            );
        }
        let name_parts: Vec<&str> = if label.is_empty() {
            vec![sr.name]
        } else {
            label.clone()
        };
        let name = run.route_names.unique(&name_parts);
        let rule = state.rule();
        if rule.len() > rdock_rules::MAX_RULE_BYTES {
            blocked.push("its rule is longer than ReverseDock allows".to_owned());
        }
        route.insert("match".to_owned(), json!(rule));
        route.insert("listeners".to_owned(), json!(listeners));
        route.insert(
            "priority".to_owned(),
            json!(i64::try_from(count - index).unwrap_or(i64::MAX)),
        );
        if !middlewares.is_empty() {
            route.insert("middlewares".to_owned(), json!(middlewares));
        }
        if let Some(service) = service {
            route.insert("service".to_owned(), json!(service));
        }
        if let Some(size) = max_body {
            route.insert("max_body".to_owned(), json!(size));
        }
        if https {
            if let Some(tls) = run.tls.route_tls(sr.name, &state.hosts()) {
                route.insert("tls".to_owned(), tls);
            }
        } else {
            route.insert("tls".to_owned(), json!("off"));
        }
        blocked.dedup();
        if !blocked.is_empty() {
            route.insert("enabled".to_owned(), json!(false));
            run.disabled.push((name.clone(), blocked.join("; ")));
        }
        run.routes.insert(name, Value::Object(route));
    }
}

/// The route the Caddyfile's `try_files {path} … /index.html` adapts to: a `file` matcher whose
/// last candidate is a fixed file, and a rewrite to `{http.matchers.file.relative}`
/// (`parseTryFiles` in `modules/caddyhttp/fileserver/caddyfile.go` at v2.11.9). Returns the
/// fallback file.
fn spa_idiom(route: &Value) -> Option<String> {
    let sets = route.get("match")?.as_array()?;
    let [set] = sets.as_slice() else { return None };
    let set = set.as_object()?;
    if set.len() != 1 {
        return None;
    }
    let file = set.get("file")?.as_object()?;
    if file.keys().any(|k| k != "try_files" && k != "try_policy")
        || file
            .get("try_policy")
            .and_then(Value::as_str)
            .is_some_and(|p| p != "first_exist")
    {
        return None;
    }
    let tries: Vec<&str> = file
        .get("try_files")?
        .as_array()?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let (last, rest) = tries.split_last()?;
    if rest.is_empty()
        || rest
            .iter()
            .any(|t| *t != "{http.request.uri.path}" && *t != "{http.request.uri.path}/")
        || handlers::has_placeholder(last)
        || last.contains('?')
    {
        return None;
    }
    let handlers = route.get("handle")?.as_array()?;
    let [handler] = handlers.as_slice() else {
        return None;
    };
    if handler.get("handler")?.as_str()? != "rewrite"
        || handler.get("uri")?.as_str()? != "{http.matchers.file.relative}"
        || handler.as_object()?.len() != 2
    {
        return None;
    }
    Some(if last.starts_with('/') {
        (*last).to_owned()
    } else {
        format!("/{last}")
    })
}
