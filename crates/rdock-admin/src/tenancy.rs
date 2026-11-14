//! Tenant-scoped callers (H-SEC-07, ADR-0031). A user or API token with a tenant reads and
//! writes only the API provider's routes, services and middlewares whose names start with the
//! tenant's prefix; what those objects may contain is checked by the configuration's own
//! validation (`rdock-model`, `tenants`), so an object under a tenant's prefix obeys its
//! tenant's rules whoever wrote it.
//!
//! Authorization **fails closed**: every operation a scoped caller may reach is listed in
//! [`OPERATIONS`] with how its handler limits the answer; anything not listed is refused with
//! 403 and audited. A test checks that every operation of the OpenAPI document is listed.

use std::sync::Arc;

use http::Method;
use serde_json::{Map, Value, json};

/// How an operation treats a tenant-scoped caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tenancy {
    /// Allowed; the handler limits reads and writes to the caller's tenant.
    Scoped,
    /// Allowed; it acts on the caller's own account or session only.
    Own,
    /// No caller is identified (health, setup, login); nothing to scope.
    Public,
    /// Refused with 403, for the reason given.
    Denied(&'static str),
}

const GLOBAL: &str = "a global setting or state, outside every tenant";
const PLANNED_TLS: &str = "certificates are global; tenant-owned certificates are planned";
const PLANNED_LISTENERS: &str = "listeners are global; tenant-owned listeners are planned";
const OTHERS: &str = "it would show other tenants' configuration";
const CONSUMERS: &str =
    "consumers and their keys are shared by every tenant; scoped callers cannot read or mint them";
const STREAMS: &str = "the streams carry every tenant's traffic and events";
const CLUSTER: &str = "the cluster is global";
const USERS: &str = "users are managed by an unscoped administrator";

/// Every operation of the admin API: `(method, path template, tenancy)`. Keep it in step
/// with `schema/openapi.json`; the test `every_documented_operation_is_classified` fails
/// when an operation is missing, and the server refuses a missing one anyway.
pub(crate) const OPERATIONS: &[(&str, &str, Tenancy)] = &[
    ("GET", "/healthz", Tenancy::Public),
    ("GET", "/readyz", Tenancy::Public),
    (
        "GET",
        "/metrics",
        Tenancy::Denied("a tenant label on the core metrics is planned"),
    ),
    ("GET", "/api/openapi.json", Tenancy::Public),
    ("GET", "/api/v1/setup", Tenancy::Public),
    ("POST", "/api/v1/setup", Tenancy::Public),
    ("POST", "/api/v1/auth/login", Tenancy::Public),
    ("POST", "/api/v1/auth/logout", Tenancy::Own),
    ("GET", "/api/v1/auth/session", Tenancy::Own),
    ("GET", "/api/v1/auth/mfa", Tenancy::Own),
    ("POST", "/api/v1/auth/mfa", Tenancy::Own),
    ("POST", "/api/v1/auth/password", Tenancy::Own),
    ("POST", "/api/v1/auth/reauth", Tenancy::Own),
    ("POST", "/api/v1/auth/recovery-codes", Tenancy::Own),
    ("GET", "/api/v1/auth/sessions", Tenancy::Own),
    ("DELETE", "/api/v1/auth/sessions/{id}", Tenancy::Own),
    ("POST", "/api/v1/auth/totp", Tenancy::Own),
    ("DELETE", "/api/v1/auth/totp", Tenancy::Own),
    ("POST", "/api/v1/auth/totp/confirm", Tenancy::Own),
    ("GET", "/api/v1/status", Tenancy::Denied(GLOBAL)),
    ("POST", "/api/v1/config/reload", Tenancy::Denied(GLOBAL)),
    ("POST", "/api/v1/upgrade", Tenancy::Denied(GLOBAL)),
    ("GET", "/api/v1/users", Tenancy::Denied(USERS)),
    ("POST", "/api/v1/users", Tenancy::Denied(USERS)),
    ("PATCH", "/api/v1/users/{name}", Tenancy::Denied(USERS)),
    ("DELETE", "/api/v1/users/{name}", Tenancy::Denied(USERS)),
    ("GET", "/api/v1/tokens", Tenancy::Scoped),
    ("POST", "/api/v1/tokens", Tenancy::Scoped),
    ("DELETE", "/api/v1/tokens/{id}", Tenancy::Scoped),
    ("GET", "/api/v1/audit", Tenancy::Scoped),
    ("GET", "/api/v1/config", Tenancy::Scoped),
    ("GET", "/api/v1/config/api", Tenancy::Scoped),
    ("PUT", "/api/v1/config/api", Tenancy::Scoped),
    ("PATCH", "/api/v1/config/api", Tenancy::Scoped),
    ("POST", "/api/v1/config/validate", Tenancy::Scoped),
    ("GET", "/api/v1/config/history", Tenancy::Denied(OTHERS)),
    ("POST", "/api/v1/config/rollback", Tenancy::Denied(OTHERS)),
    ("GET", "/api/v1/config/export", Tenancy::Denied(OTHERS)),
    ("POST", "/api/v1/config/import", Tenancy::Denied(OTHERS)),
    ("GET", "/api/v1/certificates", Tenancy::Denied(PLANNED_TLS)),
    (
        "POST",
        "/api/v1/certificates/{name}/renew",
        Tenancy::Denied(PLANNED_TLS),
    ),
    ("GET", "/api/v1/backends", Tenancy::Scoped),
    ("POST", "/api/v1/backends/drain", Tenancy::Scoped),
    ("POST", "/api/v1/backends/undrain", Tenancy::Scoped),
    ("GET", "/api/v1/providers", Tenancy::Denied(GLOBAL)),
    (
        "GET",
        "/api/v1/listeners",
        Tenancy::Denied(PLANNED_LISTENERS),
    ),
    ("GET", "/api/v1/metrics/summary", Tenancy::Scoped),
    ("POST", "/api/v1/routes/explain", Tenancy::Denied(OTHERS)),
    ("GET", "/api/v1/cache", Tenancy::Denied(GLOBAL)),
    (
        "POST",
        "/api/v1/cache/{store}/purge",
        Tenancy::Denied(GLOBAL),
    ),
    ("GET", "/api/v1/consumers", Tenancy::Denied(CONSUMERS)),
    (
        "GET",
        "/api/v1/consumers/{name}",
        Tenancy::Denied(CONSUMERS),
    ),
    (
        "PUT",
        "/api/v1/consumers/{name}",
        Tenancy::Denied(CONSUMERS),
    ),
    (
        "DELETE",
        "/api/v1/consumers/{name}",
        Tenancy::Denied(CONSUMERS),
    ),
    (
        "POST",
        "/api/v1/consumers/{name}/keys",
        Tenancy::Denied(CONSUMERS),
    ),
    (
        "DELETE",
        "/api/v1/consumers/{name}/keys/{id}",
        Tenancy::Denied(CONSUMERS),
    ),
    ("GET", "/api/v1/quota", Tenancy::Scoped),
    ("GET", "/api/v1/quota/{consumer}", Tenancy::Scoped),
    ("DELETE", "/api/v1/quota/{consumer}", Tenancy::Scoped),
    ("GET", "/api/v1/cluster/instances", Tenancy::Denied(CLUSTER)),
    (
        "POST",
        "/api/v1/cluster/instances/{name}/revoke",
        Tenancy::Denied(CLUSTER),
    ),
    ("POST", "/api/v1/cluster/tokens", Tenancy::Denied(CLUSTER)),
    ("GET", "/api/v1/cluster/revisions", Tenancy::Denied(CLUSTER)),
    (
        "POST",
        "/api/v1/cluster/revisions",
        Tenancy::Denied(CLUSTER),
    ),
    ("GET", "/api/v1/cluster/rollout", Tenancy::Denied(CLUSTER)),
    (
        "POST",
        "/api/v1/cluster/rollout/resume",
        Tenancy::Denied(CLUSTER),
    ),
    (
        "POST",
        "/api/v1/cluster/rollout/abandon",
        Tenancy::Denied(CLUSTER),
    ),
    ("GET", "/api/v1/abuse/bans", Tenancy::Scoped),
    ("DELETE", "/api/v1/abuse/bans/{key}", Tenancy::Scoped),
    ("GET", "/api/v1/logs/stream", Tenancy::Denied(STREAMS)),
    ("GET", "/api/v1/events/stream", Tenancy::Denied(STREAMS)),
    ("GET", "/api/v1/{kind}", Tenancy::Scoped),
    ("GET", "/api/v1/{kind}/{name}", Tenancy::Scoped),
    ("PUT", "/api/v1/{kind}/{name}", Tenancy::Scoped),
    ("DELETE", "/api/v1/{kind}/{name}", Tenancy::Scoped),
];

/// How `method` on the route `template` treats a scoped caller; unlisted operations are
/// refused.
pub(crate) fn classify(method: &Method, template: Option<&str>) -> Tenancy {
    let Some(template) = template else {
        return Tenancy::Denied("not an operation of the admin API");
    };
    // HEAD is answered like GET.
    let method = if method == Method::HEAD {
        "GET"
    } else {
        method.as_str()
    };
    OPERATIONS
        .iter()
        .find(|(m, t, _)| *m == method && *t == template)
        .map_or(
            Tenancy::Denied("not classified for tenant-scoped callers"),
            |(_, _, tenancy)| *tenancy,
        )
}

/// A resolved tenant scope: the tenant's name and object prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Scope {
    pub(crate) name: String,
    pub(crate) prefix: String,
}

/// The API sections a scoped caller may hold objects in.
pub(crate) const SECTIONS: [&str; 3] = ["routes", "services", "middlewares"];

impl Scope {
    /// Whether the bare API name `name` is the tenant's.
    pub(crate) fn owns_bare(&self, name: &str) -> bool {
        name.starts_with(&self.prefix) && !name.contains('@')
    }

    /// Whether `name` in the effective configuration (`x@api`) is one of the tenant's API
    /// objects. File and other providers' objects never are.
    pub(crate) fn owns_merged(&self, name: &str) -> bool {
        name.strip_suffix("@api")
            .is_some_and(|bare| bare.starts_with(&self.prefix))
    }

    /// Whether a name as given in a request path (`x` or `x@api`) is the tenant's.
    pub(crate) fn owns_requested(&self, name: &str) -> bool {
        self.owns_bare(name) || self.owns_merged(name)
    }

    /// The tenant's part of the API objects: its routes, services and middlewares.
    pub(crate) fn view(&self, api: &Value) -> Value {
        let mut out = Map::new();
        for section in SECTIONS {
            let objects: Map<String, Value> = api[section]
                .as_object()
                .map(|m| {
                    m.iter()
                        .filter(|(name, _)| self.owns_bare(name))
                        .map(|(n, v)| (n.clone(), v.clone()))
                        .collect()
                })
                .unwrap_or_default();
            out.insert(section.to_owned(), Value::Object(objects));
        }
        Value::Object(out)
    }

    /// The tenant's part of the effective configuration, with the owners of its objects.
    pub(crate) fn effective(&self, config: &Value) -> Value {
        let mut out = Map::new();
        for section in SECTIONS {
            let objects: Map<String, Value> = config[section]
                .as_object()
                .map(|m| {
                    m.iter()
                        .filter(|(name, _)| self.owns_merged(name))
                        .map(|(n, v)| (n.clone(), v.clone()))
                        .collect()
                })
                .unwrap_or_default();
            out.insert(section.to_owned(), Value::Object(objects));
        }
        Value::Object(out)
    }

    /// The version tag of the tenant's part: changes by other tenants do not touch it.
    pub(crate) fn etag(&self, api: &Value) -> String {
        let text = serde_json::to_vec(&self.view(api)).unwrap_or_default();
        let hash = ring::digest::digest(&ring::digest::SHA256, &text);
        format!("\"t-{}\"", crate::hex(&hash.as_ref()[..8]))
    }

    /// The whole API document with the tenant's part replaced by `candidate`, or why the
    /// candidate is refused (403): a section other than routes, services and middlewares, or
    /// an object outside the prefix.
    pub(crate) fn merge(&self, current: &Value, candidate: &Value) -> Result<Value, String> {
        let Some(sections) = candidate.as_object() else {
            return Err("the document is not a JSON object".to_owned());
        };
        if let Some(other) = sections.keys().find(|k| !SECTIONS.contains(&k.as_str())) {
            return Err(format!(
                "`{other}` is outside tenant `{}`: a tenant writes only routes, services and middlewares",
                self.name
            ));
        }
        let mut out = current.clone();
        if !out.is_object() {
            out = json!({});
        }
        for section in SECTIONS {
            let wanted = match candidate.get(section) {
                None | Some(Value::Null) => Map::new(),
                Some(Value::Object(map)) => map.clone(),
                Some(_) => return Err(format!("`{section}` is not an object")),
            };
            if let Some(name) = wanted.keys().find(|n| !self.owns_bare(n)) {
                return Err(format!(
                    "`{section}.{name}` is outside tenant `{}`: names start with `{}`",
                    self.name, self.prefix
                ));
            }
            let mut merged: Map<String, Value> = out[section]
                .as_object()
                .map(|m| {
                    m.iter()
                        .filter(|(name, _)| !self.owns_bare(name))
                        .map(|(n, v)| (n.clone(), v.clone()))
                        .collect()
                })
                .unwrap_or_default();
            merged.extend(wanted);
            out[section] = Value::Object(merged);
        }
        Ok(out)
    }

    /// A reload report as the tenant may see it: the outcome and the diagnostics about its
    /// own objects. The origin and other objects' diagnostics are left out without a trace
    /// (not even their number, which would show other tenants' activity).
    pub(crate) fn report(&self, report: &Value) -> Value {
        let all = report["diagnostics"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let mine: Vec<Value> = all
            .into_iter()
            .filter(|d| {
                d["path"]
                    .as_str()
                    .and_then(rdock_config::merge::owner)
                    .is_some_and(|(_, name)| self.owns_merged(&name) || self.owns_bare(&name))
            })
            .collect();
        let mut out = json!({
            "result": report["result"],
            "generation": report["generation"],
            "diagnostics": mine,
        });
        if report.get("error").is_some_and(|e| !e.is_null()) {
            out["error"] = json!("the configuration was rejected");
        }
        out
    }
}

/// `value[list]` with only the entries whose `middleware` is one of the tenant's (quota
/// counts, abuse bans).
pub(crate) fn by_middleware(scope: &Scope, mut value: Value, list: &str) -> Value {
    if let Some(items) = value[list].as_array_mut() {
        items.retain(|item| {
            item["middleware"]
                .as_str()
                .is_some_and(|m| scope.owns_merged(m))
        });
    }
    value
}

/// The caller's scope, when it has one.
pub(crate) type Scoped = Option<Arc<Scope>>;

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> Scope {
        Scope {
            name: "acme".into(),
            prefix: "acme-".into(),
        }
    }

    #[test]
    fn every_documented_operation_is_classified() {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../schema/openapi.json"
        ))
        .unwrap();
        let document: Value = serde_json::from_str(&text).unwrap();
        let mut missing = Vec::new();
        let mut documented = Vec::new();
        for (path, item) in document["paths"].as_object().unwrap() {
            for method in item.as_object().unwrap().keys() {
                let method = method.to_ascii_uppercase();
                documented.push((method.clone(), path.clone()));
                if !OPERATIONS.iter().any(|(m, t, _)| *m == method && t == path) {
                    missing.push(format!("{method} {path}"));
                }
            }
        }
        assert!(missing.is_empty(), "not classified: {missing:?}");
        for (m, t, _) in OPERATIONS {
            assert!(
                documented.iter().any(|(dm, dt)| dm == m && dt == t),
                "{m} {t} is classified but not documented"
            );
        }
    }

    #[test]
    fn unknown_operations_are_refused() {
        assert!(matches!(
            classify(&Method::GET, Some("/api/v1/new-thing")),
            Tenancy::Denied(_)
        ));
        assert!(matches!(classify(&Method::GET, None), Tenancy::Denied(_)));
        assert_eq!(
            classify(&Method::HEAD, Some("/api/v1/config/api")),
            Tenancy::Scoped
        );
        assert!(matches!(
            classify(&Method::POST, Some("/api/v1/config/api")),
            Tenancy::Denied(_)
        ));
    }

    #[test]
    fn a_tenant_sees_and_writes_only_its_prefix() {
        let s = scope();
        let api = json!({
            "routes": { "acme-web": { "x": 1 }, "globex-web": { "x": 2 }, "acmeweb": {} },
            "services": { "acme-svc": {} },
            "consumers": { "ann": {} }
        });
        let view = s.view(&api);
        assert_eq!(view["routes"], json!({ "acme-web": { "x": 1 } }));
        assert!(view.get("consumers").is_none());
        let merged = s
            .merge(&api, &json!({ "routes": { "acme-new": {} } }))
            .unwrap();
        assert_eq!(
            merged["routes"]["globex-web"],
            json!({ "x": 2 }),
            "others kept"
        );
        assert!(merged["routes"].get("acme-web").is_none(), "replaced");
        assert!(merged["routes"].get("acme-new").is_some());
        assert_eq!(
            merged["services"],
            json!({}),
            "the tenant's service was removed"
        );
        assert_eq!(merged["consumers"], json!({ "ann": {} }));
        assert!(
            s.merge(&api, &json!({ "routes": { "globex-x": {} } }))
                .is_err()
        );
        assert!(s.merge(&api, &json!({ "consumers": {} })).is_err());
        assert!(
            s.merge(&api, &json!({ "routes": { "acme-x@docker": {} } }))
                .is_err()
        );
        // Another tenant's change does not change this tenant's tag.
        let mut other = api.clone();
        other["routes"]["globex-web"] = json!({ "x": 3 });
        assert_eq!(s.etag(&api), s.etag(&other));
        assert!(s.owns_merged("acme-web@api") && !s.owns_merged("acme-web"));
        assert!(!s.owns_merged("acme-web@docker"));
    }

    #[test]
    fn reports_keep_only_the_tenants_diagnostics() {
        let report = json!({
            "result": "rejected", "generation": 3, "origin": { "path": "/etc/rdock/rdock.yaml" },
            "error": "the API configuration has errors",
            "diagnostics": [
                { "path": "routes[\"acme-web@api\"].match", "message": "not inside" },
                { "path": "routes[\"globex-web@api\"].service", "message": "secret detail" },
                { "path": "listeners.web", "message": "global" }
            ]
        });
        let out = scope().report(&report);
        assert_eq!(out["diagnostics"].as_array().unwrap().len(), 1);
        assert!(out.get("withheld").is_none(), "not even their number");
        assert!(out.get("origin").is_none());
        assert!(!out.to_string().contains("globex"));
    }
}
