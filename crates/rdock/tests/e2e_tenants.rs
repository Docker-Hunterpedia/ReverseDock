//! End-to-end: two tenants and an unscoped administrator share one proxy through the admin
//! API (H-SEC-07, ADR-0031). Each tenant writes routes under its prefix and host claims; every
//! cross-tenant read, write and reference, every host capture and every forbidden middleware
//! is refused and audited; the administrator sees everything; without `tenants` nothing is
//! scoped any more.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

use std::net::SocketAddr;

use rdock_testkit::backend::Backend;
use rdock_testkit::client::{self, get, request};
use rdock_testkit::free_port;
use rdock_testkit::rdock::Rdock;
use serde_json::{Value, json};

const RDOCK: &str = env!("CARGO_BIN_EXE_rdock");

fn config(port: u16, tenants: bool) -> String {
    let mut text = format!(
        "listeners:\n  web: {{ address: \"127.0.0.1:{port}\" }}\n\
         defaults: {{ listeners: [web], tls: off }}\n\
         middlewares:\n  compress: {{ type: compress }}\n  secret-auth: {{ type: basic_auth, users: [\"ann:$2y$05$abcdefghijklmnopqrstuuOJ5V1F1yB8x3B0N2iJ9GxZQx7lYd4mG\"] }}\n"
    );
    if tenants {
        text.push_str(
            "tenants:\n\
             \x20 acme:\n    hosts: [\"acme.test\", \"*.acme.test\"]\n    shared: { middlewares: [compress] }\n    backend_networks: [127.0.0.1/32]\n\
             \x20 globex:\n    hosts: [\"globex.test\"]\n    shared: { middlewares: [compress] }\n    backend_networks: [127.0.0.1/32]\n",
        );
    }
    text
}

struct Api<'a> {
    rdock: &'a Rdock,
}

impl Api<'_> {
    fn token(&self, role: &str, tenant: Option<&str>) -> String {
        let mut body = json!({ "name": format!("{role} {tenant:?}"), "role": role });
        if let Some(t) = tenant {
            body["tenant"] = json!(t);
        }
        let (status, _, text) = self
            .rdock
            .admin_send(
                "POST",
                "/api/v1/tokens",
                &[("Content-Type", "application/json")],
                &body.to_string(),
            )
            .unwrap();
        assert_eq!(status, 201, "{text}");
        serde_json::from_str::<Value>(&text).unwrap()["token"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    async fn call(
        &self,
        token: &str,
        method: &str,
        path: &str,
        if_match: Option<&str>,
        body: &Value,
    ) -> client::Reply {
        let text = if body.is_null() {
            String::new()
        } else {
            body.to_string()
        };
        let mut req = request(method, "127.0.0.1", path, text);
        let headers = req.headers_mut();
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());
        headers.insert("content-type", "application/json".parse().unwrap());
        if let Some(tag) = if_match {
            headers.insert("if-match", tag.parse().unwrap());
        }
        client::http1(self.rdock.admin, req).await
    }

    /// The caller's version tag of the API objects.
    async fn tag(&self, token: &str) -> String {
        let reply = self
            .call(token, "GET", "/api/v1/config/api", None, &Value::Null)
            .await;
        assert_eq!(reply.status, 200, "{}", reply.text());
        reply.header("etag").unwrap().to_owned()
    }

    /// Replaces the caller's part of the API objects.
    async fn put(&self, token: &str, document: &Value) -> client::Reply {
        let tag = self.tag(token).await;
        self.call(token, "PUT", "/api/v1/config/api", Some(&tag), document)
            .await
    }
}

fn site(name: &str, host: &str, backend: SocketAddr) -> Value {
    json!({
        "routes": { format!("{name}-web"): { "match": format!("Host(`{host}`)"), "service": format!("{name}-svc"), "middlewares": ["compress"] } },
        "services": { format!("{name}-svc"): { "backends": [{ "address": backend.to_string() }] } }
    })
}

fn with_extra(mut base: Value, section: &str, name: &str, object: Value) -> Value {
    base[section][name] = object;
    base
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tenants_stay_inside_their_prefix_and_claims() {
    let acme_backend = Backend::start("acme").await;
    let globex_backend = Backend::start("globex").await;
    let port = free_port();
    let rdock = Rdock::start(RDOCK, &config(port, true));
    let proxy = SocketAddr::from(([127, 0, 0, 1], port));
    let api = Api { rdock: &rdock };
    let acme = api.token("operator", Some("acme"));
    let acme_admin = api.token("admin", Some("acme"));
    let globex = api.token("operator", Some("globex"));
    let root = api.token("admin", None);

    // Each tenant writes its site under its prefix and claims; both are served.
    let acme_site = site("acme", "shop.acme.test", acme_backend.addr);
    let reply = api.put(&acme, &acme_site).await;
    assert_eq!(reply.status, 200, "{}\n{}", reply.text(), rdock.log());
    let globex_site = site("globex", "globex.test", globex_backend.addr);
    let reply = api.put(&globex, &globex_site).await;
    assert_eq!(reply.status, 200, "{}", reply.text());
    let served = client::http1(proxy, get("shop.acme.test", "/")).await;
    assert_eq!(served.status, 200);
    assert_eq!(served.header("x-backend"), Some("acme"), "{served:?}");
    let served = client::http1(proxy, get("globex.test", "/")).await;
    assert_eq!(served.header("x-backend"), Some("globex"));

    // Reads: each tenant sees its own objects only; the administrator sees both.
    let mine = api
        .call(&acme, "GET", "/api/v1/config/api", None, &Value::Null)
        .await
        .text();
    assert!(
        mine.contains("acme-web") && !mine.contains("globex"),
        "{mine}"
    );
    let effective = api
        .call(&acme, "GET", "/api/v1/config", None, &Value::Null)
        .await
        .text();
    assert!(
        !effective.contains("globex") && !effective.contains("secret-auth"),
        "{effective}"
    );
    let sections: Vec<String> = serde_json::from_str::<Value>(&effective).unwrap()["config"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    assert_eq!(
        sections,
        ["middlewares", "routes", "services"],
        "nothing global"
    );
    let all = api
        .call(&root, "GET", "/api/v1/config/api", None, &Value::Null)
        .await
        .text();
    assert!(
        all.contains("acme-web") && all.contains("globex-web"),
        "{all}"
    );

    // Cross-tenant reads and writes: 403.
    for (method, path) in [
        ("GET", "/api/v1/routes/globex-web@api"),
        ("GET", "/api/v1/middlewares/secret-auth"),
        ("DELETE", "/api/v1/routes/globex-web"),
        ("GET", "/api/v1/config/history"),
        ("GET", "/api/v1/listeners"),
        ("GET", "/api/v1/certificates"),
        ("GET", "/api/v1/consumers"),
        ("GET", "/api/v1/status"),
        ("POST", "/api/v1/routes/explain"),
    ] {
        let tag = api.tag(&acme).await;
        let reply = api.call(&acme, method, path, Some(&tag), &json!({})).await;
        assert_eq!(reply.status, 403, "{method} {path}: {}", reply.text());
    }
    let reply = api
        .put(
            &acme,
            &with_extra(
                acme_site.clone(),
                "routes",
                "globex-web",
                json!({ "match": "Host(`shop.acme.test`)", "service": "acme-svc" }),
            ),
        )
        .await;
    assert_eq!(
        reply.status,
        403,
        "a name under another prefix: {}",
        reply.text()
    );
    let reply = api
        .call(&acme_admin, "GET", "/api/v1/users", None, &Value::Null)
        .await;
    assert_eq!(reply.status, 403);
    let reply = api
        .call(&acme_admin, "GET", "/metrics", None, &Value::Null)
        .await;
    assert_eq!(reply.status, 403);

    // References, host captures and forbidden middlewares: 422 from validation.
    let refusals: Vec<(&str, Value)> = vec![
        (
            "a reference to the other tenant's service",
            with_extra(
                acme_site.clone(),
                "routes",
                "acme-steal",
                json!({ "match": "Host(`a.acme.test`)", "service": "globex-svc" }),
            ),
        ),
        (
            "a reference to an unshared file middleware",
            with_extra(
                acme_site.clone(),
                "routes",
                "acme-auth",
                json!({ "match": "Host(`b.acme.test`)", "service": "acme-svc", "middlewares": ["secret-auth"] }),
            ),
        ),
        (
            "the other tenant's host",
            with_extra(
                acme_site.clone(),
                "routes",
                "acme-capture",
                json!({ "match": "Host(`globex.test`)", "service": "acme-svc" }),
            ),
        ),
        (
            "a broader wildcard",
            with_extra(
                acme_site.clone(),
                "routes",
                "acme-wide",
                json!({ "match": "Host(`*.test`)", "service": "acme-svc" }),
            ),
        ),
        (
            "a rule that could match any host",
            with_extra(
                acme_site.clone(),
                "routes",
                "acme-any",
                json!({ "match": "Host(`c.acme.test`) || PathPrefix(`/`)", "service": "acme-svc" }),
            ),
        ),
        (
            "a look-alike host",
            with_extra(
                acme_site.clone(),
                "routes",
                "acme-evil",
                json!({ "match": "Host(`evil-acme.test`)", "service": "acme-svc" }),
            ),
        ),
        (
            "forward_auth",
            with_extra(
                acme_site.clone(),
                "middlewares",
                "acme-fa",
                json!({ "type": "forward_auth", "address": "http://127.0.0.1:9/check" }),
            ),
        ),
        (
            "static files",
            with_extra(
                acme_site.clone(),
                "middlewares",
                "acme-files",
                json!({ "type": "static", "root": "/etc" }),
            ),
        ),
        (
            "an environment reference",
            with_extra(
                acme_site.clone(),
                "middlewares",
                "acme-hdr",
                json!({ "type": "headers", "request": { "set": { "x-k": "${env:HOME}" } } }),
            ),
        ),
        (
            "a backend outside its networks",
            with_extra(
                acme_site.clone(),
                "services",
                "acme-far",
                json!({ "backends": [{ "address": "10.9.9.9:80" }] }),
            ),
        ),
    ];
    for (what, document) in &refusals {
        // Configuration writes share a budget of 5 a second (ADR-0024).
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        let reply = api.put(&acme, document).await;
        assert_eq!(reply.status, 422, "{what}: {}", reply.text());
        let text = reply.text();
        assert!(
            !text.contains("globex-web") && !text.contains("rdock.yaml"),
            "{what} leaks: {text}"
        );
    }
    let served = client::http1(proxy, get("globex.test", "/")).await;
    assert_eq!(
        served.header("x-backend"),
        Some("globex"),
        "nothing was captured"
    );

    // Every refusal is audited, with the tenant; a tenant reads only its own records.
    let (_, _, records) = rdock
        .admin_send("GET", "/api/v1/audit?limit=1000", &[], "")
        .unwrap();
    let records: Value = serde_json::from_str(&records).unwrap();
    let refused = |result: &str| {
        records
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["tenant"] == "acme" && r["result"] == result)
            .count()
    };
    assert!(refused("denied") >= 12, "{records}");
    assert!(refused("failed") >= refusals.len(), "{records}");
    let own = api
        .call(
            &acme_admin,
            "GET",
            "/api/v1/audit?limit=1000",
            None,
            &Value::Null,
        )
        .await
        .json();
    assert!(
        own.as_array()
            .unwrap()
            .iter()
            .all(|r| r["tenant"] == "acme")
    );

    // The administrator may write anything, but an object under a tenant's prefix still obeys
    // the tenant's rules, whoever writes it.
    let tag = api.tag(&root).await;
    let mut everything: Value = serde_json::from_str(&all).unwrap();
    everything["routes"]["acme-wide"] = json!({ "match": "Host(`*.test`)", "service": "acme-svc" });
    let reply = api
        .call(&root, "PUT", "/api/v1/config/api", Some(&tag), &everything)
        .await;
    assert_eq!(reply.status, 422, "{}", reply.text());

    // Without `tenants`, nothing is scoped: the scoped token is refused (its tenant is gone)
    // and the same write is accepted, as before tenants existed.
    rdock.write_config(&config(port, false));
    let (status, report) = rdock.reload();
    assert_eq!(status, 200, "{report}");
    let reply = api
        .call(&acme, "GET", "/api/v1/config/api", None, &Value::Null)
        .await;
    assert_eq!(
        reply.status,
        403,
        "a token of a tenant that no longer exists: {}",
        reply.text()
    );
    let tag = api.tag(&root).await;
    let reply = api
        .call(&root, "PUT", "/api/v1/config/api", Some(&tag), &everything)
        .await;
    assert_eq!(reply.status, 200, "{}", reply.text());
    assert_eq!(
        client::http1(proxy, get("other.test", "/"))
            .await
            .header("x-backend"),
        Some("acme")
    );
}
