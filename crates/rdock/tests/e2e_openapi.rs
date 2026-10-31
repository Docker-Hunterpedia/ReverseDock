//! Conformance: every operation in the OpenAPI document is called against a running rdock,
//! and every answer must have a documented status and match its documented schema
//! (F-MGMT-01, ADR-0024).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use rdock_testkit::backend::Backend;
use rdock_testkit::free_port;
use rdock_testkit::rdock::Rdock;
use serde_json::{Value, json};

const RDOCK: &str = env!("CARGO_BIN_EXE_rdock");
const PASSWORD: &str = "harbor amber lantern seventeen";

/// One answer from the admin socket.
struct Answer {
    status: u16,
    head: String,
    body: String,
}

impl Answer {
    fn header(&self, name: &str) -> Option<&str> {
        self.head.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name).then(|| value.trim())
        })
    }

    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }
}

/// Sends one request over the admin socket. Streams are cut after their headers.
fn send(rdock: &Rdock, method: &str, path: &str, headers: &[(&str, &str)], body: &str) -> Answer {
    let mut stream = UnixStream::connect(rdock.data_dir().join("admin.sock")).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut request = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\n");
    for (name, value) in headers {
        let _ = write!(request, "{name}: {value}\r\n");
    }
    let _ = write!(
        request,
        "Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).unwrap();
    let mut raw = Vec::new();
    let mut chunk = [0_u8; 8192];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => raw.extend_from_slice(&chunk[..n]),
        }
    }
    let raw = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = raw.split_once("\r\n\r\n").unwrap_or((&raw, ""));
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    Answer {
        status,
        head: head.to_owned(),
        body: body.to_owned(),
    }
}

/// Checks answers against the document and remembers which operations were called.
struct Checker {
    document: Value,
    called: BTreeSet<(String, String)>,
    problems: Vec<String>,
}

impl Checker {
    fn new() -> Self {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../schema/openapi.json"
        ))
        .unwrap();
        Self {
            document: serde_json::from_str(&text).unwrap(),
            called: BTreeSet::new(),
            problems: Vec::new(),
        }
    }

    /// Calls `path` (concrete) as the operation `template` and checks the answer.
    fn call(
        &mut self,
        rdock: &Rdock,
        (method, template, path): (&str, &str, &str),
        headers: &[(&str, &str)],
        body: &str,
    ) -> Answer {
        let answer = send(rdock, method, path, headers, body);
        let key = method.to_ascii_lowercase();
        self.called.insert((key.clone(), template.to_owned()));
        let operation = &self.document["paths"][template][&key];
        if operation.is_null() {
            self.problems
                .push(format!("{method} {template} is not in the document"));
            return answer;
        }
        let mut response = operation["responses"][answer.status.to_string()].clone();
        if response.is_null() {
            self.problems.push(format!(
                "{method} {path}: status {} is not documented: {}",
                answer.status, answer.body
            ));
            return answer;
        }
        if let Some(target) = response["$ref"].as_str() {
            let name = target.trim_start_matches("#/components/responses/");
            response = self.document["components"]["responses"][name].clone();
        }
        let content = &response["content"];
        let Some(schema) = content["application/json"]["schema"].as_object() else {
            return answer;
        };
        let Ok(instance) = serde_json::from_str::<Value>(&answer.body) else {
            self.problems.push(format!(
                "{method} {path}: the body is not JSON: {}",
                answer.body
            ));
            return answer;
        };
        let mut schema = schema.clone();
        schema.insert("components".into(), self.document["components"].clone());
        let validator = jsonschema::validator_for(&Value::Object(schema)).unwrap();
        for error in validator.iter_errors(&instance) {
            self.problems.push(format!(
                "{method} {path} {}: {error} at {}",
                answer.status,
                error.instance_path()
            ));
        }
        answer
    }

    /// Fails with every problem, and with every documented operation that was not called.
    fn finish(self) {
        let mut problems = self.problems;
        for (path, item) in self.document["paths"].as_object().unwrap() {
            for method in item.as_object().unwrap().keys() {
                if !self.called.contains(&(method.clone(), path.clone())) {
                    problems.push(format!("{method} {path} was never called"));
                }
            }
        }
        assert!(problems.is_empty(), "{}", problems.join("\n"));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_documented_operation_answers_as_documented() {
    let backend = Backend::start("openapi-backend").await;
    let port = free_port();
    let config = format!(
        "listeners:\n  web: {{ address: \"127.0.0.1:{port}\" }}\ndefaults: {{ listeners: [web], tls: off }}\nroutes:\n  file: {{ match: \"Host(`file.test`)\", service: file }}\nservices:\n  file: {{ backends: [{{ address: \"{}\" }}] }}\nadmin:\n  listener: \"{{admin}}\"\n  mfa: optional\n",
        backend.addr
    );
    let rdock = Rdock::start(RDOCK, &config);
    let mut check = Checker::new();
    let json_type = ("Content-Type", "application/json");

    for path in ["/healthz", "/readyz", "/metrics", "/api/openapi.json"] {
        check.call(&rdock, ("GET", path, path), &[], "");
    }
    check.call(&rdock, ("GET", "/api/v1/setup", "/api/v1/setup"), &[], "");
    let admin = json!({ "name": "admin", "password": PASSWORD }).to_string();
    let created = check.call(
        &rdock,
        ("POST", "/api/v1/setup", "/api/v1/setup"),
        &[json_type],
        &admin,
    );
    assert_eq!(created.status, 201, "{}", created.body);

    session_operations(&rdock, &mut check, &admin);
    user_and_token_operations(&rdock, &mut check);
    config_operations(&rdock, &mut check, &backend.addr.to_string());
    resource_operations(&rdock, &mut check);
    check.finish();
}

/// The dashboard's session endpoints, logged in with a cookie.
fn session_operations(rdock: &Rdock, check: &mut Checker, admin: &str) {
    let json_type = ("Content-Type", "application/json");
    let login = check.call(
        rdock,
        ("POST", "/api/v1/auth/login", "/api/v1/auth/login"),
        &[json_type],
        admin,
    );
    assert_eq!(login.status, 200, "{}", login.body);
    let cookie = login
        .header("set-cookie")
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let csrf = login.json()["csrf_token"].as_str().unwrap().to_owned();
    let auth = [
        ("Cookie", cookie.as_str()),
        ("X-CSRF-Token", csrf.as_str()),
        json_type,
    ];
    let reauth = json!({ "password": PASSWORD }).to_string();
    for (method, path, body) in [
        ("GET", "/api/v1/auth/session", ""),
        ("GET", "/api/v1/auth/mfa", ""),
        ("POST", "/api/v1/auth/mfa", r#"{"code":"000000"}"#),
        ("POST", "/api/v1/auth/reauth", reauth.as_str()),
        ("POST", "/api/v1/auth/totp", ""),
        ("POST", "/api/v1/auth/totp/confirm", r#"{"code":"000000"}"#),
        ("POST", "/api/v1/auth/recovery-codes", ""),
        ("DELETE", "/api/v1/auth/totp", ""),
        ("GET", "/api/v1/auth/sessions", ""),
    ] {
        check.call(rdock, (method, path, path), &auth, body);
    }
    check.call(
        rdock,
        (
            "DELETE",
            "/api/v1/auth/sessions/{id}",
            "/api/v1/auth/sessions/missing",
        ),
        &auth,
        "",
    );
    check.call(
        rdock,
        ("POST", "/api/v1/auth/logout", "/api/v1/auth/logout"),
        &auth,
        "",
    );
}

fn user_and_token_operations(rdock: &Rdock, check: &mut Checker) {
    let json_type = [("Content-Type", "application/json")];
    check.call(rdock, ("GET", "/api/v1/users", "/api/v1/users"), &[], "");
    let user = json!({ "name": "viewer1", "role": "viewer", "password": PASSWORD }).to_string();
    check.call(
        rdock,
        ("POST", "/api/v1/users", "/api/v1/users"),
        &json_type,
        &user,
    );
    check.call(
        rdock,
        ("PATCH", "/api/v1/users/{name}", "/api/v1/users/viewer1"),
        &json_type,
        r#"{"disabled":true}"#,
    );
    check.call(
        rdock,
        ("DELETE", "/api/v1/users/{name}", "/api/v1/users/viewer1"),
        &[],
        "",
    );
    check.call(rdock, ("GET", "/api/v1/tokens", "/api/v1/tokens"), &[], "");
    let token = check.call(
        rdock,
        ("POST", "/api/v1/tokens", "/api/v1/tokens"),
        &json_type,
        r#"{"name":"ci","role":"viewer","expires_in_days":30}"#,
    );
    let id = token.json()["id"].as_str().unwrap_or("missing").to_owned();
    check.call(
        rdock,
        (
            "DELETE",
            "/api/v1/tokens/{id}",
            &format!("/api/v1/tokens/{id}"),
        ),
        &[],
        "",
    );
    check.call(
        rdock,
        ("GET", "/api/v1/audit", "/api/v1/audit?limit=5"),
        &[],
        "",
    );
}

fn config_operations(rdock: &Rdock, check: &mut Checker, backend: &str) {
    let json_type = ("Content-Type", "application/json");
    for path in [
        "/api/v1/status",
        "/api/v1/config",
        "/api/v1/config/history",
        "/api/v1/config/export",
    ] {
        check.call(rdock, ("GET", path, path), &[], "");
    }
    let document = json!({
        "routes": { "app": { "match": "Host(`api.test`)", "service": "app" } },
        "services": { "app": { "backends": [{ "address": backend }] } }
    })
    .to_string();
    check.call(
        rdock,
        ("POST", "/api/v1/config/validate", "/api/v1/config/validate"),
        &[json_type],
        &document,
    );
    let etag = |check: &mut Checker| {
        let read = check.call(
            rdock,
            ("GET", "/api/v1/config/api", "/api/v1/config/api"),
            &[],
            "",
        );
        read.header("etag").unwrap().to_owned()
    };
    let tag = etag(check);
    check.call(
        rdock,
        ("PUT", "/api/v1/config/api", "/api/v1/config/api"),
        &[json_type, ("If-Match", &tag)],
        &document,
    );
    let tag = etag(check);
    check.call(
        rdock,
        ("PATCH", "/api/v1/config/api", "/api/v1/config/api"),
        &[
            ("Content-Type", "application/merge-patch+json"),
            ("If-Match", &tag),
        ],
        r#"{"routes":{"app":{"priority":5}}}"#,
    );
    let history = send(rdock, "GET", "/api/v1/config/history", &[], "").json();
    let oldest = history.as_array().unwrap().last().unwrap()["id"].clone();
    let tag = etag(check);
    check.call(
        rdock,
        ("POST", "/api/v1/config/rollback", "/api/v1/config/rollback"),
        &[json_type, ("If-Match", &tag)],
        &json!({ "id": oldest }).to_string(),
    );
    let tag = etag(check);
    check.call(
        rdock,
        ("POST", "/api/v1/config/import", "/api/v1/config/import"),
        &[json_type, ("If-Match", &tag)],
        &json!({ "version": 1, "api": serde_json::from_str::<Value>(&document).unwrap() })
            .to_string(),
    );
    check.call(
        rdock,
        ("POST", "/api/v1/config/reload", "/api/v1/config/reload"),
        &[],
        "",
    );
    check.call(rdock, ("GET", "/api/v1/{kind}", "/api/v1/routes"), &[], "");
    check.call(
        rdock,
        ("GET", "/api/v1/{kind}/{name}", "/api/v1/routes/app@api"),
        &[],
        "",
    );
    let tag = etag(check);
    check.call(
        rdock,
        ("PUT", "/api/v1/{kind}/{name}", "/api/v1/routes/extra"),
        &[json_type, ("If-Match", &tag)],
        r#"{"match":"Host(`extra.test`)","service":"app@api"}"#,
    );
    let tag = etag(check);
    check.call(
        rdock,
        ("DELETE", "/api/v1/{kind}/{name}", "/api/v1/routes/extra"),
        &[("If-Match", &tag)],
        "",
    );
}

fn resource_operations(rdock: &Rdock, check: &mut Checker) {
    let json_type = [("Content-Type", "application/json")];
    for path in [
        "/api/v1/certificates",
        "/api/v1/backends",
        "/api/v1/providers",
        "/api/v1/listeners",
        "/api/v1/metrics/summary",
        "/api/v1/logs/stream",
        "/api/v1/events/stream",
    ] {
        check.call(rdock, ("GET", path, path), &[], "");
    }
    check.call(
        rdock,
        (
            "POST",
            "/api/v1/certificates/{name}/renew",
            "/api/v1/certificates/none.test/renew",
        ),
        &[],
        "",
    );
    let services = send(rdock, "GET", "/api/v1/backends", &[], "").json();
    let file = services
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["service"] == "file")
        .unwrap();
    let address = file["backends"][0]["address"].as_str().unwrap();
    let target = json!({ "service": "file", "backend": address }).to_string();
    for path in ["/api/v1/backends/drain", "/api/v1/backends/undrain"] {
        check.call(rdock, ("POST", path, path), &json_type, &target);
    }
    check.call(
        rdock,
        ("POST", "/api/v1/routes/explain", "/api/v1/routes/explain"),
        &json_type,
        r#"{"url":"http://file.test/"}"#,
    );
}
