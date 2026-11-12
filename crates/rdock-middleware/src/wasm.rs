//! `wasm`: a sandboxed WebAssembly plugin (F-EXT-03, ADR-0030). **Experimental.**
//!
//! Loading reads the file, checks its SHA-256 pin and its minisign signature, and only then
//! compiles it and checks it against the `rdock:plugin/filter` world and the granted
//! capabilities (`rdock-wasm`). Each request gets a fresh instance in this middleware's state
//! slot, used for the request phase and kept for the response phase. A failed call (fuel,
//! deadline, memory, trap, an invalid result) is counted in
//! `rdock_wasm_failures_total{middleware, reason}`, logged, and follows `on_error`.
//!
//! Without the `wasm` cargo feature the middleware is a stand-in that is never served: the
//! proxy's gate refuses the configuration in `rdock run` and warns in `rdock validate`.

/// Whether this build runs WASM plugins (the `wasm` cargo feature).
pub const ENABLED: bool = rdock_wasm::ENABLED;

/// What a configuration using `type: wasm` is told by a build without the feature.
pub const DISABLED_MESSAGE: &str =
    "this build does not include WASM plugins; build with --features wasm";

#[cfg(not(feature = "wasm"))]
pub(crate) use disabled::WasmMiddleware;
#[cfg(feature = "wasm")]
pub(crate) use enabled::WasmMiddleware;

#[cfg(not(feature = "wasm"))]
mod disabled {
    use async_trait::async_trait;
    use pingora::http::RequestHeader;

    use crate::{BuildError, Context, Flow, Middleware, Reply};

    /// A stand-in; the gate keeps it from ever being served.
    #[derive(Debug)]
    pub(crate) struct WasmMiddleware;

    impl WasmMiddleware {
        #[allow(
            clippy::unnecessary_wraps,
            reason = "the same signature as the build with the `wasm` feature"
        )]
        pub(crate) fn build(
            _name: &str,
            _config: &rdock_model::middleware::WasmConfig,
            _metrics: Option<&rdock_observability::Metrics>,
        ) -> Result<Self, BuildError> {
            Ok(Self)
        }
    }

    #[async_trait]
    impl Middleware for WasmMiddleware {
        async fn request(&self, _req: &mut RequestHeader, _cx: &mut Context) -> Flow {
            Flow::Reply(Reply::status(500))
        }
    }
}

#[cfg(feature = "wasm")]
mod enabled {
    use std::sync::Arc;

    use async_trait::async_trait;
    use bytes::Bytes;
    use http::HeaderName;
    use pingora::http::{RequestHeader, ResponseHeader};
    use rdock_model::middleware::{AgentOnError, WasmCapability, WasmConfig};
    use rdock_plugin_api as api;
    use rdock_wasm::artifact::{self, LoadError};
    use rdock_wasm::{CallError, Facts, Grants, Instance, Limits, Plugin, Settings};

    use crate::phase::{Capabilities, Phases};
    use crate::plugin::{apply_request, apply_response, reply, request_view};
    use crate::{BuildError, Context, Flow, Issue, Middleware, Reply};

    /// The body of a `500` sent because a plugin failed.
    const FAILED_BODY: &[u8] = b"Internal Server Error\n";

    /// A WASM plugin as a middleware.
    pub(crate) struct WasmMiddleware {
        name: Arc<str>,
        plugin: Plugin,
        on_error: AgentOnError,
        metrics: Option<rdock_observability::Metrics>,
    }

    impl std::fmt::Debug for WasmMiddleware {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("WasmMiddleware")
                .field("name", &self.name)
                .field("on_error", &self.on_error)
                .finish_non_exhaustive()
        }
    }

    fn load_issue(e: &LoadError) -> Issue {
        let path = match e {
            LoadError::Read { .. } | LoadError::TooLarge { .. } => "path".to_owned(),
            LoadError::InvalidPin | LoadError::DigestMismatch { .. } => "sha256".to_owned(),
            LoadError::Key { index, .. } => format!("trusted_keys[{index}]"),
            LoadError::NoTrustedKeys => "trusted_keys".to_owned(),
            _ => "signature".to_owned(),
        };
        let issue = Issue::new(path, e.to_string());
        match e {
            LoadError::DigestMismatch { .. } => issue.with_hint(
                "the file changed: check where it came from, then update `sha256` (`sha256sum <file>`)",
            ),
            LoadError::MissingSignature { .. } => issue.with_hint(
                "sign it with `minisign -S -m <file>`, or set `signature` to where the signature is",
            ),
            _ => issue,
        }
    }

    impl WasmMiddleware {
        pub(crate) fn build(
            name: &str,
            config: &WasmConfig,
            metrics: Option<&rdock_observability::Metrics>,
        ) -> Result<Self, BuildError> {
            let source = artifact::Source {
                path: &config.path,
                sha256: &config.sha256,
                signature: config.signature.as_deref(),
                trusted_keys: &config.trusted_keys,
                allow_unsigned: config.allow_unsigned,
            };
            let verified =
                artifact::load(&source).map_err(|e| BuildError::Issues(vec![load_issue(&e)]))?;
            if let Some(key) = &verified.signer {
                tracing::debug!(
                    middleware = name,
                    path = %config.path.display(),
                    key = %key,
                    "WASM module signature verified"
                );
            } else {
                tracing::warn!(
                    middleware = name,
                    path = %config.path.display(),
                    "running an unsigned WASM module (allow_unsigned: true)"
                );
            }
            let has = |c| config.capabilities.contains(&c);
            let settings = Settings {
                name: name.to_owned(),
                limits: Limits {
                    fuel: config.fuel,
                    timeout: config.timeout.as_std(),
                    memory: config.memory.as_u64(),
                },
                grants: Grants {
                    log: has(WasmCapability::Log),
                    clock: has(WasmCapability::Clock),
                    random: has(WasmCapability::Random),
                },
                config: serde_json::Value::Object(config.config.clone()).to_string(),
            };
            let plugin = Plugin::compile(&verified.bytes, &settings)
                .map_err(|e| BuildError::Issues(vec![Issue::new("path", e.to_string())]))?;
            Ok(Self {
                name: Arc::from(name),
                plugin,
                on_error: config.on_error,
                metrics: metrics.cloned(),
            })
        }

        fn failed(&self, phase: &str, e: &CallError) {
            if let Some(m) = &self.metrics {
                m.wasm_failures
                    .with_label_values(&[&*self.name, e.reason()])
                    .inc();
            }
            let action = match self.on_error {
                AgentOnError::Deny => "answered with 500",
                AgentOnError::Allow => "passed on unchanged (on_error: allow)",
            };
            tracing::warn!(
                middleware = %self.name,
                phase,
                error = %e,
                "a WASM plugin call failed; {action}"
            );
        }

        /// This request's instance, created on first use.
        fn instance<'c>(&self, cx: &'c mut Context) -> Result<&'c mut Instance, CallError> {
            if cx.state::<Instance>().is_none() {
                cx.set_state(self.plugin.instantiate()?);
            }
            cx.state_mut::<Instance>()
                .ok_or_else(|| CallError::Trap("no instance".into()))
        }
    }

    /// Marks a request whose `on-request` failed: its instance is gone (a trapped instance
    /// cannot be entered again) and the response phase is skipped, so a failure is counted
    /// once.
    struct Failed;

    impl WasmMiddleware {}

    fn internal_error() -> Reply {
        Reply {
            status: 500,
            headers: vec![(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("text/plain; charset=utf-8"),
            )],
            body: Some(crate::Body::Bytes(Bytes::from_static(FAILED_BODY))),
            problem: None,
            extensions: None,
        }
    }

    /// The facts a plugin sees, copied out of the context so the instance can borrow it.
    struct OwnedFacts {
        client_ip: std::net::IpAddr,
        route: Arc<str>,
        request_id: Arc<str>,
        tls: bool,
        consumer: Option<Arc<str>>,
    }

    impl OwnedFacts {
        fn of(cx: &Context) -> Self {
            Self {
                client_ip: cx.client_ip,
                route: cx.route.clone(),
                request_id: cx.request_id.clone(),
                tls: cx.tls,
                consumer: cx.consumer.as_ref().map(|c| c.name.clone()),
            }
        }

        fn view(&self) -> Facts<'_> {
            Facts {
                client_ip: self.client_ip,
                route: &self.route,
                request_id: &self.request_id,
                tls: self.tls,
                consumer: self.consumer.as_deref(),
            }
        }
    }

    #[async_trait]
    impl Middleware for WasmMiddleware {
        fn capabilities(&self) -> Capabilities {
            Capabilities::new(Phases::REQUEST | Phases::RESPONSE).with_state()
        }

        async fn request(&self, req: &mut RequestHeader, cx: &mut Context) -> Flow {
            let facts = OwnedFacts::of(cx);
            let mut view = request_view(req);
            let result = self
                .instance(cx)
                .and_then(|instance| instance.on_request(&facts.view(), &mut view));
            match result {
                Ok(Some(response)) => Flow::Reply(reply(response)),
                Ok(None) => {
                    apply_request(&view, req);
                    Flow::Next
                }
                Err(e) => {
                    let _ = cx.take_state::<Instance>();
                    cx.set_state(Failed);
                    self.failed("request", &e);
                    match self.on_error {
                        AgentOnError::Deny => Flow::Reply(internal_error()),
                        AgentOnError::Allow => Flow::Next,
                    }
                }
            }
        }

        async fn response(&self, resp: &mut ResponseHeader, cx: &mut Context) {
            if cx.take_state::<Failed>().is_some() {
                return;
            }
            let facts = OwnedFacts::of(cx);
            let mut view =
                api::ResponseHead::from_parts(resp.status, resp.version, resp.headers.clone());
            let result = self
                .instance(cx)
                .and_then(|instance| instance.on_response(&facts.view(), &mut view));
            // The instance has served its request.
            let _ = cx.take_state::<Instance>();
            match result {
                Ok(()) => apply_response(&view, resp),
                Err(e) => {
                    self.failed("response", &e);
                    if self.on_error == AgentOnError::Allow {
                        return;
                    }
                    // The head has not left yet: the client gets a 500 instead.
                    let names: Vec<HeaderName> = resp.headers.keys().cloned().collect();
                    for name in names {
                        resp.remove_header(&name);
                    }
                    let _ = resp.set_status(500);
                    let _ =
                        resp.insert_header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8");
                    let _ = resp.set_content_length(FAILED_BODY.len());
                    cx.compression = None;
                    cx.replace_body = Some(Bytes::from_static(FAILED_BODY));
                }
            }
        }
    }

    #[cfg(test)]
    #[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    mod tests {
        use super::*;
        use crate::test_support::{cx, request};
        use rdock_wasm::testing::{self, Guest, TestKey};

        struct Fixture {
            _dir: tempfile::TempDir,
            config: WasmConfig,
        }

        fn fixture(guest: &Guest<'_>, extra: serde_json::Value) -> Fixture {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("plugin.wat");
            let wat = guest.wat();
            std::fs::write(&path, &wat).unwrap();
            let key = TestKey::new(3);
            std::fs::write(
                rdock_wasm::artifact::default_signature_path(&path),
                key.sign(wat.as_bytes(), true),
            )
            .unwrap();
            let mut value = serde_json::json!({
                "path": path,
                "sha256": rdock_wasm::artifact::sha256_hex(wat.as_bytes()),
                "trusted_keys": [key.public()],
            });
            if let serde_json::Value::Object(extra) = extra {
                value.as_object_mut().unwrap().extend(extra);
            }
            Fixture {
                config: serde_json::from_value(value).unwrap(),
                _dir: dir,
            }
        }

        fn build(f: &Fixture) -> Result<WasmMiddleware, Vec<Issue>> {
            WasmMiddleware::build("w", &f.config, None).map_err(|e| match e {
                BuildError::Issues(issues) => issues,
                other => panic!("{other}"),
            })
        }

        #[tokio::test]
        async fn edits_the_request_and_the_response() {
            let f = fixture(&Guest::header(), serde_json::Value::Null);
            let m = build(&f).unwrap();
            let mut cx = cx();
            let mut req = request("GET", "/", &[]);
            assert!(matches!(m.request(&mut req, &mut cx).await, Flow::Next));
            assert_eq!(req.headers["x-wasm"], "yes");
            let mut resp = ResponseHeader::build(200, None).unwrap();
            m.response(&mut resp, &mut cx).await;
            assert_eq!(resp.headers["x-wasm-response"], "yes");
            assert!(cx.state::<Instance>().is_none(), "the instance is dropped");
        }

        #[tokio::test]
        async fn answers_with_the_plugins_reply() {
            let f = fixture(&Guest::header(), serde_json::Value::Null);
            let m = build(&f).unwrap();
            let mut req = request("GET", "/blocked", &[]);
            let Flow::Reply(reply) = m.request(&mut req, &mut cx()).await else {
                panic!("expected a reply");
            };
            assert_eq!(reply.status, 403);
        }

        #[tokio::test]
        async fn a_failing_plugin_fails_closed_by_default() {
            let guest = Guest {
                on_request: testing::TRAP,
                on_response: testing::TRAP,
                ..Guest::default()
            };
            let f = fixture(&guest, serde_json::Value::Null);
            let m = build(&f).unwrap();
            let Flow::Reply(reply) = m.request(&mut request("GET", "/", &[]), &mut cx()).await
            else {
                panic!("expected a 500");
            };
            assert_eq!(reply.status, 500);
            // After a failed `on-request` the response phase is skipped (counted once).
            let mut failed = cx();
            let _ = m.request(&mut request("GET", "/", &[]), &mut failed).await;
            let mut resp = ResponseHeader::build(200, None).unwrap();
            m.response(&mut resp, &mut failed).await;
            assert_eq!(resp.status, 200);
            // A response phase on its own still fails closed.
            let mut cx = cx();
            let mut resp = ResponseHeader::build(200, None).unwrap();
            resp.insert_header("x-backend", "secret").unwrap();
            m.response(&mut resp, &mut cx).await;
            assert_eq!(resp.status, 500);
            assert!(resp.headers.get("x-backend").is_none());
            assert_eq!(cx.replace_body.as_deref(), Some(FAILED_BODY));
        }

        #[tokio::test]
        async fn on_error_allow_passes_requests_on() {
            let guest = Guest {
                on_request: testing::LOOP,
                ..Guest::default()
            };
            let f = fixture(
                &guest,
                serde_json::json!({"fuel": 1000, "on_error": "allow"}),
            );
            let m = build(&f).unwrap();
            let mut req = request("GET", "/", &[]);
            assert!(matches!(m.request(&mut req, &mut cx()).await, Flow::Next));
        }

        #[test]
        fn load_errors_name_their_setting() {
            let mut f = fixture(&Guest::header(), serde_json::Value::Null);
            f.config.sha256 = "0".repeat(64);
            let issues = build(&f).unwrap_err();
            assert_eq!(issues[0].path, "sha256");
            let mut f = fixture(&Guest::header(), serde_json::Value::Null);
            f.config.trusted_keys = vec![TestKey::new(4).public()];
            let issues = build(&f).unwrap_err();
            assert_eq!(issues[0].path, "signature");
            assert!(issues[0].message.contains("not among the trusted keys"));
            let guest = Guest {
                imports: r#"(import "rdock:plugin/random@0.1.0" (instance $r (export "next-u64" (func (result u64)))))
                    (core func $n (canon lower (func $r "next-u64")))
                    (core instance $env (export "n" (func $n)))"#,
                core_imports: r#"(import "env" "n" (func (result i64)))"#,
                ..Guest::default()
            };
            let f = fixture(&guest, serde_json::Value::Null);
            let issues = build(&f).unwrap_err();
            assert_eq!(issues[0].path, "path");
            assert!(issues[0].message.contains("capabilities: [random]"));
            let f = fixture(&guest, serde_json::json!({"capabilities": ["random"]}));
            assert!(build(&f).is_ok());
        }
    }
}
