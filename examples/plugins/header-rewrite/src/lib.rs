//! `header-rewrite`: sets and removes request and response headers from configuration. The
//! "hello world" of ReverseDock plugins: two phases, a typed configuration with validation,
//! and tests on the SDK's harness.
//!
//! ```yaml
//! middlewares:
//!   tidy:
//!     type: plugin
//!     name: header_rewrite
//!     config:
//!       request:
//!         set: { X-Team: core }
//!         remove: [X-Debug]
//!       response:
//!         set: { X-Frame-Options: DENY }
//!         remove: [Server]
//! ```

use std::collections::BTreeMap;

use rdock_plugin_api::http::{HeaderName, HeaderValue};
use rdock_plugin_api::{
    Capabilities, ConfigError, Ctx, Decision, Factory, Phases, Plugin, RequestHead, ResponseHead,
    async_trait, typed,
};
use serde::Deserialize;

/// The plugin's configuration.
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Changes to the request sent to the backend.
    pub request: Rules,
    /// Changes to the response sent to the client.
    pub response: Rules,
}

/// Header changes for one direction.
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Rules {
    /// Headers set to a value (replacing what was there).
    pub set: BTreeMap<String, String>,
    /// Headers removed.
    pub remove: Vec<String>,
}

/// Rules checked and parsed into header types.
#[derive(Debug, Default)]
struct Compiled {
    set: Vec<(HeaderName, HeaderValue)>,
    remove: Vec<HeaderName>,
}

impl Compiled {
    fn is_empty(&self) -> bool {
        self.set.is_empty() && self.remove.is_empty()
    }
}

/// The plugin.
#[derive(Debug)]
pub struct HeaderRewrite {
    request: Compiled,
    response: Compiled,
}

/// The factory to register: `Registry::new().plugin("header_rewrite", header_rewrite::factory())`.
pub fn factory() -> impl Factory {
    typed(HeaderRewrite::new)
}

/// Headers that frame a message; the proxy owns them, so they are refused here, in
/// `rdock validate`, rather than ignored at request time.
fn protected(name: &HeaderName, response: bool) -> bool {
    if response {
        rdock_plugin_api::is_protected_response_header(name)
    } else {
        rdock_plugin_api::is_protected_request_header(name)
    }
}

fn compile(rules: &Rules, at: &str, response: bool, errors: &mut ConfigError) -> Compiled {
    let mut out = Compiled::default();
    for (name, value) in &rules.set {
        let path = format!("{at}.set.{name}");
        match HeaderName::from_bytes(name.as_bytes()) {
            Err(_) => errors.push(ConfigError::at(path, "not a valid header name")),
            Ok(header) if protected(&header, response) => errors.push(
                ConfigError::at(path, format!("`{name}` is managed by the proxy"))
                    .with_hint("framing headers (Content-Length, Transfer-Encoding, Connection…) cannot be set"),
            ),
            Ok(header) => match HeaderValue::from_str(value) {
                Ok(value) => out.set.push((header, value)),
                Err(_) => errors.push(ConfigError::at(
                    path,
                    "not a valid header value (line breaks and control characters are refused)",
                )),
            },
        }
    }
    for (i, name) in rules.remove.iter().enumerate() {
        let path = format!("{at}.remove[{i}]");
        match HeaderName::from_bytes(name.as_bytes()) {
            Err(_) => errors.push(ConfigError::at(path, "not a valid header name")),
            Ok(header) if protected(&header, response) && header != "content-length" => {
                errors.push(ConfigError::at(
                    path,
                    format!("`{name}` is managed by the proxy"),
                ));
            }
            Ok(header) if out.set.iter().any(|(n, _)| *n == header) => errors.push(
                ConfigError::at(path, format!("`{name}` is both set and removed")),
            ),
            Ok(header) => out.remove.push(header),
        }
    }
    out
}

impl HeaderRewrite {
    /// Checks `config` and builds the plugin.
    ///
    /// # Errors
    ///
    /// Invalid or protected header names, invalid values, a header both set and removed, or
    /// no rule at all.
    pub fn new(config: Config) -> Result<Self, ConfigError> {
        let Config { request, response } = config;
        let mut errors = ConfigError::empty();
        let request = compile(&request, "request", false, &mut errors);
        let response = compile(&response, "response", true, &mut errors);
        if errors.is_empty() && request.is_empty() && response.is_empty() {
            errors.push(
                ConfigError::new("no header to set or remove")
                    .with_hint("add `request` or `response` rules with `set` or `remove`"),
            );
        }
        errors.into_result(Self { request, response })
    }
}

#[async_trait]
impl Plugin for HeaderRewrite {
    fn capabilities(&self) -> Capabilities {
        let mut phases = Phases::NONE;
        if !self.request.is_empty() {
            phases = phases | Phases::REQUEST;
        }
        if !self.response.is_empty() {
            phases = phases | Phases::RESPONSE;
        }
        Capabilities::new(phases)
    }

    async fn request(&self, req: &mut RequestHead, _cx: &mut Ctx<'_>) -> Decision {
        for name in &self.request.remove {
            // Protected names were refused when the configuration was checked.
            let _ = req.remove_header(name.clone());
        }
        for (name, value) in &self.request.set {
            let _ = req.set_header(name.clone(), value.clone());
        }
        Decision::Continue
    }

    async fn response(&self, resp: &mut ResponseHead, _cx: &mut Ctx<'_>) {
        for name in &self.response.remove {
            let _ = resp.remove_header(name.clone());
        }
        for (name, value) in &self.response.set {
            let _ = resp.set_header(name.clone(), value.clone());
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use rdock_plugin_api::http::StatusCode;
    use rdock_plugin_api::serde_json::json;
    use rdock_plugin_api::testing::{Harness, block_on, request, response};

    use super::*;

    fn harness(config: &rdock_plugin_api::serde_json::Value) -> Harness {
        Harness::from_factory(&factory(), config).unwrap()
    }

    #[test]
    fn sets_and_removes_request_and_response_headers() {
        let mut h = harness(&json!({
            "request": { "set": { "X-Team": "core" }, "remove": ["X-Debug"] },
            "response": { "set": { "X-Frame-Options": "DENY" }, "remove": ["Server"] }
        }));
        let req = request("GET", "/")
            .with_header("x-debug", "1")
            .unwrap()
            .with_header("x-team", "spoofed")
            .unwrap();
        let backend = response(StatusCode::OK)
            .with_header("server", "app/1.2")
            .unwrap();
        let outcome = block_on(h.run(req, None, backend));
        assert!(outcome.answered.is_none());
        assert_eq!(outcome.upstream_request.header("x-team"), Some("core"));
        assert_eq!(outcome.upstream_request.header("x-debug"), None);
        assert_eq!(outcome.response.header("x-frame-options"), Some("DENY"));
        assert_eq!(outcome.response.header("server"), None);
    }

    #[test]
    fn declares_only_the_phases_it_needs() {
        let h = harness(&json!({ "response": { "remove": ["Server"] } }));
        assert_eq!(
            h.capabilities().phases().names().collect::<Vec<_>>(),
            ["response"]
        );
    }

    #[test]
    fn configuration_errors_name_their_path() {
        let err = Harness::from_factory(
            &factory(),
            &json!({
                "request": { "set": { "Content-Length": "1", "Bad Name": "x", "X-Ok": "a\nb" }, "remove": ["X-Ok"] },
                "response": { "remove": ["Transfer-Encoding"] }
            }),
        )
        .unwrap_err();
        let paths: Vec<&str> = err.issues().iter().map(|i| i.path.as_str()).collect();
        assert_eq!(
            paths,
            [
                "request.set.Bad Name",
                "request.set.Content-Length",
                "request.set.X-Ok",
                "response.remove[0]",
            ]
        );
        let err = Harness::from_factory(&factory(), &json!({})).unwrap_err();
        assert_eq!(err.to_string(), "no header to set or remove");
        let err = Harness::from_factory(&factory(), &json!({ "requests": {} })).unwrap_err();
        assert_eq!(err.issues()[0].path, "requests", "unknown keys are refused");
        let err = Harness::from_factory(
            &factory(),
            &json!({ "request": { "set": { "X-A": "1" }, "remove": ["x-a"] } }),
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "request.remove[0]: `x-a` is both set and removed"
        );
    }
}
