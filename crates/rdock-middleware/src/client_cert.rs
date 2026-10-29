//! `client_cert`: demand a verified client certificate, check its names, and pass its identity
//! to the backend in Traefik's or Envoy's headers (M-TLS-01). The listener has already verified
//! the certificate against its CA; this middleware never sees an unverified one.

use std::fmt::Write;
use std::sync::Arc;

use async_trait::async_trait;
use http::HeaderValue;
use pingora::http::RequestHeader;
use rdock_model::middleware::{ClientCertConfig, ClientCertForward};

use crate::{Context, Flow, Middleware, Reply};

/// Headers that carry a client identity. The proxy removes client-sent copies from every
/// request, so a backend can trust them.
pub const IDENTITY_HEADERS: [&str; 3] = [
    "x-forwarded-tls-client-cert",
    "x-forwarded-tls-client-cert-info",
    "x-forwarded-client-cert",
];

/// What a verified client certificate says.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientIdentity {
    /// Subject common name.
    pub common_name: Option<String>,
    /// Subject in RFC 4514 form.
    pub subject: String,
    /// Issuer in RFC 4514 form.
    pub issuer: String,
    /// DNS names.
    pub dns: Vec<String>,
    /// URIs (SPIFFE IDs, for example).
    pub uris: Vec<String>,
    /// Email addresses.
    pub emails: Vec<String>,
    /// IP addresses.
    pub ips: Vec<String>,
    /// Validity, in seconds since the Unix epoch.
    pub not_before: i64,
    /// Validity, in seconds since the Unix epoch.
    pub not_after: i64,
    /// SHA-256 of the certificate, lower-case hex.
    pub sha256: String,
    /// The certificate, base64 DER (PEM without delimiters or line breaks).
    pub der_base64: String,
}

impl ClientIdentity {
    fn names(&self) -> impl Iterator<Item = &str> {
        self.common_name
            .iter()
            .chain(&self.dns)
            .chain(&self.uris)
            .chain(&self.emails)
            .map(String::as_str)
    }
}

/// The `client_cert` middleware.
#[derive(Debug)]
pub(crate) struct ClientCert {
    required: bool,
    allow: Vec<String>,
    forward: ClientCertForward,
}

impl ClientCert {
    pub(crate) fn new(config: &ClientCertConfig) -> Self {
        Self {
            required: config.required,
            allow: config
                .allow
                .iter()
                .map(|p| p.to_ascii_lowercase())
                .collect(),
            forward: config.forward,
        }
    }

    fn allowed(&self, identity: &ClientIdentity) -> bool {
        self.allow.is_empty()
            || identity.names().any(|name| {
                let name = name.to_ascii_lowercase();
                self.allow.iter().any(|pattern| glob(pattern, &name))
            })
    }
}

#[async_trait]
impl Middleware for ClientCert {
    async fn request(&self, req: &mut RequestHeader, cx: &mut Context) -> Flow {
        let Some(identity) = cx.client_cert.clone() else {
            return if self.required {
                Flow::Reply(Reply::status(403))
            } else {
                Flow::Next
            };
        };
        if !self.allowed(&identity) {
            return Flow::Reply(Reply::status(403));
        }
        forward(self.forward, &identity, req);
        Flow::Next
    }
}

fn forward(how: ClientCertForward, identity: &Arc<ClientIdentity>, req: &mut RequestHeader) {
    let headers: Vec<(&'static str, String)> = match how {
        ClientCertForward::None => Vec::new(),
        ClientCertForward::Traefik => vec![
            (IDENTITY_HEADERS[0], query_escape(&identity.der_base64)),
            (IDENTITY_HEADERS[1], query_escape(&traefik_info(identity))),
        ],
        ClientCertForward::Xfcc => vec![(IDENTITY_HEADERS[2], xfcc(identity))],
    };
    for (name, value) in headers {
        if let Ok(value) = HeaderValue::from_str(&value) {
            let _ = req.insert_header(name, value);
        }
    }
}

/// Traefik's `X-Forwarded-Tls-Client-Cert-Info` fields.
fn traefik_info(identity: &ClientIdentity) -> String {
    let sans: Vec<&str> = identity
        .dns
        .iter()
        .chain(&identity.emails)
        .chain(&identity.ips)
        .chain(&identity.uris)
        .map(String::as_str)
        .collect();
    format!(
        "Subject=\"{}\";Issuer=\"{}\";NB=\"{}\";NA=\"{}\";SAN=\"{}\"",
        identity.subject,
        identity.issuer,
        identity.not_before,
        identity.not_after,
        sans.join(",")
    )
}

/// Envoy's `X-Forwarded-Client-Cert` element for one certificate.
fn xfcc(identity: &ClientIdentity) -> String {
    let mut out = format!(
        "Hash={};Subject={}",
        identity.sha256,
        quoted(&identity.subject)
    );
    for uri in &identity.uris {
        let _ = write!(out, ";URI={}", quoted(uri));
    }
    for dns in &identity.dns {
        let _ = write!(out, ";DNS={}", quoted(dns));
    }
    out
}

/// A value in double quotes, with `"` and `\` escaped.
fn quoted(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

/// Percent-encodes everything but unreserved characters (Go's `url.QueryEscape`, which Traefik
/// uses, writes spaces as `+`).
fn query_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(char::from(byte));
            }
            b' ' => out.push('+'),
            _ => {
                let _ = write!(out, "%{byte:02X}");
            }
        }
    }
    out
}

/// `*` matches any run of characters, including none.
fn glob(pattern: &str, text: &str) -> bool {
    let mut parts = pattern.split('*');
    let first = parts.next().unwrap_or_default();
    let Some(mut rest) = text.strip_prefix(first) else {
        return false;
    };
    let parts: Vec<&str> = parts.collect();
    let Some((last, middle)) = parts.split_last() else {
        return rest.is_empty();
    };
    for part in middle {
        match rest.find(part) {
            Some(at) => rest = &rest[at + part.len()..],
            None => return false,
        }
    }
    rest.len() >= last.len() && rest.ends_with(last)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{block_on, cx, request};

    fn identity() -> Arc<ClientIdentity> {
        Arc::new(ClientIdentity {
            common_name: Some("billing".into()),
            subject: "CN=billing,O=Example".into(),
            issuer: "CN=Example CA".into(),
            dns: vec!["billing.clients.example.com".into()],
            uris: vec!["spiffe://example.com/billing".into()],
            sha256: "ab12".into(),
            der_base64: "MII+/=".into(),
            not_before: 1,
            not_after: 2,
            ..ClientIdentity::default()
        })
    }

    fn run(config: &ClientCertConfig, cert: Option<Arc<ClientIdentity>>) -> (Flow, RequestHeader) {
        let mw = ClientCert::new(config);
        let mut c = cx();
        c.client_cert = cert;
        let mut req = request("GET", "/", &[]);
        let flow = block_on(mw.request(&mut req, &mut c));
        (flow, req)
    }

    #[test]
    fn requires_a_certificate_and_checks_names() {
        let required = ClientCertConfig::default();
        assert!(matches!(run(&required, None).0, Flow::Reply(_)));
        assert!(matches!(run(&required, Some(identity())).0, Flow::Next));
        let optional = ClientCertConfig {
            required: false,
            ..ClientCertConfig::default()
        };
        assert!(matches!(run(&optional, None).0, Flow::Next));
        let allow = |p: &str| ClientCertConfig {
            allow: vec![p.into()],
            ..ClientCertConfig::default()
        };
        assert!(matches!(
            run(&allow("*.clients.example.com"), Some(identity())).0,
            Flow::Next
        ));
        assert!(matches!(
            run(&allow("spiffe://example.com/*"), Some(identity())).0,
            Flow::Next
        ));
        assert!(matches!(
            run(&allow("BILLING"), Some(identity())).0,
            Flow::Next
        ));
        assert!(matches!(
            run(&allow("*.other.example.com"), Some(identity())).0,
            Flow::Reply(_)
        ));
    }

    #[test]
    fn forwards_traefik_and_envoy_headers() {
        let traefik = ClientCertConfig {
            forward: ClientCertForward::Traefik,
            ..ClientCertConfig::default()
        };
        let (_, req) = run(&traefik, Some(identity()));
        let header = |name: &str| {
            req.headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        };
        assert_eq!(
            header("x-forwarded-tls-client-cert").as_deref(),
            Some("MII%2B%2F%3D")
        );
        let info = header("x-forwarded-tls-client-cert-info").unwrap();
        assert!(
            info.starts_with("Subject%3D%22CN%3Dbilling%2CO%3DExample%22"),
            "{info}"
        );
        let xfcc = ClientCertConfig {
            forward: ClientCertForward::Xfcc,
            ..ClientCertConfig::default()
        };
        let (_, req) = run(&xfcc, Some(identity()));
        assert_eq!(
            req.headers.get("x-forwarded-client-cert").unwrap(),
            "Hash=ab12;Subject=\"CN=billing,O=Example\";URI=\"spiffe://example.com/billing\";DNS=\"billing.clients.example.com\""
        );
    }

    #[test]
    fn globs() {
        assert!(glob("*", ""));
        assert!(glob("a*c", "abbbc"));
        assert!(glob("*.example.com", "x.example.com"));
        assert!(!glob("*.example.com", "example.com"));
        assert!(glob("exact", "exact"));
        assert!(!glob("exact", "exactly"));
        assert!(glob("a*b*c", "a-b-c"));
        assert!(!glob("ab*ba", "aba"), "the parts must not overlap");
    }
}
