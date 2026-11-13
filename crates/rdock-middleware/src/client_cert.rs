//! `client_cert`: demand a verified client certificate, check its names, and pass its identity
//! to the backend in Traefik's or Envoy's headers (M-TLS-01). The listener has already verified
//! the certificate against its CA; this middleware never sees an unverified one.

use std::fmt::Write;
use std::sync::Arc;

use async_trait::async_trait;
use http::HeaderValue;
use pingora::http::RequestHeader;
use rdock_model::middleware::{ClientCertConfig, ClientCertForward, SpiffeRules};

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
    /// Subject organizations (O).
    pub organizations: Vec<String>,
    /// Serial number, lower-case hex without separators.
    pub serial: String,
    /// Basic constraints say the certificate is a CA.
    pub ca: bool,
    /// Key usage allows signing certificates (`keyCertSign`) or CRLs (`cRLSign`).
    pub signs_certificates: bool,
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
    subjects: Vec<String>,
    organizations: Vec<String>,
    dns: Vec<String>,
    uris: Vec<String>,
    emails: Vec<String>,
    serials: Vec<String>,
    sha256: Vec<String>,
    spiffe: Option<SpiffeRules>,
    forward: ClientCertForward,
}

fn lower(list: &[String]) -> Vec<String> {
    list.iter().map(|p| p.to_ascii_lowercase()).collect()
}

/// Hex without `:` separators, lower case.
fn hex(list: &[String]) -> Vec<String> {
    list.iter()
        .map(|v| v.replace(':', "").to_ascii_lowercase())
        .collect()
}

/// Whether `list` is empty or one of `values` matches one of its globs (case-insensitive).
fn any_glob<'a>(list: &[String], mut values: impl Iterator<Item = &'a String>) -> bool {
    list.is_empty()
        || values.any(|v| {
            let v = v.to_ascii_lowercase();
            list.iter().any(|pattern| glob(pattern, &v))
        })
}

impl ClientCert {
    pub(crate) fn new(config: &ClientCertConfig) -> Self {
        Self {
            required: config.required,
            allow: lower(&config.allow),
            subjects: lower(&config.subjects),
            organizations: lower(&config.organizations),
            dns: lower(&config.dns),
            uris: config.uris.clone(),
            emails: lower(&config.emails),
            serials: hex(&config.serials),
            sha256: hex(&config.sha256),
            spiffe: config.spiffe.clone(),
            forward: config.forward,
        }
    }

    fn allowed(&self, identity: &ClientIdentity) -> bool {
        let legacy = self.allow.is_empty()
            || identity.names().any(|name| {
                let name = name.to_ascii_lowercase();
                self.allow.iter().any(|pattern| glob(pattern, &name))
            });
        // URIs keep their case: a SPIFFE path is case-sensitive.
        let uris = self.uris.is_empty()
            || identity
                .uris
                .iter()
                .any(|u| self.uris.iter().any(|pattern| glob(pattern, u)));
        legacy
            && uris
            && any_glob(&self.subjects, identity.common_name.iter())
            && any_glob(&self.organizations, identity.organizations.iter())
            && any_glob(&self.dns, identity.dns.iter())
            && any_glob(&self.emails, identity.emails.iter())
            && (self.serials.is_empty() || self.serials.contains(&identity.serial))
            && (self.sha256.is_empty() || self.sha256.contains(&identity.sha256))
    }
}

/// Why a certificate is not an acceptable X.509-SVID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SvidError {
    /// Not exactly one URI SAN.
    UriSans(usize),
    /// The URI SAN is not a valid SPIFFE ID.
    InvalidId(&'static str),
    /// A SPIFFE ID without a path (a trust domain's own ID) on a leaf.
    RootPath,
    /// The leaf is a CA, or may sign certificates or CRLs.
    SigningCertificate,
    /// The trust domain is not accepted.
    TrustDomain,
    /// The ID is not among `ids` or under `id_prefixes`.
    NotAllowed,
}

/// The SPIFFE ID's trust domain and path, after the checks of `SPIFFE-ID.md` §2.
pub(crate) fn parse_spiffe_id(id: &str) -> Result<(&str, &str), SvidError> {
    if id.len() > 2048 {
        return Err(SvidError::InvalidId("longer than 2048 bytes"));
    }
    let rest = id
        .strip_prefix("spiffe://")
        .ok_or(SvidError::InvalidId("the scheme is not `spiffe`"))?;
    if rest.contains(['?', '#']) {
        return Err(SvidError::InvalidId("a query or fragment"));
    }
    let (domain, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    if domain.is_empty() {
        return Err(SvidError::InvalidId("an empty trust domain"));
    }
    if domain.len() > 255
        || !domain
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
    {
        return Err(SvidError::InvalidId(
            "the trust domain has characters other than [a-z0-9._-] (a port, user info, upper case or percent-encoding)",
        ));
    }
    if path.is_empty() {
        return Ok((domain, path));
    }
    for segment in path.split('/').skip(1) {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(SvidError::InvalidId(
                "an empty, `.` or `..` path segment, or a trailing `/`",
            ));
        }
        if !segment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err(SvidError::InvalidId(
                "a path segment with characters other than [a-zA-Z0-9._-]",
            ));
        }
    }
    Ok((domain, path))
}

/// The SPIFFE ID of `identity` when it is an acceptable X.509-SVID under `rules`
/// (`X509-SVID.md` §2, §4.1, §5.2).
pub(crate) fn svid<'a>(
    identity: &'a ClientIdentity,
    rules: &SpiffeRules,
) -> Result<&'a str, SvidError> {
    let [id] = identity.uris.as_slice() else {
        return Err(SvidError::UriSans(identity.uris.len()));
    };
    let (domain, path) = parse_spiffe_id(id)?;
    if path.is_empty() {
        return Err(SvidError::RootPath);
    }
    if identity.ca || identity.signs_certificates {
        return Err(SvidError::SigningCertificate);
    }
    if !rules
        .trust_domains
        .iter()
        .any(|d| d.eq_ignore_ascii_case(domain))
    {
        return Err(SvidError::TrustDomain);
    }
    let listed = rules.ids.is_empty() && rules.id_prefixes.is_empty()
        || rules.ids.iter().any(|allowed| allowed == id)
        || rules.id_prefixes.iter().any(|prefix| {
            let prefix = prefix.trim_end_matches('/');
            id.strip_prefix(prefix)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
        });
    if !listed {
        return Err(SvidError::NotAllowed);
    }
    Ok(id)
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
        if let Some(rules) = &self.spiffe {
            match svid(&identity, rules) {
                Ok(id) => {
                    let id: Arc<str> = Arc::from(id);
                    if rules.consumer {
                        let domain = parse_spiffe_id(&id).map(|(d, _)| d).unwrap_or_default();
                        cx.consumer = Some(crate::Consumer {
                            name: id.clone(),
                            groups: Arc::from([]),
                            issuer: Some(Arc::from(format!("spiffe://{domain}"))),
                        });
                        cx.user = Some(id.to_string());
                    }
                    cx.spiffe_id = Some(id);
                }
                Err(why) => {
                    tracing::debug!(reason = ?why, "client certificate refused: not an acceptable SPIFFE SVID");
                    return Flow::Reply(Reply::status(403));
                }
            }
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
    fn typed_lists_check_their_own_field() {
        let with = |f: fn(&mut ClientCertConfig)| {
            let mut c = ClientCertConfig::default();
            f(&mut c);
            c
        };
        let next = |c: &ClientCertConfig| matches!(run(c, Some(identity())).0, Flow::Next);
        assert!(next(&with(|c| c.subjects = vec!["BILL*".into()])));
        assert!(next(
            &with(|c| c.dns = vec!["*.clients.example.com".into()])
        ));
        assert!(next(&with(
            |c| c.uris = vec!["spiffe://example.com/*".into()]
        )));
        // A DNS name or CN cannot satisfy a URI rule, nor a URI a DNS rule.
        assert!(!next(&with(|c| c.uris = vec!["billing*".into()])));
        assert!(!next(&with(|c| c.dns = vec!["spiffe://*".into()])));
        // URIs are case-sensitive (SPIFFE paths are).
        assert!(!next(&with(
            |c| c.uris = vec!["spiffe://example.com/BILLING".into()]
        )));
        assert!(next(&with(|c| c.sha256 = vec!["AB:12".into()])));
        assert!(!next(&with(|c| c.sha256 = vec!["ab13".into()])));
        // Every set list must match.
        assert!(!next(&with(|c| {
            c.subjects = vec!["billing".into()];
            c.dns = vec!["*.other.example.com".into()];
        })));
    }

    fn svid_identity(uris: &[&str]) -> ClientIdentity {
        ClientIdentity {
            uris: uris.iter().map(|u| (*u).to_owned()).collect(),
            ..ClientIdentity::default()
        }
    }

    fn rules() -> SpiffeRules {
        SpiffeRules {
            trust_domains: vec!["prod.example.com".into()],
            ..SpiffeRules::default()
        }
    }

    #[test]
    fn the_svid_validity_matrix() {
        let ok = "spiffe://prod.example.com/ns/web/sa/api";
        assert_eq!(svid(&svid_identity(&[ok]), &rules()), Ok(ok));
        assert_eq!(
            svid(
                &svid_identity(&[ok, "spiffe://prod.example.com/other"]),
                &rules()
            ),
            Err(SvidError::UriSans(2)),
            "two URI SANs"
        );
        assert_eq!(
            svid(&svid_identity(&[]), &rules()),
            Err(SvidError::UriSans(0))
        );
        let ca = ClientIdentity {
            ca: true,
            ..svid_identity(&[ok])
        };
        assert_eq!(
            svid(&ca, &rules()),
            Err(SvidError::SigningCertificate),
            "CA leaf"
        );
        let signer = ClientIdentity {
            signs_certificates: true,
            ..svid_identity(&[ok])
        };
        assert_eq!(svid(&signer, &rules()), Err(SvidError::SigningCertificate));
        assert_eq!(
            svid(&svid_identity(&["spiffe://prod.example.com"]), &rules()),
            Err(SvidError::RootPath),
            "empty path"
        );
        assert_eq!(
            svid(
                &svid_identity(&["spiffe://staging.example.com/ns/web"]),
                &rules()
            ),
            Err(SvidError::TrustDomain),
            "wrong trust domain"
        );
        for bad in [
            "https://prod.example.com/ns/web",
            "spiffe:///ns/web",
            "spiffe://prod.example.com:8443/ns/web",
            "spiffe://user@prod.example.com/ns/web",
            "spiffe://Prod.example.com/ns/web",
            "spiffe://prod.example.com/ns//web",
            "spiffe://prod.example.com/ns/web/",
            "spiffe://prod.example.com/ns/../web",
            "spiffe://prod.example.com/ns/%41",
            "spiffe://prod.example.com/ns/web?x=1",
            "spiffe://prod.example.com/ns/web#f",
        ] {
            assert!(
                matches!(
                    svid(&svid_identity(&[bad]), &rules()),
                    Err(SvidError::InvalidId(_))
                ),
                "{bad}"
            );
        }
    }

    #[test]
    fn spiffe_ids_and_prefixes_match_whole_segments() {
        let listed = SpiffeRules {
            ids: vec!["spiffe://prod.example.com/ns/web/sa/api".into()],
            id_prefixes: vec!["spiffe://prod.example.com/ns/jobs/".into()],
            ..rules()
        };
        let check = |id: &str| svid(&svid_identity(&[id]), &listed).is_ok();
        assert!(check("spiffe://prod.example.com/ns/web/sa/api"));
        assert!(!check("spiffe://prod.example.com/ns/web/sa/api2"));
        assert!(check("spiffe://prod.example.com/ns/jobs"));
        assert!(check("spiffe://prod.example.com/ns/jobs/sa/cron"));
        assert!(
            !check("spiffe://prod.example.com/ns/jobsx/sa/cron"),
            "never a substring"
        );
    }

    #[test]
    fn a_spiffe_id_becomes_an_issuer_keyed_consumer_on_request() {
        let id = "spiffe://prod.example.com/ns/web/sa/api";
        let identity = Arc::new(svid_identity(&[id]));
        let config = ClientCertConfig {
            spiffe: Some(SpiffeRules {
                consumer: true,
                ..rules()
            }),
            ..ClientCertConfig::default()
        };
        let mw = ClientCert::new(&config);
        let mut c = cx();
        c.client_cert = Some(identity.clone());
        let mut req = request("GET", "/", &[]);
        assert!(matches!(block_on(mw.request(&mut req, &mut c)), Flow::Next));
        assert_eq!(c.spiffe_id.as_deref(), Some(id));
        let consumer = c.consumer.unwrap();
        assert_eq!(&*consumer.name, id);
        assert_eq!(
            consumer.issuer.as_deref(),
            Some("spiffe://prod.example.com")
        );
        assert_ne!(
            consumer.key(),
            crate::Consumer::named(id).key(),
            "never a configured consumer's key"
        );
        // Without `consumer`, the ID is only recorded.
        let plain = ClientCert::new(&ClientCertConfig {
            spiffe: Some(rules()),
            ..ClientCertConfig::default()
        });
        let mut c = cx();
        c.client_cert = Some(identity);
        assert!(matches!(
            block_on(plain.request(&mut req, &mut c)),
            Flow::Next
        ));
        assert!(c.consumer.is_none());
        assert_eq!(c.spiffe_id.as_deref(), Some(id));
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
