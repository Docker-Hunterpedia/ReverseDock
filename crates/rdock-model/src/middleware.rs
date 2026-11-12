//! Built-in middlewares. Each middleware is an object with a `type` and its settings.

use std::collections::BTreeMap;
use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::values::{ByteSize, Duration, HttpUrl, IpNetwork, RateLimitKey};

/// A reusable request/response policy, selected by `type`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Middleware {
    /// Set, add or remove request and response headers.
    Headers(HeadersConfig),
    /// Redirect to another scheme or to a URL built from a regular expression.
    Redirect(RedirectConfig),
    /// Rewrite the path with a regular expression.
    Rewrite(RewriteConfig),
    /// Remove a path prefix before forwarding.
    StripPrefix(StripPrefixConfig),
    /// Add a path prefix before forwarding.
    AddPrefix(AddPrefixConfig),
    /// Replace the whole path before forwarding.
    ReplacePath(ReplacePathConfig),
    /// HTTP Basic authentication with hashed passwords.
    BasicAuth(BasicAuthConfig),
    /// Ask an external service (Authelia, Authentik, oauth2-proxy…) whether to allow a request.
    ForwardAuth(ForwardAuthConfig),
    /// Allow only these client networks.
    IpAllow(IpListConfig),
    /// Reject these client networks.
    IpDeny(IpListConfig),
    /// Token-bucket rate limiting.
    RateLimit(RateLimitConfig),
    /// A cap on requests in flight, with an optional queue (Traefik's `inFlightReq`).
    InFlight(InFlightConfig),
    /// A cap on response bytes per second.
    Bandwidth(BandwidthConfig),
    /// Cross-origin resource sharing.
    Cors(CorsConfig),
    /// Response compression.
    Compress(CompressConfig),
    /// Custom error pages.
    Errors(ErrorsConfig),
    /// Maintenance mode.
    Maintenance(MaintenanceConfig),
    /// Verify JSON Web Tokens (JWS) and pass their claims on.
    Jwt(JwtConfig),
    /// Demand a verified client certificate, check its names and pass its identity on.
    ClientCert(ClientCertConfig),
    /// Translate gRPC-Web from browsers into gRPC for the backend (binary
    /// `application/grpc-web`; the service needs `scheme: h2c` or `https`).
    GrpcWeb(GrpcWebConfig),
    /// Serve files from a directory on ReverseDock's own file system. It answers the request,
    /// so a route that ends with it needs no service (unless `pass_through` is on).
    Static(StaticConfig),
    /// Hold the request body until it is complete (up to `max`) before any of it reaches the
    /// backend. The backend connection and the request head are already sent, so this does
    /// not shield backend workers from slow uploads; it refuses oversize bodies with `413`
    /// and lets body middlewares see the whole body.
    HoldBody(HoldBodyConfig),
    /// Cache responses in a store named under `caches` (RFC 9111). Only what the origin's
    /// headers allow is stored; see `docs/guides/caching`.
    Cache(crate::cache::CacheConfig),
    /// A native plugin compiled into this binary and registered under `name` (ADR-0030). The
    /// stock `rdock` binary registers none; see `docs/guides/plugins`.
    Plugin(PluginConfig),
    /// A sandboxed WebAssembly plugin (EXPERIMENTAL, ADR-0030): a component for the world
    /// `rdock:plugin/filter@0.1.0`, loaded from a file pinned by SHA-256 and signed with
    /// minisign. Needs a build with the `wasm` cargo feature; see `docs/guides/wasm-plugins`.
    Wasm(WasmConfig),
    /// Ask an out-of-process agent (a WAF, a policy service) whether to allow a request,
    /// with its body up to `max_body` (ADR-0030). Fails closed by default.
    Agent(AgentConfig),
    /// Verify the token Cloudflare Access adds to requests it let through (W-CF-06): a preset
    /// over `jwt` with the team's keys, issuer and RS256, the token from the
    /// `Cf-Access-Jwt-Assertion` header, then the `CF_Authorization` cookie.
    CloudflareAccess(CloudflareAccessConfig),
    /// Authenticate with consumers' API keys (`rdk_…`), read from `Authorization: Bearer` or
    /// `X-API-Key`; sets the request's consumer (F-GW-01).
    ApiKey(crate::gateway::ApiKeyConfig),
    /// Requests per consumer per calendar window (hour, day, month), persisted across
    /// restarts; `429` when used up (F-GW-02).
    Quota(crate::gateway::QuotaConfig),
    /// Check request parameters and JSON bodies against JSON Schema 2020-12, inline or from an
    /// OpenAPI 3.1 document; `400` with the errors when they do not match (F-GW-03).
    Validate(crate::validation::ValidateConfig),
    /// Change request and response headers, and JSON bodies with JSON Patch (RFC 6902)
    /// (F-GW-04).
    Transform(crate::transform::TransformConfig),
    /// OpenID Connect login for browsers: authorization code flow with PKCE, a stateless
    /// encrypted session cookie, claims to headers and to the consumer (F-GW-01).
    Oidc(Box<crate::oidc::OidcConfig>),
}

/// Cloudflare Access application tokens (`type: cloudflare_access`, W-CF-06, ADR-0030).
///
/// The keys come from `https://<team>.cloudflareaccess.com/cdn-cgi/access/certs` (refreshed
/// every 10 minutes and at once on an unknown key ID, well inside the 7 days a rotated key
/// stays valid), the issuer must be `https://<team>.cloudflareaccess.com`, the algorithm RS256.
/// The request's consumer becomes the user's `email`, or for a service token (empty `sub`) its
/// `common_name` in the group `service-token`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[schemars(inline)]
pub struct CloudflareAccessConfig {
    /// The Zero Trust team name (`acme`) or team domain (`acme.cloudflareaccess.com`).
    pub team: String,
    /// The Application Audience (AUD) tag of the Access application, or several. Required:
    /// without it a token of any application of the same team would pass.
    pub audience: Audience,
    /// Request headers set from claims (`claim: header`), e.g. `{ email: X-Auth-Email,
    /// common_name: X-Auth-Service-Token }`. Client-sent copies are removed first.
    #[serde(default)]
    pub claims_to_headers: BTreeMap<String, String>,
    /// Where the keys are fetched from instead of the team's certs URL: for tests, or an
    /// egress proxy that mirrors it. `https://` (or a loopback address).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certs_url: Option<HttpUrl>,
}

impl CloudflareAccessConfig {
    /// The team name: `team` without the `.cloudflareaccess.com` suffix, lower-cased.
    #[must_use]
    pub fn team_name(&self) -> String {
        let team = self.team.trim().to_ascii_lowercase();
        team.strip_suffix(".cloudflareaccess.com")
            .map_or_else(|| team.clone(), str::to_owned)
    }

    /// Whether `team` is a valid team name or team domain.
    #[must_use]
    pub fn team_is_valid(&self) -> bool {
        let name = self.team_name();
        !name.is_empty()
            && name.len() <= 63
            && !name.starts_with('-')
            && !name.ends_with('-')
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    }

    /// The issuer of the team's tokens, `https://<team>.cloudflareaccess.com`.
    #[must_use]
    pub fn issuer(&self) -> String {
        format!("https://{}.cloudflareaccess.com", self.team_name())
    }

    /// The URL of the team's signing keys.
    #[must_use]
    pub fn certs(&self) -> String {
        self.certs_url.as_ref().map_or_else(
            || format!("{}/cdn-cgi/access/certs", self.issuer()),
            |url| url.as_url().to_string(),
        )
    }

    /// The `jwt` settings this preset stands for.
    #[must_use]
    pub fn to_jwt(&self) -> Option<JwtConfig> {
        let jwks_url = self.certs().parse().ok()?;
        Some(JwtConfig {
            jwks_url: Some(jwks_url),
            jwks_file: None,
            hmac_secret: None,
            issuer: self.issuer(),
            audiences: self.audience.list().to_vec(),
            algorithms: vec![JwtAlgorithm::Rs256],
            leeway: sixty_seconds(),
            token: TokenSource {
                header: Some("Cf-Access-Jwt-Assertion".to_owned()),
                cookie: Some("CF_Authorization".to_owned()),
                query: None,
            },
            claims_to_headers: self.claims_to_headers.clone(),
            forward_token: true,
            consumer_claim: None,
            groups_claim: None,
            map_to_consumers: false,
            unverified_emails: false,
        })
    }
}

/// One value or a list of values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum Audience {
    /// One value.
    One(String),
    /// Several values.
    Many(Vec<String>),
}

impl Audience {
    /// The values.
    #[must_use]
    pub fn list(&self) -> &[String] {
        match self {
            Self::One(one) => std::slice::from_ref(one),
            Self::Many(many) => many,
        }
    }
}

/// How an authenticating middleware identifies who it let in, for the cache rule
/// (ADR-0030): a route that authenticates and caches must share responses explicitly or key
/// them on this identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Identity {
    /// The `basic_auth` user name.
    User,
    /// The `jwt` issuer and subject (`iss`, `sub`).
    TokenSubject,
    /// The verified client certificate's subject.
    Certificate,
    /// The consumer the middleware attributes the request to (`api_key`,
    /// `cloudflare_access`, `oidc`, `jwt` with `consumer_claim`).
    Consumer,
    /// Decided by an external service; rdock knows only the headers it copies back.
    External {
        /// Headers the middleware copies from the service's answer.
        headers: Vec<String>,
    },
}

impl Identity {
    /// Whether `key.consumer` can tell users apart for this middleware.
    #[must_use]
    pub fn keyable(&self) -> bool {
        !matches!(self, Self::External { .. })
    }

    /// What `key.consumer` keys on, for diagnostics.
    #[must_use]
    pub fn describe(&self) -> &'static str {
        match self {
            Self::User => "the user name",
            Self::TokenSubject => "the token's issuer and subject",
            Self::Certificate => "the certificate's subject",
            Self::Consumer => "the consumer name",
            Self::External { .. } => "nothing: rdock does not learn who the service let in",
        }
    }
}

impl Middleware {
    /// The identity this middleware establishes, when it authenticates requests. New
    /// authenticating middlewares add themselves here and the cache rule follows.
    #[must_use]
    pub fn authenticates(&self) -> Option<Identity> {
        match self {
            Self::BasicAuth(_) => Some(Identity::User),
            Self::Jwt(j) if j.consumer_claim.is_some() => Some(Identity::Consumer),
            Self::Jwt(_) => Some(Identity::TokenSubject),
            Self::ClientCert(_) => Some(Identity::Certificate),
            Self::CloudflareAccess(_) | Self::ApiKey(_) | Self::Oidc(_) => Some(Identity::Consumer),
            Self::ForwardAuth(f) => Some(Identity::External {
                headers: f.copy_headers.clone(),
            }),
            // An agent that sets identity headers decides who is let in, as `forward_auth` does.
            Self::Agent(a) if !a.response_headers.is_empty() => Some(Identity::External {
                headers: a.response_headers.clone(),
            }),
            _ => None,
        }
    }

    /// Whether this middleware answers every request itself, so a route whose chain ends with
    /// it needs no service: `static` without `pass_through`, and `maintenance` that is enabled
    /// for everyone.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        match self {
            Self::Static(s) => !s.pass_through,
            Self::Maintenance(m) => m.enabled && m.allow.is_empty(),
            _ => false,
        }
    }
}

/// JWT validation (RFC 7519, RFC 8725).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[schemars(inline)]
pub struct JwtConfig {
    /// URL of a JSON Web Key Set, fetched in the background and cached for 10 minutes.
    #[serde(default)]
    pub jwks_url: Option<HttpUrl>,
    /// A JSON Web Key Set file, read on every reload.
    #[serde(default)]
    pub jwks_file: Option<PathBuf>,
    /// Shared secret for HS256/HS384/HS512 tokens, as a `${file:…}` or `${env:…}` reference.
    #[serde(default)]
    pub hmac_secret: Option<String>,
    /// Required `iss`; `any` accepts every issuer.
    pub issuer: String,
    /// Accepted `aud` values (one must match); `[any]` accepts every audience.
    pub audiences: Vec<String>,
    /// Algorithms accepted. `none` does not exist here.
    #[serde(default = "default_jwt_algorithms")]
    pub algorithms: Vec<JwtAlgorithm>,
    /// Clock skew allowed for `exp` and `nbf`.
    #[serde(default = "sixty_seconds")]
    pub leeway: Duration,
    /// Where the token is read from; `Authorization: Bearer` when empty.
    #[serde(default)]
    pub token: TokenSource,
    /// Request headers set from claims (`claim: header`). Client-sent copies are removed first.
    #[serde(default)]
    pub claims_to_headers: BTreeMap<String, String>,
    /// Keep the token in the request to the backend.
    #[serde(default = "crate::defaults::yes")]
    pub forward_token: bool,
    /// A claim that becomes the request's consumer (for `rate_limit` and `quota` with
    /// `key: consumer`, the cache key and the access log), e.g. `sub` or `email`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consumer_claim: Option<String>,
    /// The claim listing the consumer's groups (a string or an array of strings), with
    /// `consumer_claim`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups_claim: Option<String>,
    /// With `consumer_claim`: treat a name that `consumers` defines as that consumer, adding
    /// its groups and sharing its quota, rate-limit and cache identity with its API keys
    /// (other names stay keyed on the issuer). Off by default: a token's consumer is a
    /// separate identity keyed on the token's issuer and the name. Turn it on only when the
    /// issuer controls the claim.
    #[serde(default)]
    pub map_to_consumers: bool,
    /// With `consumer_claim: email`: accept an `email` claim that comes without
    /// `email_verified`. Off: the address names the consumer only with `email_verified:
    /// true`, otherwise `sub` does (`email_verified: false` never counts). Unsafe with an
    /// issuer that lets users set an address they do not own.
    #[serde(default)]
    pub unverified_emails: bool,
}

fn default_jwt_algorithms() -> Vec<JwtAlgorithm> {
    vec![
        JwtAlgorithm::Rs256,
        JwtAlgorithm::Es256,
        JwtAlgorithm::EdDsa,
    ]
}

const fn sixty_seconds() -> Duration {
    Duration::from_secs(60)
}

/// JWS algorithms (RFC 7518, RFC 8037).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum JwtAlgorithm {
    /// RSASSA-PKCS1-v1_5 with SHA-256.
    #[serde(rename = "RS256")]
    Rs256,
    /// RSASSA-PKCS1-v1_5 with SHA-384.
    #[serde(rename = "RS384")]
    Rs384,
    /// RSASSA-PKCS1-v1_5 with SHA-512.
    #[serde(rename = "RS512")]
    Rs512,
    /// RSASSA-PSS with SHA-256.
    #[serde(rename = "PS256")]
    Ps256,
    /// RSASSA-PSS with SHA-384.
    #[serde(rename = "PS384")]
    Ps384,
    /// RSASSA-PSS with SHA-512.
    #[serde(rename = "PS512")]
    Ps512,
    /// ECDSA P-256 with SHA-256.
    #[serde(rename = "ES256")]
    Es256,
    /// ECDSA P-384 with SHA-384.
    #[serde(rename = "ES384")]
    Es384,
    /// Ed25519.
    #[serde(rename = "EdDSA")]
    EdDsa,
    /// HMAC with SHA-256 (needs `hmac_secret`).
    #[serde(rename = "HS256")]
    Hs256,
    /// HMAC with SHA-384.
    #[serde(rename = "HS384")]
    Hs384,
    /// HMAC with SHA-512.
    #[serde(rename = "HS512")]
    Hs512,
}

impl JwtAlgorithm {
    /// The `alg` value.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Rs256 => "RS256",
            Self::Rs384 => "RS384",
            Self::Rs512 => "RS512",
            Self::Ps256 => "PS256",
            Self::Ps384 => "PS384",
            Self::Ps512 => "PS512",
            Self::Es256 => "ES256",
            Self::Es384 => "ES384",
            Self::EdDsa => "EdDSA",
            Self::Hs256 => "HS256",
            Self::Hs384 => "HS384",
            Self::Hs512 => "HS512",
        }
    }

    /// Whether this is an HMAC algorithm.
    #[must_use]
    pub fn is_hmac(self) -> bool {
        matches!(self, Self::Hs256 | Self::Hs384 | Self::Hs512)
    }
}

/// Where a JWT is read from. The first one present wins: header, cookie, query parameter.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct TokenSource {
    /// A header; `Authorization` values must start with `Bearer `.
    pub header: Option<String>,
    /// A cookie.
    pub cookie: Option<String>,
    /// A query parameter (tokens in URLs end up in logs; prefer a header).
    pub query: Option<String>,
}

/// Client certificate checks of a route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
#[schemars(inline)]
pub struct ClientCertConfig {
    /// Answer `403` to requests without a verified client certificate.
    pub required: bool,
    /// Names a certificate must have one of: its common name or a DNS, URI or email SAN.
    /// `*` matches any run of characters, e.g. `*.clients.example.com`. Any name when empty.
    pub allow: Vec<String>,
    /// Headers that pass the identity to the backend.
    pub forward: ClientCertForward,
}

impl Default for ClientCertConfig {
    fn default() -> Self {
        Self {
            required: true,
            allow: Vec::new(),
            forward: ClientCertForward::None,
        }
    }
}

/// How a client certificate is passed to the backend. Copies of these headers sent by clients
/// are always removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ClientCertForward {
    /// Not passed on.
    #[default]
    None,
    /// Traefik's `X-Forwarded-Tls-Client-Cert` (the certificate) and
    /// `X-Forwarded-Tls-Client-Cert-Info` (its fields).
    Traefik,
    /// Envoy's `X-Forwarded-Client-Cert`.
    Xfcc,
}

/// Holding the request body (`hold_body`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
#[schemars(inline)]
pub struct HoldBodyConfig {
    /// Largest body held, at most 64MiB; a longer one is refused with `413`. The route's
    /// `max_body` (or `security.limits.max_body_bytes`) applies when it is smaller.
    pub max: ByteSize,
    /// Longest time from the first body byte to the last; a slower upload is refused with
    /// `408`. The service's `timeouts.read` also runs while the backend waits for the body.
    pub timeout: Duration,
}

impl HoldBodyConfig {
    /// Largest `max` accepted: a held body is in memory in full when it is released.
    pub const MAX: ByteSize = ByteSize::mib(64);
}

impl Default for HoldBodyConfig {
    fn default() -> Self {
        Self {
            max: ByteSize::mib(1),
            timeout: Duration::from_secs(30),
        }
    }
}

/// gRPC-Web translation has no settings.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[schemars(inline)]
pub struct GrpcWebConfig {}

/// Header changes for requests (to the backend) and responses (to the client).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
#[schemars(inline)]
pub struct HeadersConfig {
    /// Changes to the request sent to the backend.
    pub request: HeaderRules,
    /// Changes to the response sent to the client.
    pub response: HeaderRules,
    /// HTTP Strict Transport Security, sent on HTTPS responses only.
    pub hsts: Option<Hsts>,
}

/// `Strict-Transport-Security` settings. Browsers then refuse plain HTTP for the host, so
/// enable it only when HTTPS works for every name involved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Hsts {
    /// How long browsers remember the policy. `0s` removes it.
    pub max_age: Duration,
    /// Apply the policy to all subdomains too.
    #[serde(default)]
    pub include_subdomains: bool,
    /// Ask for inclusion in browser preload lists. This is hard to undo.
    #[serde(default)]
    pub preload: bool,
}

/// Header operations, applied in the order remove, set, add.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct HeaderRules {
    /// Replace headers.
    pub set: BTreeMap<String, String>,
    /// Append header values.
    pub add: BTreeMap<String, String>,
    /// Remove headers.
    pub remove: Vec<String>,
}

/// Redirect settings: a target built from the request (`scheme`, `hostname`, `port`, `path`
/// or `prefix`, in any combination), or `regex` with `replacement`. The query string is kept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[schemars(inline)]
pub struct RedirectConfig {
    /// Redirect to this scheme. Alone (without `hostname`, `path` or `prefix`; `port`,
    /// `status` and `permanent` may be set), a request that already uses it is not
    /// redirected, unless `always` is set.
    #[serde(default)]
    pub scheme: Option<RedirectScheme>,
    /// Replace the host name.
    #[serde(default)]
    pub hostname: Option<String>,
    /// Replace the whole path, e.g. `/new`.
    #[serde(default)]
    pub path: Option<String>,
    /// Replace a leading path prefix, by path segment: `{ from: /a, to: /b }` turns `/a/x`
    /// into `/b/x` and `/a` into `/b`; other paths are kept.
    #[serde(default)]
    pub prefix: Option<RedirectPrefix>,
    /// Regular expression matched against the full request URL. Not combined with the
    /// fields above.
    #[serde(default)]
    pub regex: Option<String>,
    /// Target URL; may use `$1`, `${name}` groups from `regex`.
    #[serde(default)]
    pub replacement: Option<String>,
    /// `301`/`308` when true, `302`/`307` when false (the second code of each pair is used for
    /// methods other than GET, so the method and body are kept), as in Traefik.
    #[serde(default)]
    pub permanent: bool,
    /// Status code of the redirect: `301`, `302`, `303`, `307` or `308`, for every method.
    /// Overrides `permanent`.
    #[serde(default)]
    pub status: Option<u16>,
    /// Port of the target, left out of the URL when it is the scheme's default. Unset: the
    /// scheme's default port when `scheme` is set, otherwise the request's port.
    #[serde(default)]
    pub port: Option<u16>,
    /// Redirect even a request that already uses `scheme` (a redirect that sets `hostname`,
    /// `path` or `prefix` is always sent). The Gateway API's `RequestRedirect` filter sets it:
    /// there a redirect is sent whatever the request's scheme. Default `false`.
    #[serde(default)]
    pub always: bool,
}

/// A path prefix replaced by another (`redirect.prefix`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RedirectPrefix {
    /// The prefix to replace, starting with `/`. It matches whole path segments: `/a`
    /// matches `/a` and `/a/x`, not `/ab`.
    pub from: String,
    /// Its replacement, starting with `/`, or empty to remove the prefix.
    pub to: String,
}

/// Redirect target schemes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RedirectScheme {
    /// `http://`.
    Http,
    /// `https://`.
    Https,
}

/// Path rewrite with a regular expression.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[schemars(inline)]
pub struct RewriteConfig {
    /// Regular expression matched against the path.
    pub regex: String,
    /// Replacement path; may use `$1`, `${name}` groups.
    pub replacement: String,
}

/// Prefix removal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[schemars(inline)]
pub struct StripPrefixConfig {
    /// Prefixes to remove; the first that matches is used.
    pub prefixes: Vec<String>,
}

/// Prefix addition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[schemars(inline)]
pub struct AddPrefixConfig {
    /// Prefix to add, starting with `/`.
    pub prefix: String,
}

/// Path replacement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[schemars(inline)]
pub struct ReplacePathConfig {
    /// New path, starting with `/`.
    pub path: String,
}

/// Basic authentication. Passwords are argon2id or bcrypt hashes; the weaker Apache MD5
/// (`$apr1$`) and SHA-1 (`{SHA}`) hashes are accepted for compatibility with a warning.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
#[schemars(inline)]
pub struct BasicAuthConfig {
    /// `user:hash` entries.
    pub users: Vec<String>,
    /// File with one `user:hash` entry per line.
    pub users_file: Option<PathBuf>,
    /// Realm shown by browsers.
    pub realm: Option<String>,
    /// Remove the `Authorization` header before forwarding.
    pub remove_header: bool,
}

/// A native plugin (`type: plugin`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[schemars(inline)]
pub struct PluginConfig {
    /// The name the plugin is registered under in this binary.
    pub name: String,
    /// The plugin's own settings, checked by the plugin when the configuration is validated
    /// and loaded. Values are interpolated like any other (`${env:…}`, `${file:…}`) and stay
    /// visible in the configuration API.
    #[serde(default)]
    pub config: serde_json::Map<String, serde_json::Value>,
}

/// A sandboxed WebAssembly plugin (`type: wasm`, F-EXT-03, ADR-0030). EXPERIMENTAL: the
/// host ABI is `0.x` and may change in any release.
///
/// The file is checked before it is compiled: its SHA-256 must equal `sha256`, and its
/// minisign signature (`signature`, by default `<path>.minisig`) must be made by one of
/// `trusted_keys`. Each request runs in a fresh instance with `fuel`, `timeout` and `memory`
/// as limits and no access to files, the network, environment variables or clocks beyond
/// the granted `capabilities`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[schemars(inline)]
pub struct WasmConfig {
    /// The component file (`.wasm`; `.wat` text is accepted too). Read when the configuration
    /// is loaded; a reload reads it again.
    pub path: PathBuf,
    /// The file's SHA-256 digest, 64 hex digits (`sha256sum plugin.wasm`). Required: it
    /// fixes which file runs, so a changed file is refused until the pin is updated.
    pub sha256: String,
    /// The minisign signature file; default `<path>.minisig` (what `minisign -S -m <path>`
    /// writes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<PathBuf>,
    /// Minisign public keys whose signatures are accepted: the base64 line of a `.pub` file
    /// (`RWQ…`).
    #[serde(default)]
    pub trusted_keys: Vec<String>,
    /// UNSAFE: run the module without a signature (the `sha256` pin still applies). A
    /// signature that is present must still verify. Logged as a warning at every load.
    #[serde(default)]
    pub allow_unsigned: bool,
    /// Fuel per call, about one unit per WebAssembly instruction; a call that runs out fails.
    #[serde(default = "WasmConfig::default_fuel")]
    pub fuel: u64,
    /// Wall-clock time allowed per call (a backstop to `fuel`; resolution about 1 ms). The
    /// call runs on a proxy worker thread, so keep it short.
    #[serde(default = "WasmConfig::default_timeout")]
    pub timeout: Duration,
    /// The largest linear memory the plugin may have.
    #[serde(default = "WasmConfig::default_memory")]
    pub memory: ByteSize,
    /// Host interfaces the plugin may import besides its `config`. A component that imports
    /// one not listed here, or anything else (WASI included), is refused when it is loaded.
    #[serde(default)]
    pub capabilities: Vec<WasmCapability>,
    /// What a failed call (fuel, timeout, memory, trap, an invalid result) does: `deny`
    /// answers `500` (in the response phase, the response is replaced by a `500`), `allow`
    /// passes the request or response on unchanged. Both are counted and logged.
    #[serde(default)]
    pub on_error: AgentOnError,
    /// The plugin's own settings, given to it as JSON text through `rdock:plugin/config`.
    #[serde(default)]
    pub config: serde_json::Map<String, serde_json::Value>,
}

impl WasmConfig {
    /// The largest `memory`.
    pub const MAX_MEMORY: ByteSize = ByteSize::mib(1024);
    /// The longest `timeout`.
    pub const MAX_TIMEOUT: Duration = Duration::from_secs(10);

    const fn default_fuel() -> u64 {
        10_000_000
    }

    const fn default_timeout() -> Duration {
        Duration::from_millis(50)
    }

    const fn default_memory() -> ByteSize {
        ByteSize::mib(16)
    }
}

/// A host interface a WASM plugin may be granted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WasmCapability {
    /// `rdock:plugin/log`: write lines to rdock's log (32 per request, 1 KiB each).
    Log,
    /// `rdock:plugin/clock`: read the wall clock.
    Clock,
    /// `rdock:plugin/random`: read random bits from the operating system.
    Random,
}

/// An out-of-process agent (`type: agent`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[schemars(inline)]
pub struct AgentConfig {
    /// The agent's URL (`http://` or `https://`). Use `https://` or a loopback address unless
    /// the network between rdock and the agent is private.
    pub address: HttpUrl,
    /// How the request is described to the agent.
    #[serde(default)]
    pub protocol: AgentProtocol,
    /// Time allowed for the agent's whole answer.
    #[serde(default = "one_second")]
    pub timeout: Duration,
    /// What happens when the agent cannot answer (unreachable, timeout, an invalid answer, an
    /// open breaker): `deny` refuses the request (502, 504 on timeout, 503 while the breaker
    /// is open), `allow` lets it through unchecked.
    #[serde(default)]
    pub on_error: AgentOnError,
    /// Largest request body sent to the agent; `0` sends none. The body is held until the
    /// agent has answered, so none of the body reaches the backend before the verdict; the
    /// request head does: with a body, the backend connection is opened and the head sent
    /// before the body is read (Pingora 0.9.1), and a refusal closes that connection.
    #[serde(default = "sixty_four_kib")]
    pub max_body: ByteSize,
    /// A body longer than `max_body`: `reject` answers `413`, `skip` asks the agent without
    /// the body (only when the length is declared; a chunked body that grows past
    /// `max_body` is refused with `413` either way).
    #[serde(default)]
    pub on_oversize: AgentOversize,
    /// Request headers sent to the agent besides the default set (`accept`,
    /// `accept-encoding`, `accept-language`, `cache-control`, `content-type`, `origin`,
    /// `referer`, `user-agent`); `["*"]` sends every header except hop-by-hop ones.
    /// `authorization`, `cookie` and `proxy-authorization` go only when listed here.
    #[serde(default)]
    pub request_headers: Vec<String>,
    /// Request headers the agent may set on the request that goes to the backend (allowed
    /// answers only). Copies sent by the client are removed first. Applied only when the
    /// verdict comes before the request head leaves, which is the case for requests without
    /// a body (or whose body is not sent to the agent).
    #[serde(default)]
    pub response_headers: Vec<String>,
    /// The circuit breaker that stops calling a failing agent for a while.
    #[serde(default)]
    pub breaker: AgentBreaker,
    /// TLS to an `https://` agent.
    #[serde(default)]
    pub tls: Option<crate::service::UpstreamTls>,
}

impl AgentConfig {
    /// Request headers an agent may never set: framing, routing and forwarding facts belong
    /// to the proxy (and every `x-forwarded-*` header).
    pub const PROTECTED_HEADERS: [&'static str; 13] = [
        "host",
        "content-length",
        "transfer-encoding",
        "connection",
        "keep-alive",
        "proxy-connection",
        "te",
        "trailer",
        "upgrade",
        "expect",
        "x-request-id",
        "forwarded",
        "x-real-ip",
    ];

    /// Whether an agent may not set the request header `lower` (a lower-case name).
    #[must_use]
    pub fn is_protected_header(lower: &str) -> bool {
        Self::PROTECTED_HEADERS.contains(&lower) || lower.starts_with("x-forwarded-")
    }
}

const fn sixty_four_kib() -> ByteSize {
    ByteSize::kib(64)
}

/// How a request is described to an agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AgentProtocol {
    /// POST a JSON document describing the request; the agent answers a JSON verdict
    /// (`schema/agent.v1.json`).
    #[default]
    Rdock,
    /// Replay the request to the agent (same method, path, query, allowed headers and body);
    /// a 2xx allows, any other answer is sent to the client. What a WAF reverse-proxy image
    /// understands.
    Forward,
    /// Envoy's gRPC external processing (planned for a later version).
    ExtProc,
    /// Envoy's gRPC external authorization (planned for a later version).
    ExtAuthz,
    /// HAProxy's stream processing offload protocol (planned for a later version).
    Spop,
}

impl AgentProtocol {
    /// The name used in configuration.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Rdock => "rdock",
            Self::Forward => "forward",
            Self::ExtProc => "ext_proc",
            Self::ExtAuthz => "ext_authz",
            Self::Spop => "spop",
        }
    }
}

/// What an agent failure does to the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AgentOnError {
    /// Refuse the request (fail closed).
    #[default]
    Deny,
    /// Let the request through unchecked (fail open); counted and logged.
    Allow,
}

/// What a body longer than `max_body` does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AgentOversize {
    /// Refuse the request with `413`.
    #[default]
    Reject,
    /// Ask the agent without the body.
    Skip,
}

/// An agent's circuit breaker: after `failures` failed calls in a row, the most recent within
/// `window` of the first, the agent is not called for `open_for`; `on_error` applies at once
/// meanwhile. Then one call is tried: success closes the breaker, failure opens it again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct AgentBreaker {
    /// Failed calls in a row that open the breaker; `0` turns it off.
    pub failures: u32,
    /// The failures must fall within this time.
    pub window: Duration,
    /// How long the breaker stays open.
    pub open_for: Duration,
}

impl Default for AgentBreaker {
    fn default() -> Self {
        Self {
            failures: 5,
            window: Duration::from_secs(10),
            open_for: Duration::from_secs(30),
        }
    }
}

/// Forward authentication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[schemars(inline)]
pub struct ForwardAuthConfig {
    /// Authentication endpoint. A 2xx answer allows the request; anything else is returned to
    /// the client.
    pub address: HttpUrl,
    /// Response headers of the auth service copied to the forwarded request.
    #[serde(default)]
    pub copy_headers: Vec<String>,
    /// Request headers sent to the auth service (all when empty).
    #[serde(default)]
    pub request_headers: Vec<String>,
    /// Time allowed for the auth service. Requests fail closed on timeout.
    #[serde(default = "five_seconds")]
    pub timeout: Duration,
    /// Trust `X-Forwarded-*` headers already present on the request.
    #[serde(default)]
    pub trust_forward_header: bool,
}

const fn five_seconds() -> Duration {
    Duration::from_secs(5)
}

/// A list of client networks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[schemars(inline)]
pub struct IpListConfig {
    /// IP addresses or CIDR ranges.
    pub cidrs: Vec<IpNetwork>,
}

/// Token-bucket rate limit: `average` requests per `period`, bursts up to `burst`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[schemars(inline)]
pub struct RateLimitConfig {
    /// What to count by.
    #[serde(default)]
    pub key: RateLimitKey,
    /// Requests allowed per `period` on average.
    pub average: u32,
    /// Largest burst; defaults to `average`.
    #[serde(default)]
    pub burst: Option<u32>,
    /// Period of `average`.
    #[serde(default = "one_second")]
    pub period: Duration,
    /// Group → limit for consumers in that group, with `key: consumer`. The first of the
    /// consumer's groups (in its `groups` order) that has an override wins.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub overrides: BTreeMap<String, crate::gateway::RateOverride>,
    /// `draft` adds `RateLimit-Policy` and `RateLimit` to responses
    /// (`draft-ietf-httpapi-ratelimit-headers-11`). Off by default.
    #[serde(default)]
    pub headers: crate::gateway::LimitHeaders,
}

const fn one_second() -> Duration {
    Duration::from_secs(1)
}

/// Requests in flight per key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[schemars(inline)]
pub struct InFlightConfig {
    /// Requests in flight allowed per key.
    pub amount: u32,
    /// What to count by.
    #[serde(default)]
    pub key: RateLimitKey,
    /// Requests over the limit that wait for a slot; more get `429` at once.
    #[serde(default)]
    pub queue: u32,
    /// How long a queued request waits before it gets `429`.
    #[serde(default = "five_seconds")]
    pub queue_timeout: Duration,
}

/// Response bytes per second per key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[schemars(inline)]
pub struct BandwidthConfig {
    /// Bytes per second, e.g. `1MiB`.
    pub rate: ByteSize,
    /// Bytes that may be sent at once before the rate applies; defaults to `rate`.
    #[serde(default)]
    pub burst: Option<ByteSize>,
    /// What to count by.
    #[serde(default)]
    pub key: RateLimitKey,
}

/// Cross-origin resource sharing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[schemars(inline)]
pub struct CorsConfig {
    /// Allowed origins (`https://app.example.com`) or `*`.
    pub allowed_origins: Vec<String>,
    /// Allowed methods.
    #[serde(default = "default_cors_methods")]
    pub allowed_methods: Vec<String>,
    /// Allowed request headers.
    #[serde(default)]
    pub allowed_headers: Vec<String>,
    /// Response headers exposed to scripts.
    #[serde(default)]
    pub exposed_headers: Vec<String>,
    /// Allow cookies and credentials. Not allowed together with `*`.
    #[serde(default)]
    pub allow_credentials: bool,
    /// How long browsers may cache the preflight answer.
    #[serde(default)]
    pub max_age: Option<Duration>,
}

fn default_cors_methods() -> Vec<String> {
    ["GET", "HEAD", "POST"].map(str::to_owned).to_vec()
}

/// Response compression.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
#[schemars(inline)]
pub struct CompressConfig {
    /// Algorithms offered, in order of preference.
    pub algorithms: Vec<CompressAlgorithm>,
    /// Smallest response compressed.
    pub min_size: ByteSize,
    /// Content types to compress; common text types when empty.
    pub content_types: Vec<String>,
}

impl Default for CompressConfig {
    fn default() -> Self {
        Self {
            algorithms: vec![
                CompressAlgorithm::Zstd,
                CompressAlgorithm::Br,
                CompressAlgorithm::Gzip,
            ],
            min_size: ByteSize::kib(1),
            content_types: Vec::new(),
        }
    }
}

/// Compression algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CompressAlgorithm {
    /// gzip.
    Gzip,
    /// Brotli.
    Br,
    /// Zstandard.
    Zstd,
}

/// Custom error pages for selected status codes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[schemars(inline)]
pub struct ErrorsConfig {
    /// Status codes or ranges, e.g. `404` or `500-599`.
    pub status: Vec<String>,
    /// Static HTML file to serve. Set this or `service`.
    #[serde(default)]
    pub file: Option<PathBuf>,
    /// Service that renders the error page. Set this or `file`.
    #[serde(default)]
    pub service: Option<String>,
    /// Path requested from `service`; `{status}` is replaced by the code.
    #[serde(default)]
    pub path: Option<String>,
}

/// Maintenance mode: answer every request with a fixed status and page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
#[schemars(inline)]
pub struct MaintenanceConfig {
    /// Turn maintenance mode on.
    pub enabled: bool,
    /// Status code returned.
    pub status: u16,
    /// HTML page to serve.
    pub file: Option<PathBuf>,
    /// `Retry-After` value sent to clients.
    pub retry_after: Option<Duration>,
    /// Clients that still reach the service (e.g. your office).
    pub allow: Vec<IpNetwork>,
}

impl Default for MaintenanceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            status: 503,
            file: None,
            retry_after: None,
            allow: Vec::new(),
        }
    }
}

/// Static files from a directory (F-WEB-01, ADR-0026).
///
/// The directory is on ReverseDock's file system (with Docker, a volume mounted into the
/// ReverseDock container). It is opened once when the configuration is applied. Requests are
/// answered with strong `ETag`s, `Last-Modified`, conditional requests, byte ranges and
/// precompressed sidecar files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[schemars(inline)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent switches of the YAML model"
)]
pub struct StaticConfig {
    /// Directory to serve. It must exist and be a directory when the configuration is applied.
    pub root: PathBuf,
    /// File names tried, in order, for a request that names a directory.
    #[serde(default = "default_index")]
    pub index: Vec<String>,
    /// File served (with status 200) for a GET or HEAD whose last path segment has no `.` and
    /// that names no file, e.g. `/index.html` for a single-page app. Off when unset.
    #[serde(default)]
    pub fallback: Option<String>,
    /// Path prefixes that never get the `fallback`, e.g. `/api/`; they stay `404`.
    #[serde(default)]
    pub fallback_except: Vec<String>,
    /// Precompressed sidecar files (`app.js.zst`, `app.js.br`, `app.js.gz`) served to clients
    /// that accept the coding, in this order of preference. `[]` turns them off.
    #[serde(default = "default_precompressed")]
    pub precompressed: Vec<CompressAlgorithm>,
    /// Which symbolic links are followed.
    #[serde(default)]
    pub symlinks: SymlinkPolicy,
    /// Files and directories whose name starts with `.` (`.env`, `.git/`).
    #[serde(default)]
    pub hidden: HiddenFiles,
    /// List a directory that has no `index` file (F-WEB-02): HTML, or JSON for clients that
    /// prefer it in `Accept`. Off by default. Follows `hidden` and `symlinks`: names a request
    /// would be refused are not listed. At most 10,000 entries, sorted by name. A directory
    /// that exists is listed instead of getting the `fallback`.
    #[serde(default)]
    pub listing: bool,
    /// Redirect (`308`) a directory path without a trailing slash to the path with one when the
    /// directory has an index file, or is listed.
    #[serde(default = "crate::defaults::yes")]
    pub directory_redirect: bool,
    /// Most byte ranges answered in one request, from 1 to 16. A request for more gets the
    /// whole file (`200`); more than 1 allows `multipart/byteranges` answers.
    #[serde(default = "one")]
    pub max_ranges: u32,
    /// `Cache-Control` of served files.
    #[serde(default)]
    pub cache_control: StaticCacheControl,
    /// Send `X-Content-Type-Options: nosniff`.
    #[serde(default = "crate::defaults::yes")]
    pub nosniff: bool,
    /// File extension → media type, overriding the built-in table, e.g. `{ ts: text/typescript }`.
    #[serde(default)]
    pub types: BTreeMap<String, String>,
    /// Send requests that name no file (and methods other than GET and HEAD) on to the route's
    /// service instead of answering `404` or `405`. The route then needs a service.
    #[serde(default)]
    pub pass_through: bool,
}

fn default_index() -> Vec<String> {
    vec!["index.html".to_owned()]
}

fn default_precompressed() -> Vec<CompressAlgorithm> {
    vec![
        CompressAlgorithm::Zstd,
        CompressAlgorithm::Br,
        CompressAlgorithm::Gzip,
    ]
}

const fn one() -> u32 {
    1
}

/// Which symbolic links `static` follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SymlinkPolicy {
    /// None: a path with a symbolic link in it answers `404`.
    #[default]
    None,
    /// Links that stay inside `root`; the kernel refuses any resolution that leaves it.
    WithinRoot,
    /// Every link, also out of `root`. `rdock validate` warns about it.
    All,
}

/// How `static` treats names starting with `.`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HiddenFiles {
    /// A path with any component starting with `.` answers `404`.
    #[default]
    Refuse,
    /// Hidden files and directories are served like any other.
    Allow,
}

/// `Cache-Control` of static files: a default and overrides by path prefix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct StaticCacheControl {
    /// Value for files no prefix matches. `no-cache` makes clients revalidate with the `ETag`.
    #[serde(default = "no_cache")]
    pub default: String,
    /// Path prefix (starting with `/`, compared literally, not a glob) → value; the longest
    /// matching prefix wins, e.g. `/assets/: public, max-age=31536000, immutable` for files
    /// with hashed names.
    #[serde(flatten)]
    pub paths: BTreeMap<String, String>,
}

impl Default for StaticCacheControl {
    fn default() -> Self {
        Self {
            default: no_cache(),
            paths: BTreeMap::new(),
        }
    }
}

fn no_cache() -> String {
    "no-cache".to_owned()
}
