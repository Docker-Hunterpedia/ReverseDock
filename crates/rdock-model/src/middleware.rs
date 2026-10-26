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
    /// Cross-origin resource sharing.
    Cors(CorsConfig),
    /// Response compression.
    Compress(CompressConfig),
    /// Custom error pages.
    Errors(ErrorsConfig),
    /// Maintenance mode.
    Maintenance(MaintenanceConfig),
}

/// Header changes for requests (to the backend) and responses (to the client).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
#[schemars(inline)]
pub struct HeadersConfig {
    /// Changes to the request sent to the backend.
    pub request: HeaderRules,
    /// Changes to the response sent to the client.
    pub response: HeaderRules,
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

/// Redirect settings: `scheme` alone, or `regex` with `replacement`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[schemars(inline)]
pub struct RedirectConfig {
    /// Redirect to this scheme, keeping host, path and query.
    #[serde(default)]
    pub scheme: Option<RedirectScheme>,
    /// Regular expression matched against the full request URL.
    #[serde(default)]
    pub regex: Option<String>,
    /// Target URL; may use `$1`, `${name}` groups from `regex`.
    #[serde(default)]
    pub replacement: Option<String>,
    /// `301`/`308` when true, `302`/`307` when false.
    #[serde(default = "crate::defaults::yes")]
    pub permanent: bool,
    /// Port for scheme redirects when it is not the scheme's default.
    #[serde(default)]
    pub port: Option<u16>,
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

/// Basic authentication. Passwords must be argon2id or bcrypt hashes.
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
}

const fn one_second() -> Duration {
    Duration::from_secs(1)
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
            algorithms: vec![CompressAlgorithm::Gzip],
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
