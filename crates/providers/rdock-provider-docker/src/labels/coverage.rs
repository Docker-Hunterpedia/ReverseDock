//! The documented Traefik label subset (ADR-0033): every Traefik v3.7 Docker label with what
//! ReverseDock does with it. One table feeds the conformance test (each row needs a fixture,
//! and the translator must accept exactly the rows marked exact or approximate),
//! `rdock migrate traefik` (each label's level in the report), the generated
//! `tests/conformance/traefik-labels/coverage.json`, the compatibility snapshot
//! `schema/compat/labels.json` and the website's "supported Traefik subset" table.
//!
//! The rows are the keys of Traefik's generated label list on the v3.7 branch
//! (<https://github.com/traefik/traefik/blob/v3.7/docs/content/reference/dynamic-configuration/docker-labels.yml>,
//! read 2026-11-14), plus the options the per-middleware pages of the v3.7 reference list and
//! that file lacks (`retry.status`, `retry.disableRetryOnNetworkError`,
//! `retry.retryNonIdempotentMethod`, `retry.timeout`, `retry.maxRequestBodyBytes`, the
//! `encodedCharacters` middleware; <https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/overview/>,
//! read 2026-11-14), and the provider labels of the Docker and Swarm provider pages. Semantics
//! were read from the same v3.7 pages; a row is **exact** only when the behaviour is the same,
//! otherwise it is **approximate** and says what differs.

use serde::Serialize;

/// The Traefik minor release the subset is pinned to.
pub const TRAEFIK_VERSION: &str = "v3.7";

/// The reference the rows were checked against.
pub const TRAEFIK_REFERENCE: &str =
    "https://doc.traefik.io/traefik/reference/routing-configuration/other-providers/docker/";

/// The day the rows were checked against [`TRAEFIK_REFERENCE`].
pub const CHECKED: &str = "2026-11-14";

/// What ReverseDock does with one Traefik label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Coverage {
    /// Translated with the same behaviour.
    Exact,
    /// Translated; the behaviour differs in the way the row's note says.
    Approximate,
    /// Not translated: it needs a decision or a setting outside labels (the note says which).
    Manual,
    /// No equivalent; the label is reported and ignored (the note says why).
    None,
}

impl Coverage {
    /// `exact`, `approximate`, `manual` or `none`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Approximate => "approximate",
            Self::Manual => "manual",
            Self::None => "none",
        }
    }

    /// Whether the translator takes the label.
    #[must_use]
    pub const fn translated(self) -> bool {
        matches!(self, Self::Exact | Self::Approximate)
    }
}

/// One Traefik label of the table.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct TraefikOption {
    /// The label key in lower case with user-chosen parts replaced: `<name>` for object names,
    /// `<header>` for header names, `[n]` for list indices, `<status>`, `<store>`,
    /// `<plugin>.<option>`.
    pub key: &'static str,
    /// What happens to it.
    pub status: Coverage,
    /// What it becomes (empty when nothing).
    pub rdock: &'static str,
    /// Approximate: what differs. Manual: what to do. None: why there is no equivalent.
    pub note: &'static str,
    /// A value for the table's own test (the translator must take it exactly when the row is
    /// exact or approximate).
    #[serde(skip)]
    pub example: &'static str,
    /// Where the row is proven when no Docker fixture can be (the Swarm provider's labels).
    #[serde(skip_serializing_if = "str::is_empty")]
    pub proven_by: &'static str,
}

const fn row(
    key: &'static str,
    status: Coverage,
    rdock: &'static str,
    note: &'static str,
    example: &'static str,
) -> TraefikOption {
    TraefikOption {
        key,
        status,
        rdock,
        note,
        example,
        proven_by: "",
    }
}

const fn exact(key: &'static str, rdock: &'static str, example: &'static str) -> TraefikOption {
    row(key, Coverage::Exact, rdock, "", example)
}

const fn approx(
    key: &'static str,
    rdock: &'static str,
    note: &'static str,
    example: &'static str,
) -> TraefikOption {
    row(key, Coverage::Approximate, rdock, note, example)
}

const fn manual(key: &'static str, note: &'static str, example: &'static str) -> TraefikOption {
    row(key, Coverage::Manual, "", note, example)
}

const fn none(key: &'static str, note: &'static str, example: &'static str) -> TraefikOption {
    row(key, Coverage::None, "", note, example)
}

// Notes shared by several rows.
const IP_STRATEGY: &str = "the client IP is the one resolved from `security.trusted_proxies` (one setting for the whole proxy), not chosen per middleware";
const REDIS: &str = "a Redis endpoint is not read; cluster-wide limits are `scope: cluster` on the middleware with `cluster.limits` (ADR-0031)";
const CIRCUIT: &str = "circuit-breaker expressions are not carried over: set `health.passive` and `max_requests` on the service in rdock.yaml";
const DIGEST: &str = "digest authentication is not offered (it needs reversible or MD5-derived secrets); use `basic_auth` over HTTPS, `forward_auth` or `oidc`";
const ENCODED: &str = "encoded reserved characters in paths are always allowed and never act as separators (ADR-0014); there is nothing to switch";
const FA_EXTRA: &str = "not offered by `forward_auth`";
const SSL_V2: &str =
    "removed in Traefik v3 (only in its old label list); use a `redirectscheme` middleware";
const INFO: &str = "the certificate is passed in `X-Forwarded-Tls-Client-Cert` (`forward: traefik`) whatever fields are selected; the per-field selection is not kept";
const OBSERVABILITY: &str = "access logs, metrics and tracing are switched for the whole proxy (`observability`), not per router";
const TCP_TLS: &str = "a terminating TCP route uses its listener's TLS settings and certificates: set them on `listeners.<name>.tls`";
const STORES: &str =
    "the default certificate is `defaults.certificate` (a key of `certificates`) in rdock.yaml";
const HEALTH_DEFAULTS: &str = "unset settings take ReverseDock's defaults (every 10s, a 2s timeout, 2 passes or 3 failures to change state); Traefik's defaults are every 30s with a 5s timeout";

/// Every Traefik v3.7 Docker label, sorted by key.
pub static TRAEFIK_OPTIONS: &[TraefikOption] = &[
    // --- Provider labels -----------------------------------------------------------------
    TraefikOption {
        proven_by: "crates/providers/rdock-provider-swarm/tests/translate.rs",
        ..exact(
            "traefik.swarm.lbswarm",
            "Swarm only: route to the service's virtual IP (`rdock.swarm.lbswarm`)",
            "true",
        )
    },
    TraefikOption {
        proven_by: "crates/providers/rdock-provider-swarm/tests/translate.rs",
        ..exact(
            "traefik.swarm.network",
            "Swarm only: the network used to reach tasks (`rdock.network`)",
            "proxy",
        )
    },
    exact(
        "traefik.docker.network",
        "`rdock.network`: the network used to reach the container",
        "web",
    ),
    none(
        "traefik.docker.allownonrunning",
        "only running containers are routed",
        "true",
    ),
    exact(
        "traefik.enable",
        "exposes the container (`rdock.enable`)",
        "true",
    ),
    none(
        "traefik.tls.stores.<store>.defaultgeneratedcert.domain.main",
        STORES,
        "example.com",
    ),
    none(
        "traefik.tls.stores.<store>.defaultgeneratedcert.domain.sans",
        STORES,
        "www.example.com",
    ),
    none(
        "traefik.tls.stores.<store>.defaultgeneratedcert.resolver",
        STORES,
        "le",
    ),
    // --- HTTP middlewares ----------------------------------------------------------------
    exact(
        "traefik.http.middlewares.<name>.addprefix.prefix",
        "`add_prefix.prefix`",
        "/api",
    ),
    none(
        "traefik.http.middlewares.<name>.basicauth.headerfield",
        "the user name is not passed on in a header",
        "X-User",
    ),
    exact(
        "traefik.http.middlewares.<name>.basicauth.realm",
        "`basic_auth.realm`",
        "staff",
    ),
    exact(
        "traefik.http.middlewares.<name>.basicauth.removeheader",
        "`basic_auth.remove_header`",
        "true",
    ),
    exact(
        "traefik.http.middlewares.<name>.basicauth.users",
        "`basic_auth.users` (bcrypt and argon2id; Apache MD5 and SHA-1 with a warning)",
        "alice:$2y$05$abcdefghijklmnopqrstuu5Lr1G6eJNlZtuVPWTn4lHBJDU2P8m8a",
    ),
    manual(
        "traefik.http.middlewares.<name>.basicauth.usersfile",
        "labels cannot name files on the proxy's host: set `basic_auth.users_file` on the middleware in rdock.yaml",
        "/etc/users",
    ),
    manual(
        "traefik.http.middlewares.<name>.buffering.maxrequestbodybytes",
        "set `max_body` on the routes in rdock.yaml (or `rdock.routes.<name>.max_body`)",
        "1000000",
    ),
    none(
        "traefik.http.middlewares.<name>.buffering.maxresponsebodybytes",
        "responses are streamed; there is no response size limit",
        "1000000",
    ),
    none(
        "traefik.http.middlewares.<name>.buffering.memrequestbodybytes",
        "bodies are streamed, not spooled to disk",
        "1000000",
    ),
    none(
        "traefik.http.middlewares.<name>.buffering.memresponsebodybytes",
        "responses are streamed, not spooled to disk",
        "1000000",
    ),
    none(
        "traefik.http.middlewares.<name>.buffering.retryexpression",
        "retries are a service setting (`retries`)",
        "IsNetworkError()",
    ),
    exact(
        "traefik.http.middlewares.<name>.chain.middlewares",
        "inlined: routes that use the chain list its middlewares in its place",
        "a,b",
    ),
    manual(
        "traefik.http.middlewares.<name>.circuitbreaker.checkperiod",
        CIRCUIT,
        "10s",
    ),
    manual(
        "traefik.http.middlewares.<name>.circuitbreaker.expression",
        CIRCUIT,
        "NetworkErrorRatio() > 0.5",
    ),
    manual(
        "traefik.http.middlewares.<name>.circuitbreaker.fallbackduration",
        CIRCUIT,
        "10s",
    ),
    manual(
        "traefik.http.middlewares.<name>.circuitbreaker.recoveryduration",
        CIRCUIT,
        "10s",
    ),
    manual(
        "traefik.http.middlewares.<name>.circuitbreaker.responsecode",
        CIRCUIT,
        "503",
    ),
    approx(
        "traefik.http.middlewares.<name>.compress",
        "`compress` with its defaults",
        "ReverseDock compresses common text types only (Traefik: every type not excluded, and it sniffs a missing `Content-Type`), and prefers zstd, then br, then gzip (Traefik: gzip, br, zstd)",
        "true",
    ),
    none(
        "traefik.http.middlewares.<name>.compress.defaultencoding",
        "a response is compressed only when the client sends `Accept-Encoding`",
        "gzip",
    ),
    exact(
        "traefik.http.middlewares.<name>.compress.encodings",
        "`compress.algorithms`, in the same order of preference",
        "gzip,br",
    ),
    none(
        "traefik.http.middlewares.<name>.compress.excludedcontenttypes",
        "`compress.content_types` is an allow-list",
        "image/png",
    ),
    approx(
        "traefik.http.middlewares.<name>.compress.includedcontenttypes",
        "`compress.content_types`",
        "`text/event-stream` and `application/grpc` are never compressed, even when listed",
        "text/html",
    ),
    exact(
        "traefik.http.middlewares.<name>.compress.minresponsebodybytes",
        "`compress.min_size`",
        "2048",
    ),
    none(
        "traefik.http.middlewares.<name>.contenttype",
        "a missing `Content-Type` is never guessed",
        "true",
    ),
    none(
        "traefik.http.middlewares.<name>.contenttype.autodetect",
        "a missing `Content-Type` is never guessed",
        "true",
    ),
    none(
        "traefik.http.middlewares.<name>.digestauth.headerfield",
        DIGEST,
        "X-User",
    ),
    none(
        "traefik.http.middlewares.<name>.digestauth.realm",
        DIGEST,
        "staff",
    ),
    none(
        "traefik.http.middlewares.<name>.digestauth.removeheader",
        DIGEST,
        "true",
    ),
    none(
        "traefik.http.middlewares.<name>.digestauth.users",
        DIGEST,
        "alice:staff:0123456789abcdef0123456789abcdef",
    ),
    none(
        "traefik.http.middlewares.<name>.digestauth.usersfile",
        DIGEST,
        "/etc/users",
    ),
    none(
        "traefik.http.middlewares.<name>.encodedcharacters.allowencodedbackslash",
        ENCODED,
        "true",
    ),
    none(
        "traefik.http.middlewares.<name>.encodedcharacters.allowencodedhash",
        ENCODED,
        "true",
    ),
    none(
        "traefik.http.middlewares.<name>.encodedcharacters.allowencodedpercent",
        ENCODED,
        "true",
    ),
    none(
        "traefik.http.middlewares.<name>.encodedcharacters.allowencodedquestionmark",
        ENCODED,
        "true",
    ),
    none(
        "traefik.http.middlewares.<name>.encodedcharacters.allowencodedsemicolon",
        ENCODED,
        "true",
    ),
    none(
        "traefik.http.middlewares.<name>.encodedcharacters.allowencodedslash",
        ENCODED,
        "true",
    ),
    none(
        "traefik.http.middlewares.<name>.errors.errorrequestheaders",
        "the error page request carries no extra headers",
        "X-Original",
    ),
    approx(
        "traefik.http.middlewares.<name>.errors.query",
        "`errors.path`",
        "only `{status}` is replaced; Traefik also replaces `{originalStatus}` and `{url}`",
        "/{status}.html",
    ),
    exact(
        "traefik.http.middlewares.<name>.errors.service",
        "`errors.service`",
        "pages",
    ),
    exact(
        "traefik.http.middlewares.<name>.errors.status",
        "`errors.status`",
        "500-599",
    ),
    none(
        "traefik.http.middlewares.<name>.errors.statusrewrites.<status>",
        "the status of the error page response is the original one",
        "404",
    ),
    none(
        "traefik.http.middlewares.<name>.forwardauth.addauthcookiestoresponse",
        FA_EXTRA,
        "Session",
    ),
    approx(
        "traefik.http.middlewares.<name>.forwardauth.address",
        "`forward_auth.address`",
        "an auth service that cannot be reached gives `502` (Traefik: `500`); the auth request times out after 5s",
        "http://auth:9091/verify",
    ),
    exact(
        "traefik.http.middlewares.<name>.forwardauth.authrequestheaders",
        "`forward_auth.request_headers`",
        "Cookie,Authorization",
    ),
    exact(
        "traefik.http.middlewares.<name>.forwardauth.authresponseheaders",
        "`forward_auth.copy_headers`",
        "Remote-User",
    ),
    none(
        "traefik.http.middlewares.<name>.forwardauth.authresponseheadersregex",
        FA_EXTRA,
        "^X-",
    ),
    none(
        "traefik.http.middlewares.<name>.forwardauth.forwardbody",
        "the body is not sent to the auth service (an `agent` middleware with `protocol: forward` can)",
        "true",
    ),
    none(
        "traefik.http.middlewares.<name>.forwardauth.headerfield",
        FA_EXTRA,
        "X-User",
    ),
    none(
        "traefik.http.middlewares.<name>.forwardauth.maxbodysize",
        "the body is not sent to the auth service",
        "1024",
    ),
    none(
        "traefik.http.middlewares.<name>.forwardauth.maxresponsebodysize",
        FA_EXTRA,
        "1024",
    ),
    none(
        "traefik.http.middlewares.<name>.forwardauth.preservelocationheader",
        FA_EXTRA,
        "true",
    ),
    none(
        "traefik.http.middlewares.<name>.forwardauth.preserverequestmethod",
        FA_EXTRA,
        "true",
    ),
    none(
        "traefik.http.middlewares.<name>.forwardauth.tls.ca",
        "TLS settings for the auth service are not offered; it is reached with the system roots",
        "/ca.pem",
    ),
    none(
        "traefik.http.middlewares.<name>.forwardauth.tls.caoptional",
        "TLS settings for the auth service are not offered",
        "true",
    ),
    none(
        "traefik.http.middlewares.<name>.forwardauth.tls.cert",
        "client certificates to the auth service are not offered",
        "/c.pem",
    ),
    none(
        "traefik.http.middlewares.<name>.forwardauth.tls.insecureskipverify",
        "the auth service's certificate is always verified",
        "true",
    ),
    none(
        "traefik.http.middlewares.<name>.forwardauth.tls.key",
        "client certificates to the auth service are not offered",
        "/k.pem",
    ),
    exact(
        "traefik.http.middlewares.<name>.forwardauth.trustforwardheader",
        "`forward_auth.trust_forward_header`",
        "true",
    ),
    none(
        "traefik.http.middlewares.<name>.grpcweb.alloworigins",
        "the `grpc_web` middleware has no origin list; add it in rdock.yaml with a `cors` middleware",
        "*",
    ),
    approx(
        "traefik.http.middlewares.<name>.headers.accesscontrolallowcredentials",
        "`cors.allow_credentials` (a `cors` middleware added next to the headers one)",
        "preflight requests are answered `204` (Traefik: `200`)",
        "true",
    ),
    approx(
        "traefik.http.middlewares.<name>.headers.accesscontrolallowheaders",
        "`cors.allowed_headers`",
        "as `accesscontrolallowcredentials`",
        "Content-Type",
    ),
    approx(
        "traefik.http.middlewares.<name>.headers.accesscontrolallowmethods",
        "`cors.allowed_methods`",
        "as `accesscontrolallowcredentials`",
        "GET,POST",
    ),
    approx(
        "traefik.http.middlewares.<name>.headers.accesscontrolalloworiginlist",
        "`cors.allowed_origins`",
        "as `accesscontrolallowcredentials`; without `accesscontrolallowmethods` the preflight allows GET, HEAD and POST (Traefik: none)",
        "https://app.example.com",
    ),
    none(
        "traefik.http.middlewares.<name>.headers.accesscontrolalloworiginlistregex",
        "`cors.allowed_origins` is a list of exact origins",
        "https://.*\\.example\\.com",
    ),
    approx(
        "traefik.http.middlewares.<name>.headers.accesscontrolexposeheaders",
        "`cors.exposed_headers`",
        "as `accesscontrolallowcredentials`",
        "X-Total",
    ),
    approx(
        "traefik.http.middlewares.<name>.headers.accesscontrolmaxage",
        "`cors.max_age`",
        "as `accesscontrolallowcredentials`",
        "600",
    ),
    approx(
        "traefik.http.middlewares.<name>.headers.addvaryheader",
        "always on: the `cors` middleware sends `Vary: Origin`",
        "`Vary` is sent whether or not the label is set",
        "true",
    ),
    none(
        "traefik.http.middlewares.<name>.headers.allowedhosts",
        "routes match hosts; there is no separate host allow-list",
        "example.com",
    ),
    exact(
        "traefik.http.middlewares.<name>.headers.browserxssfilter",
        "`response.set` of `X-XSS-Protection: 1; mode=block`",
        "true",
    ),
    exact(
        "traefik.http.middlewares.<name>.headers.contentsecuritypolicy",
        "`response.set` of `Content-Security-Policy`",
        "default-src 'self'",
    ),
    exact(
        "traefik.http.middlewares.<name>.headers.contentsecuritypolicyreportonly",
        "`response.set` of `Content-Security-Policy-Report-Only`",
        "default-src 'self'",
    ),
    exact(
        "traefik.http.middlewares.<name>.headers.contenttypenosniff",
        "`response.set` of `X-Content-Type-Options: nosniff`",
        "true",
    ),
    exact(
        "traefik.http.middlewares.<name>.headers.custombrowserxssvalue",
        "`response.set` of `X-XSS-Protection` (overrides `browserxssfilter`)",
        "0",
    ),
    exact(
        "traefik.http.middlewares.<name>.headers.customframeoptionsvalue",
        "`response.set` of `X-Frame-Options` (overrides `framedeny`)",
        "SAMEORIGIN",
    ),
    exact(
        "traefik.http.middlewares.<name>.headers.customrequestheaders.<header>",
        "`request.set` (an empty value: `request.remove`)",
        "1",
    ),
    exact(
        "traefik.http.middlewares.<name>.headers.customresponseheaders.<header>",
        "`response.set` (an empty value: `response.remove`)",
        "1",
    ),
    none(
        "traefik.http.middlewares.<name>.headers.featurepolicy",
        "removed in Traefik v3 (only in its old label list); use `permissionspolicy`",
        "camera 'none'",
    ),
    none(
        "traefik.http.middlewares.<name>.headers.forcestsheader",
        "HSTS is sent on HTTPS responses only",
        "true",
    ),
    exact(
        "traefik.http.middlewares.<name>.headers.framedeny",
        "`response.set` of `X-Frame-Options: DENY`",
        "true",
    ),
    none(
        "traefik.http.middlewares.<name>.headers.hostsproxyheaders",
        "the host is never taken from a proxy header",
        "X-Forwarded-Host",
    ),
    none(
        "traefik.http.middlewares.<name>.headers.isdevelopment",
        "there is no development mode",
        "true",
    ),
    exact(
        "traefik.http.middlewares.<name>.headers.permissionspolicy",
        "`response.set` of `Permissions-Policy`",
        "camera=()",
    ),
    none(
        "traefik.http.middlewares.<name>.headers.publickey",
        "HPKP is obsolete and not offered",
        "pin-sha256=\"x\"",
    ),
    exact(
        "traefik.http.middlewares.<name>.headers.referrerpolicy",
        "`response.set` of `Referrer-Policy`",
        "no-referrer",
    ),
    none(
        "traefik.http.middlewares.<name>.headers.sslforcehost",
        SSL_V2,
        "true",
    ),
    none(
        "traefik.http.middlewares.<name>.headers.sslhost",
        SSL_V2,
        "example.com",
    ),
    none(
        "traefik.http.middlewares.<name>.headers.sslproxyheaders.<header>",
        "HTTPS is never inferred from a request header",
        "https",
    ),
    none(
        "traefik.http.middlewares.<name>.headers.sslredirect",
        SSL_V2,
        "true",
    ),
    none(
        "traefik.http.middlewares.<name>.headers.ssltemporaryredirect",
        SSL_V2,
        "true",
    ),
    exact(
        "traefik.http.middlewares.<name>.headers.stsincludesubdomains",
        "`hsts.include_subdomains`",
        "true",
    ),
    exact(
        "traefik.http.middlewares.<name>.headers.stspreload",
        "`hsts.preload`",
        "true",
    ),
    exact(
        "traefik.http.middlewares.<name>.headers.stsseconds",
        "`hsts.max_age`",
        "31536000",
    ),
    exact(
        "traefik.http.middlewares.<name>.inflightreq.amount",
        "`in_flight.amount`",
        "10",
    ),
    none(
        "traefik.http.middlewares.<name>.inflightreq.sourcecriterion.ipstrategy.depth",
        IP_STRATEGY,
        "1",
    ),
    none(
        "traefik.http.middlewares.<name>.inflightreq.sourcecriterion.ipstrategy.excludedips",
        IP_STRATEGY,
        "10.0.0.1",
    ),
    none(
        "traefik.http.middlewares.<name>.inflightreq.sourcecriterion.ipstrategy.ipv6subnet",
        IP_STRATEGY,
        "64",
    ),
    exact(
        "traefik.http.middlewares.<name>.inflightreq.sourcecriterion.requestheadername",
        "`in_flight.key: header:<Name>`",
        "X-Tenant",
    ),
    none(
        "traefik.http.middlewares.<name>.inflightreq.sourcecriterion.requesthost",
        "only the client IP and a request header are keys",
        "true",
    ),
    none(
        "traefik.http.middlewares.<name>.ipallowlist.ipstrategy",
        IP_STRATEGY,
        "true",
    ),
    none(
        "traefik.http.middlewares.<name>.ipallowlist.ipstrategy.depth",
        IP_STRATEGY,
        "1",
    ),
    none(
        "traefik.http.middlewares.<name>.ipallowlist.ipstrategy.excludedips",
        IP_STRATEGY,
        "10.0.0.1",
    ),
    none(
        "traefik.http.middlewares.<name>.ipallowlist.ipstrategy.ipv6subnet",
        IP_STRATEGY,
        "64",
    ),
    none(
        "traefik.http.middlewares.<name>.ipallowlist.rejectstatuscode",
        "refused clients always get `403`",
        "404",
    ),
    exact(
        "traefik.http.middlewares.<name>.ipallowlist.sourcerange",
        "`ip_allow.cidrs`",
        "10.0.0.0/8",
    ),
    none(
        "traefik.http.middlewares.<name>.ipwhitelist.ipstrategy",
        IP_STRATEGY,
        "true",
    ),
    none(
        "traefik.http.middlewares.<name>.ipwhitelist.ipstrategy.depth",
        IP_STRATEGY,
        "1",
    ),
    none(
        "traefik.http.middlewares.<name>.ipwhitelist.ipstrategy.excludedips",
        IP_STRATEGY,
        "10.0.0.1",
    ),
    none(
        "traefik.http.middlewares.<name>.ipwhitelist.ipstrategy.ipv6subnet",
        IP_STRATEGY,
        "64",
    ),
    exact(
        "traefik.http.middlewares.<name>.ipwhitelist.sourcerange",
        "`ip_allow.cidrs` (the old name of `ipallowlist`)",
        "10.0.0.0/8",
    ),
    approx(
        "traefik.http.middlewares.<name>.passtlsclientcert.info.issuer.commonname",
        "`client_cert` with `required: false`, `forward: traefik`",
        INFO,
        "true",
    ),
    approx(
        "traefik.http.middlewares.<name>.passtlsclientcert.info.issuer.country",
        "as `info.issuer.commonname`",
        INFO,
        "true",
    ),
    approx(
        "traefik.http.middlewares.<name>.passtlsclientcert.info.issuer.domaincomponent",
        "as `info.issuer.commonname`",
        INFO,
        "true",
    ),
    approx(
        "traefik.http.middlewares.<name>.passtlsclientcert.info.issuer.locality",
        "as `info.issuer.commonname`",
        INFO,
        "true",
    ),
    approx(
        "traefik.http.middlewares.<name>.passtlsclientcert.info.issuer.organization",
        "as `info.issuer.commonname`",
        INFO,
        "true",
    ),
    approx(
        "traefik.http.middlewares.<name>.passtlsclientcert.info.issuer.province",
        "as `info.issuer.commonname`",
        INFO,
        "true",
    ),
    approx(
        "traefik.http.middlewares.<name>.passtlsclientcert.info.issuer.serialnumber",
        "as `info.issuer.commonname`",
        INFO,
        "true",
    ),
    approx(
        "traefik.http.middlewares.<name>.passtlsclientcert.info.notafter",
        "as `info.issuer.commonname`",
        INFO,
        "true",
    ),
    approx(
        "traefik.http.middlewares.<name>.passtlsclientcert.info.notbefore",
        "as `info.issuer.commonname`",
        INFO,
        "true",
    ),
    approx(
        "traefik.http.middlewares.<name>.passtlsclientcert.info.sans",
        "as `info.issuer.commonname`",
        INFO,
        "true",
    ),
    approx(
        "traefik.http.middlewares.<name>.passtlsclientcert.info.serialnumber",
        "as `info.issuer.commonname`",
        INFO,
        "true",
    ),
    approx(
        "traefik.http.middlewares.<name>.passtlsclientcert.info.subject.commonname",
        "as `info.issuer.commonname`",
        INFO,
        "true",
    ),
    approx(
        "traefik.http.middlewares.<name>.passtlsclientcert.info.subject.country",
        "as `info.issuer.commonname`",
        INFO,
        "true",
    ),
    approx(
        "traefik.http.middlewares.<name>.passtlsclientcert.info.subject.domaincomponent",
        "as `info.issuer.commonname`",
        INFO,
        "true",
    ),
    approx(
        "traefik.http.middlewares.<name>.passtlsclientcert.info.subject.locality",
        "as `info.issuer.commonname`",
        INFO,
        "true",
    ),
    approx(
        "traefik.http.middlewares.<name>.passtlsclientcert.info.subject.organization",
        "as `info.issuer.commonname`",
        INFO,
        "true",
    ),
    approx(
        "traefik.http.middlewares.<name>.passtlsclientcert.info.subject.organizationalunit",
        "as `info.issuer.commonname`",
        INFO,
        "true",
    ),
    approx(
        "traefik.http.middlewares.<name>.passtlsclientcert.info.subject.province",
        "as `info.issuer.commonname`",
        INFO,
        "true",
    ),
    approx(
        "traefik.http.middlewares.<name>.passtlsclientcert.info.subject.serialnumber",
        "as `info.issuer.commonname`",
        INFO,
        "true",
    ),
    approx(
        "traefik.http.middlewares.<name>.passtlsclientcert.pem",
        "`client_cert` with `required: false`, `forward: traefik`",
        "the PEM is passed in `X-Forwarded-Tls-Client-Cert`; the client certificate is requested on the listener (`listeners.<name>.tls.client_auth`)",
        "true",
    ),
    none(
        "traefik.http.middlewares.<name>.plugin.<plugin>.<option>",
        "Traefik (Yaegi) plugins do not run here; ReverseDock's `plugin` type is a native or WASM plugin of its own",
        "v",
    ),
    approx(
        "traefik.http.middlewares.<name>.ratelimit.average",
        "`rate_limit.average`",
        "without `burst`, the burst is `average` (Traefik: 1)",
        "100",
    ),
    exact(
        "traefik.http.middlewares.<name>.ratelimit.burst",
        "`rate_limit.burst`",
        "50",
    ),
    exact(
        "traefik.http.middlewares.<name>.ratelimit.period",
        "`rate_limit.period`",
        "1m",
    ),
    none(
        "traefik.http.middlewares.<name>.ratelimit.redis.db",
        REDIS,
        "0",
    ),
    none(
        "traefik.http.middlewares.<name>.ratelimit.redis.dialtimeout",
        REDIS,
        "5s",
    ),
    none(
        "traefik.http.middlewares.<name>.ratelimit.redis.endpoints",
        REDIS,
        "redis:6379",
    ),
    none(
        "traefik.http.middlewares.<name>.ratelimit.redis.maxactiveconns",
        REDIS,
        "10",
    ),
    none(
        "traefik.http.middlewares.<name>.ratelimit.redis.minidleconns",
        REDIS,
        "1",
    ),
    none(
        "traefik.http.middlewares.<name>.ratelimit.redis.password",
        REDIS,
        "not-a-secret",
    ),
    none(
        "traefik.http.middlewares.<name>.ratelimit.redis.poolsize",
        REDIS,
        "10",
    ),
    none(
        "traefik.http.middlewares.<name>.ratelimit.redis.readtimeout",
        REDIS,
        "3s",
    ),
    none(
        "traefik.http.middlewares.<name>.ratelimit.redis.tls.ca",
        REDIS,
        "/ca.pem",
    ),
    none(
        "traefik.http.middlewares.<name>.ratelimit.redis.tls.cert",
        REDIS,
        "/c.pem",
    ),
    none(
        "traefik.http.middlewares.<name>.ratelimit.redis.tls.insecureskipverify",
        REDIS,
        "true",
    ),
    none(
        "traefik.http.middlewares.<name>.ratelimit.redis.tls.key",
        REDIS,
        "/k.pem",
    ),
    none(
        "traefik.http.middlewares.<name>.ratelimit.redis.username",
        REDIS,
        "rdock",
    ),
    none(
        "traefik.http.middlewares.<name>.ratelimit.redis.writetimeout",
        REDIS,
        "3s",
    ),
    none(
        "traefik.http.middlewares.<name>.ratelimit.sourcecriterion.ipstrategy.depth",
        IP_STRATEGY,
        "1",
    ),
    none(
        "traefik.http.middlewares.<name>.ratelimit.sourcecriterion.ipstrategy.excludedips",
        IP_STRATEGY,
        "10.0.0.1",
    ),
    none(
        "traefik.http.middlewares.<name>.ratelimit.sourcecriterion.ipstrategy.ipv6subnet",
        IP_STRATEGY,
        "64",
    ),
    exact(
        "traefik.http.middlewares.<name>.ratelimit.sourcecriterion.requestheadername",
        "`rate_limit.key: header:<Name>`",
        "X-Api-Key",
    ),
    none(
        "traefik.http.middlewares.<name>.ratelimit.sourcecriterion.requesthost",
        "only the client IP, a request header and consumers are keys",
        "true",
    ),
    exact(
        "traefik.http.middlewares.<name>.redirectregex.permanent",
        "`redirect.permanent`",
        "true",
    ),
    exact(
        "traefik.http.middlewares.<name>.redirectregex.regex",
        "`redirect.regex`",
        "^http://(.*)",
    ),
    exact(
        "traefik.http.middlewares.<name>.redirectregex.replacement",
        "`redirect.replacement`",
        "https://${1}",
    ),
    exact(
        "traefik.http.middlewares.<name>.redirectscheme.permanent",
        "`redirect.permanent`",
        "true",
    ),
    exact(
        "traefik.http.middlewares.<name>.redirectscheme.port",
        "`redirect.port`",
        "443",
    ),
    exact(
        "traefik.http.middlewares.<name>.redirectscheme.scheme",
        "`redirect.scheme`",
        "https",
    ),
    exact(
        "traefik.http.middlewares.<name>.replacepath.path",
        "`replace_path.path`",
        "/new",
    ),
    exact(
        "traefik.http.middlewares.<name>.replacepathregex.regex",
        "`rewrite.regex`",
        "^/old/(.*)",
    ),
    exact(
        "traefik.http.middlewares.<name>.replacepathregex.replacement",
        "`rewrite.replacement`",
        "/new/$1",
    ),
    approx(
        "traefik.http.middlewares.<name>.retry.attempts",
        "`retries.attempts` of the routes' services (minus one: Traefik counts the first try)",
        "retries move from the route to its service, so every route to that service retries; they use a fixed jittered backoff of 25 to 250 ms",
        "4",
    ),
    exact(
        "traefik.http.middlewares.<name>.retry.disableretryonnetworkerror",
        "`retries.on` without `connect` and `reset`",
        "true",
    ),
    none(
        "traefik.http.middlewares.<name>.retry.initialinterval",
        "retries use a fixed jittered backoff (25 to 250 ms)",
        "100ms",
    ),
    none(
        "traefik.http.middlewares.<name>.retry.maxrequestbodybytes",
        "a request whose body was sent is retried only when the body was held (`hold_body`)",
        "1000",
    ),
    exact(
        "traefik.http.middlewares.<name>.retry.retrynonidempotentmethod",
        "`retries.retry_non_idempotent`",
        "true",
    ),
    approx(
        "traefik.http.middlewares.<name>.retry.status",
        "`retries.on` with the statuses",
        "only `502`, `503` and `504` are retried; other statuses in the list are left out",
        "502-504",
    ),
    none(
        "traefik.http.middlewares.<name>.retry.timeout",
        "set `retries.per_try_timeout` or the service's `timeouts` in rdock.yaml",
        "5s",
    ),
    none(
        "traefik.http.middlewares.<name>.stripprefix.forceslash",
        "deprecated in Traefik; the stripped path always starts with `/`",
        "false",
    ),
    exact(
        "traefik.http.middlewares.<name>.stripprefix.prefixes",
        "`strip_prefix.prefixes`",
        "/api",
    ),
    none(
        "traefik.http.middlewares.<name>.stripprefixregex.regex",
        "not translated yet; write a `rewrite` middleware with an anchored regex in rdock.yaml",
        "/v[0-9]+",
    ),
    // --- HTTP routers --------------------------------------------------------------------
    exact(
        const_concat::ROUTER_ENTRYPOINTS,
        "`listeners`, through `providers.docker.entrypoints`",
        "websecure",
    ),
    exact(const_concat::ROUTER_MIDDLEWARES, "`middlewares`", "auth"),
    none(const_concat::ROUTER_OBS_ACCESSLOGS, OBSERVABILITY, "false"),
    none(const_concat::ROUTER_OBS_METRICS, OBSERVABILITY, "false"),
    none(
        const_concat::ROUTER_OBS_TRACEVERBOSITY,
        OBSERVABILITY,
        "detailed",
    ),
    none(const_concat::ROUTER_OBS_TRACING, OBSERVABILITY, "false"),
    exact(
        const_concat::ROUTER_PRIORITY,
        "`priority` (default: the rule's length, as in Traefik)",
        "10",
    ),
    exact(
        const_concat::ROUTER_RULE,
        "`match`, the same rule grammar",
        "Host(`app.example.com`)",
    ),
    none(
        const_concat::ROUTER_RULESYNTAX,
        "Traefik v2 rule syntax is not read: write the rule in v3 syntax",
        "v2",
    ),
    exact(const_concat::ROUTER_SERVICE, "`service`", "app"),
    approx(
        const_concat::ROUTER_TLS,
        "`tls.auto: true` (`true`) or `tls: off` (`false`)",
        "`true` without a resolver gets an automatic certificate here (Traefik: a stored certificate or its default one)",
        "true",
    ),
    approx(
        const_concat::ROUTER_TLS_CERTRESOLVER,
        "`tls.auto: true`",
        "certificates come from the one `acme` account; the resolver's name is not kept",
        "le",
    ),
    exact(
        const_concat::ROUTER_TLS_DOMAINS_MAIN,
        "`tls.domains`",
        "example.com",
    ),
    exact(
        const_concat::ROUTER_TLS_DOMAINS_SANS,
        "`tls.domains`",
        "www.example.com",
    ),
    manual(
        const_concat::ROUTER_TLS_OPTIONS,
        "TLS options are listener settings here: set `listeners.<name>.tls` (`policy`, `client_auth`) in rdock.yaml",
        "modern",
    ),
    // --- HTTP services -------------------------------------------------------------------
    exact(
        const_concat::SVC_HC_FOLLOWREDIRECTS_FALSE,
        "redirects are never followed (only `false` is taken)",
        "false",
    ),
    exact(const_concat::SVC_HC_HEADERS, "`health.active.headers`", "x"),
    exact(
        const_concat::SVC_HC_HOSTNAME,
        "`health.active.hostname`",
        "app.example.com",
    ),
    exact(
        const_concat::SVC_HC_INTERVAL,
        "`health.active.interval`",
        "10s",
    ),
    exact(
        const_concat::SVC_HC_METHOD,
        "`health.active.method`",
        "HEAD",
    ),
    exact(const_concat::SVC_HC_MODE, "`health.active.mode`", "http"),
    approx(
        const_concat::SVC_HC_PATH,
        "`health.active.path`",
        HEALTH_DEFAULTS,
        "/healthz",
    ),
    exact(const_concat::SVC_HC_PORT, "`health.active.port`", "8081"),
    none(
        const_concat::SVC_HC_SCHEME,
        "health checks use the service's scheme",
        "https",
    ),
    exact(
        const_concat::SVC_HC_STATUS,
        "`health.active.expected_status`",
        "200",
    ),
    exact(
        const_concat::SVC_HC_TIMEOUT,
        "`health.active.timeout`",
        "3s",
    ),
    none(
        const_concat::SVC_HC_UNHEALTHYINTERVAL,
        "one interval is used for healthy and unhealthy backends",
        "5s",
    ),
    exact(
        const_concat::SVC_PASSHOSTHEADER,
        "`pass_host_header`",
        "false",
    ),
    exact(
        const_concat::SVC_PASSIVE_FAILUREWINDOW,
        "`health.passive.window`",
        "10",
    ),
    exact(
        const_concat::SVC_PASSIVE_MAXFAILED,
        "`health.passive.failures`",
        "3",
    ),
    none(
        const_concat::SVC_FLUSHINTERVAL,
        "responses are streamed as they arrive; there is no flush setting",
        "100ms",
    ),
    exact(const_concat::SVC_SERVER_PORT, "the backend's port", "8080"),
    none(
        const_concat::SVC_SERVER_PRESERVEPATH,
        "a backend address carries no path",
        "true",
    ),
    exact(
        const_concat::SVC_SERVER_SCHEME,
        "`scheme` (`http`, `https`, `h2c`)",
        "h2c",
    ),
    exact(
        const_concat::SVC_SERVER_URL,
        "the backend's address and `scheme`",
        "http://backend:8080",
    ),
    exact(
        const_concat::SVC_SERVER_WEIGHT,
        "the container's backend `weight`",
        "3",
    ),
    manual(
        const_concat::SVC_SERVERSTRANSPORT,
        "servers transports are not read from labels: set `tls` (server name, CA, client certificate) and `timeouts` on the service in rdock.yaml",
        "insecure@file",
    ),
    approx(
        const_concat::SVC_STICKY,
        "`sticky.cookie` with the defaults of `sticky.cookie`",
        "as `sticky.cookie`",
        "true",
    ),
    approx(
        const_concat::SVC_STICKY_COOKIE,
        "`sticky.cookie` named `rdock_sticky`",
        "the cookie is named `rdock_sticky` unless `sticky.cookie.name` is set (Traefik derives a name), is signed, and is `Secure`, `HttpOnly` and `SameSite=Lax` unless the labels say otherwise (Traefik: none of the three)",
        "true",
    ),
    none(
        const_concat::SVC_STICKY_DOMAIN,
        "the cookie has no `Domain` attribute",
        "example.com",
    ),
    exact(
        const_concat::SVC_STICKY_HTTPONLY,
        "`sticky.cookie.http_only`",
        "true",
    ),
    exact(
        const_concat::SVC_STICKY_MAXAGE,
        "`sticky.cookie.max_age`",
        "3600",
    ),
    exact(const_concat::SVC_STICKY_NAME, "`sticky.cookie.name`", "lb"),
    exact(
        const_concat::SVC_STICKY_PATH,
        "`sticky.cookie.path`",
        "/app",
    ),
    exact(
        const_concat::SVC_STICKY_SAMESITE,
        "`sticky.cookie.same_site`",
        "strict",
    ),
    exact(
        const_concat::SVC_STICKY_SECURE,
        "`sticky.cookie.secure`",
        "true",
    ),
    approx(
        const_concat::SVC_STRATEGY,
        "`load_balancer.policy`: `wrr` → `round_robin`, `p2c` → `p2c`, `hrw` → `ip_hash`, `leasttime` → `least_requests`",
        "`leasttime` also weighs response time in Traefik; `least_requests` counts requests in flight only",
        "wrr",
    ),
    // --- TCP -----------------------------------------------------------------------------
    exact(
        "traefik.tcp.middlewares.<name>.inflightconn.amount",
        "`in_flight.amount` (TCP connections)",
        "10",
    ),
    exact(
        "traefik.tcp.middlewares.<name>.ipallowlist.sourcerange",
        "`ip_allow.cidrs`",
        "10.0.0.0/8",
    ),
    exact(
        "traefik.tcp.middlewares.<name>.ipwhitelist.sourcerange",
        "`ip_allow.cidrs` (the old name of `ipallowlist`)",
        "10.0.0.0/8",
    ),
    exact(
        "traefik.tcp.routers.<name>.entrypoints",
        "`tcp_routes.<r>.listeners`",
        "postgres",
    ),
    exact(
        "traefik.tcp.routers.<name>.middlewares",
        "`tcp_routes.<r>.middlewares`",
        "allow",
    ),
    exact(
        "traefik.tcp.routers.<name>.priority",
        "`tcp_routes.<r>.priority`",
        "10",
    ),
    exact(
        "traefik.tcp.routers.<name>.rule",
        "`tcp_routes.<r>.match` (`HostSNI`, `HostSNIRegexp`, `ALPN`, `ClientIP`)",
        "HostSNI(`db.example.com`)",
    ),
    none(
        "traefik.tcp.routers.<name>.rulesyntax",
        "Traefik v2 rule syntax is not read: write the rule in v3 syntax",
        "v2",
    ),
    exact(
        "traefik.tcp.routers.<name>.service",
        "`tcp_routes.<r>.service`",
        "db",
    ),
    approx(
        "traefik.tcp.routers.<name>.tls",
        "`tcp_routes.<r>.tls`",
        "TLS is terminated with the listener's certificates (Traefik: a resolver's or the default certificate)",
        "true",
    ),
    manual("traefik.tcp.routers.<name>.tls.certresolver", TCP_TLS, "le"),
    manual(
        "traefik.tcp.routers.<name>.tls.domains[n].main",
        TCP_TLS,
        "db.example.com",
    ),
    manual(
        "traefik.tcp.routers.<name>.tls.domains[n].sans",
        TCP_TLS,
        "db2.example.com",
    ),
    manual("traefik.tcp.routers.<name>.tls.options", TCP_TLS, "modern"),
    exact(
        "traefik.tcp.routers.<name>.tls.passthrough",
        "`tcp_routes.<r>.tls.passthrough`",
        "true",
    ),
    exact(
        "traefik.tcp.services.<name>.loadbalancer.proxyprotocol",
        "`tcp_services.<s>.proxy_protocol: v2` (Traefik's default version)",
        "true",
    ),
    exact(
        "traefik.tcp.services.<name>.loadbalancer.proxyprotocol.version",
        "`tcp_services.<s>.proxy_protocol` (`1` → `v1`, `2` → `v2`)",
        "1",
    ),
    exact(
        "traefik.tcp.services.<name>.loadbalancer.server.port",
        "the backend's port",
        "5432",
    ),
    none(
        "traefik.tcp.services.<name>.loadbalancer.server.tls",
        "TLS to TCP backends is not offered; the backend gets the bytes as relayed",
        "true",
    ),
    manual(
        "traefik.tcp.services.<name>.loadbalancer.serverstransport",
        "servers transports are not read from labels: set `proxy_protocol` and `timeouts` on the TCP service in rdock.yaml",
        "pp@file",
    ),
    exact(
        "traefik.tcp.services.<name>.loadbalancer.terminationdelay",
        "`tcp_services.<s>.timeouts.termination_delay` (milliseconds; a negative value, no deadline, is refused)",
        "200",
    ),
    // --- UDP -----------------------------------------------------------------------------
    exact(
        "traefik.udp.routers.<name>.entrypoints",
        "`udp_routes.<r>.listeners`",
        "dns",
    ),
    exact(
        "traefik.udp.routers.<name>.service",
        "`udp_routes.<r>.service`",
        "dns",
    ),
    exact(
        "traefik.udp.services.<name>.loadbalancer.server.port",
        "the backend's port",
        "53",
    ),
];

/// Router and service keys, spelled once.
mod const_concat {
    pub(super) const ROUTER_ENTRYPOINTS: &str = "traefik.http.routers.<name>.entrypoints";
    pub(super) const ROUTER_MIDDLEWARES: &str = "traefik.http.routers.<name>.middlewares";
    pub(super) const ROUTER_OBS_ACCESSLOGS: &str =
        "traefik.http.routers.<name>.observability.accesslogs";
    pub(super) const ROUTER_OBS_METRICS: &str = "traefik.http.routers.<name>.observability.metrics";
    pub(super) const ROUTER_OBS_TRACEVERBOSITY: &str =
        "traefik.http.routers.<name>.observability.traceverbosity";
    pub(super) const ROUTER_OBS_TRACING: &str = "traefik.http.routers.<name>.observability.tracing";
    pub(super) const ROUTER_PRIORITY: &str = "traefik.http.routers.<name>.priority";
    pub(super) const ROUTER_RULE: &str = "traefik.http.routers.<name>.rule";
    pub(super) const ROUTER_RULESYNTAX: &str = "traefik.http.routers.<name>.rulesyntax";
    pub(super) const ROUTER_SERVICE: &str = "traefik.http.routers.<name>.service";
    pub(super) const ROUTER_TLS: &str = "traefik.http.routers.<name>.tls";
    pub(super) const ROUTER_TLS_CERTRESOLVER: &str = "traefik.http.routers.<name>.tls.certresolver";
    pub(super) const ROUTER_TLS_DOMAINS_MAIN: &str =
        "traefik.http.routers.<name>.tls.domains[n].main";
    pub(super) const ROUTER_TLS_DOMAINS_SANS: &str =
        "traefik.http.routers.<name>.tls.domains[n].sans";
    pub(super) const ROUTER_TLS_OPTIONS: &str = "traefik.http.routers.<name>.tls.options";
    pub(super) const SVC_HC_FOLLOWREDIRECTS_FALSE: &str =
        "traefik.http.services.<name>.loadbalancer.healthcheck.followredirects";
    pub(super) const SVC_HC_HEADERS: &str =
        "traefik.http.services.<name>.loadbalancer.healthcheck.headers.<header>";
    pub(super) const SVC_HC_HOSTNAME: &str =
        "traefik.http.services.<name>.loadbalancer.healthcheck.hostname";
    pub(super) const SVC_HC_INTERVAL: &str =
        "traefik.http.services.<name>.loadbalancer.healthcheck.interval";
    pub(super) const SVC_HC_METHOD: &str =
        "traefik.http.services.<name>.loadbalancer.healthcheck.method";
    pub(super) const SVC_HC_MODE: &str =
        "traefik.http.services.<name>.loadbalancer.healthcheck.mode";
    pub(super) const SVC_HC_PATH: &str =
        "traefik.http.services.<name>.loadbalancer.healthcheck.path";
    pub(super) const SVC_HC_PORT: &str =
        "traefik.http.services.<name>.loadbalancer.healthcheck.port";
    pub(super) const SVC_HC_SCHEME: &str =
        "traefik.http.services.<name>.loadbalancer.healthcheck.scheme";
    pub(super) const SVC_HC_STATUS: &str =
        "traefik.http.services.<name>.loadbalancer.healthcheck.status";
    pub(super) const SVC_HC_TIMEOUT: &str =
        "traefik.http.services.<name>.loadbalancer.healthcheck.timeout";
    pub(super) const SVC_HC_UNHEALTHYINTERVAL: &str =
        "traefik.http.services.<name>.loadbalancer.healthcheck.unhealthyinterval";
    pub(super) const SVC_PASSHOSTHEADER: &str =
        "traefik.http.services.<name>.loadbalancer.passhostheader";
    pub(super) const SVC_PASSIVE_FAILUREWINDOW: &str =
        "traefik.http.services.<name>.loadbalancer.passivehealthcheck.failurewindow";
    pub(super) const SVC_PASSIVE_MAXFAILED: &str =
        "traefik.http.services.<name>.loadbalancer.passivehealthcheck.maxfailedattempts";
    pub(super) const SVC_FLUSHINTERVAL: &str =
        "traefik.http.services.<name>.loadbalancer.responseforwarding.flushinterval";
    pub(super) const SVC_SERVER_PORT: &str =
        "traefik.http.services.<name>.loadbalancer.server.port";
    pub(super) const SVC_SERVER_PRESERVEPATH: &str =
        "traefik.http.services.<name>.loadbalancer.server.preservepath";
    pub(super) const SVC_SERVER_SCHEME: &str =
        "traefik.http.services.<name>.loadbalancer.server.scheme";
    pub(super) const SVC_SERVER_URL: &str = "traefik.http.services.<name>.loadbalancer.server.url";
    pub(super) const SVC_SERVER_WEIGHT: &str =
        "traefik.http.services.<name>.loadbalancer.server.weight";
    pub(super) const SVC_SERVERSTRANSPORT: &str =
        "traefik.http.services.<name>.loadbalancer.serverstransport";
    pub(super) const SVC_STICKY: &str = "traefik.http.services.<name>.loadbalancer.sticky";
    pub(super) const SVC_STICKY_COOKIE: &str =
        "traefik.http.services.<name>.loadbalancer.sticky.cookie";
    pub(super) const SVC_STICKY_DOMAIN: &str =
        "traefik.http.services.<name>.loadbalancer.sticky.cookie.domain";
    pub(super) const SVC_STICKY_HTTPONLY: &str =
        "traefik.http.services.<name>.loadbalancer.sticky.cookie.httponly";
    pub(super) const SVC_STICKY_MAXAGE: &str =
        "traefik.http.services.<name>.loadbalancer.sticky.cookie.maxage";
    pub(super) const SVC_STICKY_NAME: &str =
        "traefik.http.services.<name>.loadbalancer.sticky.cookie.name";
    pub(super) const SVC_STICKY_PATH: &str =
        "traefik.http.services.<name>.loadbalancer.sticky.cookie.path";
    pub(super) const SVC_STICKY_SAMESITE: &str =
        "traefik.http.services.<name>.loadbalancer.sticky.cookie.samesite";
    pub(super) const SVC_STICKY_SECURE: &str =
        "traefik.http.services.<name>.loadbalancer.sticky.cookie.secure";
    pub(super) const SVC_STRATEGY: &str = "traefik.http.services.<name>.loadbalancer.strategy";
}

/// A Traefik label key in the table's form: lower case, with object names, header names, list
/// indices, status codes, store names and plugin settings replaced
/// (`traefik.http.routers.App.tls.domains[0].main` → `traefik.http.routers.<name>.tls.domains[n].main`).
#[must_use]
pub fn normalize(key: &str) -> String {
    let lower = key.to_ascii_lowercase();
    let mut parts: Vec<String> = lower.split('.').map(str::to_owned).collect();
    if parts.len() > 3
        && ["http", "tcp", "udp"].contains(&parts[1].as_str())
        && ["routers", "services", "middlewares"].contains(&parts[2].as_str())
    {
        "<name>".clone_into(&mut parts[3]);
        if parts[2] == "middlewares" && parts.len() > 5 && parts[4] == "plugin" {
            parts.truncate(5);
            parts.push("<plugin>".to_owned());
            parts.push("<option>".to_owned());
        }
    }
    if parts.len() > 3 && parts[1] == "tls" && parts[2] == "stores" {
        "<store>".clone_into(&mut parts[3]);
    }
    let n = parts.len();
    let header_map = n >= 2
        && matches!(
            parts[n - 2].as_str(),
            "customrequestheaders" | "customresponseheaders" | "sslproxyheaders"
        )
        || n >= 3 && parts[n - 2] == "headers" && parts[n - 3] == "healthcheck";
    if header_map {
        "<header>".clone_into(&mut parts[n - 1]);
    }
    if n >= 2 && parts[n - 2] == "statusrewrites" {
        "<status>".clone_into(&mut parts[n - 1]);
    }
    let joined = parts.join(".");
    let mut out = String::with_capacity(joined.len());
    let mut chars = joined.chars().peekable();
    while let Some(c) = chars.next() {
        out.push(c);
        if c == '[' {
            while chars.peek().is_some_and(char::is_ascii_digit) {
                chars.next();
            }
            out.push('n');
        }
    }
    out
}

/// The row of a label key (any case, with real names), if Traefik v3.7 has it.
#[must_use]
pub fn lookup(key: &str) -> Option<&'static TraefikOption> {
    let normalized = normalize(key);
    TRAEFIK_OPTIONS.iter().find(|row| row.key == normalized)
}

/// A key of the table with its placeholders filled in, for tests and examples.
#[must_use]
pub fn instantiate(key: &str) -> String {
    key.replace("<name>", "x")
        .replace("<header>", "X-Test")
        .replace("[n]", "[0]")
        .replace("<status>", "404")
        .replace("<store>", "default")
        .replace("<plugin>", "demo")
        .replace("<option>", "key")
}
