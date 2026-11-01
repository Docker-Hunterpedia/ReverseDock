# ASVS 5.0 Level 2 review: the v0.5 admin surface

This checklist reviews the v0.5 admin surface against OWASP ASVS 5.0 Level 2, as [ADR-0024](../decisions/0024-management-api-and-dashboard.md) and the v0.5 roadmap require (issue #115, H-ENG-04). The requirement list it starts from is in the [v0.5 research](../research/v0.5-management.md) §3.

- **Scope:** the admin API (`crates/rdock-admin`), the dashboard (`apps/dashboard`), the CLI's use of the admin socket and listener (`crates/rdock/src/admin_cli.rs`, `crates/rdock/src/ctl.rs`), and the parts of `rdock-model` and `rdock-observability` the admin surface relies on (admin settings validation, secret masking, alert delivery).
- **Standard:** OWASP ASVS 5.0.0 ([source](https://github.com/OWASP/ASVS), checked 2026-11-01). Requirement numbers are given where the research note cites them; otherwise the chapter or section is named.
- **Method:** reading the code on branch `feat/admin-isolation` and the tests that cover it. No penetration test was run. Evidence is `path:line` or a test name; every item was checked in the code.
- **Reviewed by:** Reviewed with Claude Code; signed off by the maintainer on 2026-11-01.

Status values: **Met**, **Partly**, **Not met**, **N/A**. Everything that is not Met is listed again under [Findings](#findings).

## V1 Encoding and Sanitization

| Requirement | Status | Evidence |
|---|---|---|
| Output is encoded for its context; API answers are JSON built by a serializer, never by string concatenation | Met | `crates/rdock-admin/src/routes.rs:21-23` (`error` builds JSON with `serde_json::json!`); handlers answer with `axum::Json` |
| The dashboard never puts API data into HTML as markup | Met | No `dangerouslySetInnerHTML`, `innerHTML`, `eval` or `new Function` in `apps/dashboard/src`; React escapes text |
| Log and audit records cannot be forged by injected line breaks | Met | Audit records are one JSON object per line (`crates/rdock-admin/src/audit.rs:203-219`); failed logins record the name only when it is a valid user name (`crates/rdock-admin/src/auth.rs:229-235`) |
| Values placed into URIs are safe for that context | Met | User names in the `otpauth://` URI are limited to `[a-z0-9._-]` (`crates/rdock-admin/src/users.rs:252-258`, `crates/rdock-admin/src/totp.rs:57-63`) |
| The CLI encodes path segments it puts into requests | Partly | `crates/rdock/src/ctl.rs:168` writes `call.path` as given; paths such as `/api/v1/tokens/{id}` are formatted from arguments without percent-encoding (`crates/rdock/src/admin_cli.rs:388`) |

## V2 Validation and Business Logic

| Requirement | Status | Evidence |
|---|---|---|
| Request bodies are validated against a strict schema; unknown fields are refused | Met | `#[serde(deny_unknown_fields)]` on `Credentials` (`auth.rs:26-31`), `Code`, `Reauth` (`account.rs:153-157`, `438-444`), `TokenRequest`, `AuditQuery` (`manage.rs`); wrong content type gets 415 (test `configuration_writes_are_conditional_dry_run_and_audited`) |
| Configuration written through the API goes through the same validation as a file reload | Met | `crates/rdock-admin/src/config_api.rs:159-200` sends every write to `Control::write_api`, which answers `Rejected` with the diagnostics |
| Lost updates are prevented | Met | `If-Match` is required (428) and stale versions get 412 (`config_api.rs:138-147`, `config_api.rs:190-196`); test `configuration_writes_are_conditional_dry_run_and_audited` |
| Business rules cannot be bypassed: the last enabled admin cannot be removed or demoted | Met | `crates/rdock-admin/src/users.rs:166-205`; test `admins_manage_users_but_never_remove_the_last_admin` |
| A token never has a higher role than its creator | Met | `manage.rs:358-363` at creation; `caller.rs:206-224` caps it at the creator's current role on every request; test `roles_limit_tokens_and_metrics_needs_one` |
| Anti-automation on authentication flows | Met | Login, MFA, TOTP confirmation, re-authentication and setup share sliding-window limits (`crates/rdock-admin/src/limits.rs:84-122`; `auth.rs:143`, `auth.rs:236`, `account.rs:196-201`, `281-286`, `465-470`); test `logins_hide_which_users_exist_and_are_rate_limited` |
| Resource limits on expensive operations | Met | Argon2 runs on at most 2 blocking threads with a bounded queue (`auth.rs:76-84`, `server.rs:168`); at most 4 streams per identity (`stream.rs:32`, `stream.rs:306-313`); audit queries are capped at 1000 records (`manage.rs:449`) |

## V3 Web Frontend Security

| Requirement | Status | Evidence |
|---|---|---|
| 3.3.1, 3.3.3, 3.3.4: session cookie has the `__Host-` prefix, `Secure`, `HttpOnly` and a `SameSite` attribute | Met | `crates/rdock-admin/src/sessions.rs:20`; `crates/rdock-admin/src/account.rs:41-46` (`Path=/; Secure; HttpOnly; SameSite=Strict`); test `an_admin_enrols_totp_then_logs_in_with_a_second_factor` (helper `session_cookie` asserts the attributes) |
| 3.5.1-3.5.3: unsafe requests carry an anti-forgery token, and state never changes on GET | Met | Synchronizer token per session, compared in constant time (`account.rs:34-39`), required on every method except GET and HEAD (`caller.rs:170-177`, `account.rs:92-98`); the dashboard sends it (`apps/dashboard/src/lib/api.ts:51-52`); test `an_admin_enrols_totp_then_logs_in_with_a_second_factor` ("writes need the CSRF token") |
| Cross-site unsafe requests are refused with Fetch Metadata and an `Origin` fallback, including the login form | Met | `crates/rdock-admin/src/guard.rs:56-72`, `guard.rs:91-97`; test `the_api_needs_the_token_and_refuses_cross_site_writes` |
| 3.4.2: CORS is fixed; no cross-origin access is granted | Met | No `Access-Control-*` header is set anywhere in `crates/rdock-admin/src` |
| 3.4.3, 3.4.6: a Content Security Policy with `object-src 'none'`, `base-uri 'none'` and `frame-ancestors 'none'` | Partly | `guard.rs:15-17`; `style-src` allows `'unsafe-inline'`. `script-src 'self'` holds: the built `index.html` has no inline script |
| 3.4.1, 3.4.4, 3.4.5: HSTS on TLS, `X-Content-Type-Options: nosniff`, `Referrer-Policy` | Met | `guard.rs:107-132`; tests `health_answers_with_security_headers_and_foreign_hosts_are_refused`, `tls_serves_https_with_hsts_and_the_configured_host_names` |
| Cross-origin isolation headers | Met | `Cross-Origin-Opener-Policy` and `Cross-Origin-Resource-Policy: same-origin` (`guard.rs:117-124`) |
| The dashboard loads nothing from other origins | Met | `connect-src 'self'` (`guard.rs:16`); fonts are bundled (`@fontsource-variable/*`) and the QR code is drawn locally (`uqr`) per `apps/dashboard/package.json`; `fetch` uses relative `/api/v1` paths with `credentials: "same-origin"` (`api.ts:55-60`) |
| Browser storage holds no sensitive data | Met | `localStorage` keeps only the theme and the sidebar state (`apps/dashboard/src/lib/theme.ts`, `apps/dashboard/src/components/Shell.tsx:63-72`) |

## V4 API and Web Service

| Requirement | Status | Evidence |
|---|---|---|
| Only the documented methods are accepted | Met | Routes are declared per method (`routes.rs:52-102`); other methods get 405 (test `the_api_needs_the_token_and_refuses_cross_site_writes`) |
| Request bodies have a size limit | Met | `DefaultBodyLimit::max(1 MiB)` (`routes.rs:18-19`, `routes.rs:109`). No test covers the 413 |
| Credentials are never accepted in a URL | Met | Tokens are read only from `Authorization: Bearer` (`caller.rs:144-150`); browser streams use the cookie (`stream.rs` module comment, `apps/dashboard/src/lib/stream.ts:20`) |
| Answers are not cached | Met | `Cache-Control: no-store` on every admin answer (`guard.rs:113`) |
| API pages and the dashboard stay apart: `/api/` never falls back to the SPA | Met | `routes.rs:141-154`; test `pages_get_the_dashboard_and_the_api_stays_json` |
| Streams end when access is withdrawn | Met | Re-check every 60 s (`stream.rs:34`, `stream.rs:274-282`); revoked credentials get 204 so `EventSource` stops (`caller.rs:236-243`); test `streams_are_limited_per_identity_and_end_for_revoked_tokens` |
| The admin listener limits slow or idle connections | Met (finding 11, fixed) | `crates/rdock-admin/src/server.rs:323-338` serves with hyper defaults: no header-read timeout and no connection cap. The admin runtime is separate from the proxy (`server.rs:170-199`), so only the admin surface is affected |

## V5 File Handling

| Requirement | Status | Evidence |
|---|---|---|
| File uploads | N/A | The admin API takes no file uploads; import is a JSON body (`config_api.rs:479-500`) |
| Served files cannot escape their directory | Met | Dashboard files are embedded in the binary with `rust-embed`; there is no file-system read on a request (`crates/rdock-admin/src/dashboard.rs:11-33`) |

## V6 Authentication

| Requirement | Status | Evidence |
|---|---|---|
| 6.2.1: passwords of at least 8 characters (12 by default) | Met | `crates/rdock-model/src/settings.rs:252-260`; bounds 8-128 in `crates/rdock-model/src/validate.rs:1477-1479`; `crates/rdock-admin/src/passwords.rs:61-74` |
| 6.2.9: at least 64 characters allowed, counted as characters | Met | `MAX_LENGTH = 128` (`passwords.rs:15`); test `length_and_common_passwords_are_checked` |
| 6.2.5: no composition rules | Met | `passwords.rs:61-74` checks only length and lists |
| 6.2.4: common passwords are refused | Met | Bundled list (`passwords.rs:17-21`) and the optional `blocklist_file`, case-insensitive; tests `length_and_common_passwords_are_checked`, `the_blocklist_file_is_case_insensitive` |
| 6.2.12 (L2): passwords are checked against breached passwords | Partly | Only when an operator sets `admin.passwords.blocklist_file` (`settings.rs:247-249`); nothing is checked by default beyond the bundled common list |
| V6.2: users can change their own password, giving the current one | Met (finding 4, fixed) | No self-service endpoint: `routes.rs:85-101` has no password route, and only an admin can set a password (`manage.rs:159-176`). Viewers and operators keep the first password an admin chose (`apps/dashboard/src/pages/Access.tsx:98`) |
| 6.3.2: no default accounts | Met | The first admin is created with a single-use bootstrap token (`crates/rdock-admin/src/bootstrap.rs:34-50`, `auth.rs:132-210`); test `the_bootstrap_token_creates_one_admin_who_can_log_in` |
| 6.4.1: the bootstrap token is random, single-use and short-lived | Met | 160 random bits, 24 h, only its SHA-256 kept, constant-time compare, deleted after use (`bootstrap.rs:15`, `bootstrap.rs:34-85`); the log shows the file path, never the value (`server.rs:88-92`) |
| 6.1.1, 6.3.1: brute-force controls that do not enable malicious lockout | Partly | 5 per minute per address (IPv6 per /64) and 10 per 15 minutes per user name, no permanent lockout (`limits.rs:61-122`). The per-name window still lets anyone hold a known user name at 429 for 15 minutes from any address, and successful logins count toward it (`limits.rs:107-122`). The address comes from `X-Forwarded-For` on loopback connections (`auth.rs:38-54`), so a local process can rotate addresses |
| 6.3.8: no user enumeration by message, status or timing | Met | Same 401 body, and a dummy Argon2 verification for unknown users (`auth.rs:245-287`, `passwords.rs:110-114`, `passwords.rs:138-146`); test `logins_hide_which_users_exist_and_are_rate_limited` |
| 6.3.3 (L2): multi-factor authentication | Met | TOTP is required for admins by default (`settings.rs:224-235`); a session stays at `Mfa` or `Enrol` until the second step (`auth.rs:92-104`, `caller.rs:167-169`); test `an_admin_enrols_totp_then_logs_in_with_a_second_factor` |
| V6.6: TOTP codes are short-lived, single-use and checked in constant time | Met | RFC 6238, ±1 step, `last_step` prevents reuse, `ct_eq` (`crates/rdock-admin/src/totp.rs:80-98`, `account.rs:131-146`); test `rfc_6238_vectors_verify_once_within_one_step` |
| V6.5: recovery (lookup) codes are random, single-use and stored safely | Partly | 10 codes of 50 random bits, single-use, compared in constant time (`totp.rs:100-133`, `account.rs:139-141`). Stored as unsalted SHA-256 (`totp.rs:114-121`); ASVS asks for a salted password hash below 112 bits of entropy |
| Replacing recovery codes and removing TOTP need a recent password check | Met | `account.rs:352-357`, `account.rs:415-426` |
| Changing a password or the second factor ends the user's other sessions | Met | `account.rs:319`, `account.rs:431`, `manage.rs:206` |
| Password hashes are upgraded when the cost rises | Met | `passwords.rs:96-107`, `auth.rs:255-264`; test `hashes_verify_and_weaker_ones_ask_for_a_rehash` |
| Credentials are never taken on the command line | Met | `rdock users` reads the password from standard input (`crates/rdock/src/admin_cli.rs:207-219`) |

## V7 Session Management

| Requirement | Status | Evidence |
|---|---|---|
| 7.2.1: sessions are checked on the server | Met | `sessions.rs:170-181`; `caller.rs:167-186` |
| 7.2.3: session tokens have at least 128 bits from a CSPRNG | Met | 256 bits from `ring::rand::SystemRandom` (`sessions.rs:79-83`); test `only_the_hash_of_the_cookie_is_kept` |
| Only a hash of the session token is stored | Met | `sessions.rs:85-89`, `sessions.rs:165`; test `only_the_hash_of_the_cookie_is_kept` |
| 7.2.4: a new token at login and at every privilege change | Met | New session at login (`auth.rs:100`); rotation after the second factor and enrolment (`account.rs:210`, `account.rs:320-324`), with a new CSRF token (`sessions.rs:193-207`); test `rotation_issues_a_new_id_and_csrf_token` |
| 7.3.1, 7.3.2: idle and absolute timeouts | Partly | 30 min idle, 8 h absolute, bounded 5 min-12 h (`settings.rs:204-222`, `validate.rs:1496-1509`, `sessions.rs:113-121`); pending logins end after 10 min (`sessions.rs:27`); test `idle_and_absolute_timeouts_end_sessions`. Every request refreshes the idle timer, and the dashboard polls `/status` every 5 s (`apps/dashboard/src/components/Shell.tsx:42-46`), so a visible, unattended tab stays logged in until the absolute timeout |
| 7.4.1: logout ends the session on the server and clears the browser | Met | `account.rs:503-532` (`Max-Age=0`, `Clear-Site-Data`); test `an_admin_enrols_totp_then_logs_in_with_a_second_factor` |
| Disabling, deleting or changing a user ends their sessions | Met | `manage.rs:206`, `manage.rs:252-255` |
| 7.5.2: users see and end their own sessions; admins end anyone's | Met | `account.rs:534-580`; `sessions.rs:221-255`; test `users_keep_at_most_32_sessions_and_can_be_logged_out_everywhere` |
| 7.5.1: re-authentication before sensitive changes | Met | Within 5 minutes (`sessions.rs:29`, `caller.rs:94-103`, `caller.rs:128-138`), for user changes (`manage.rs:91-92`, `165-166`, `241-242`), token creation (`manage.rs:349-350`), rollback (`config_api.rs:419-420`), export and import (`config_api.rs:448-449`, `485-486`). API tokens and the socket count as re-authenticated (`caller.rs:101`), see V8 |
| Session count is bounded | Met | 32 per user, 10,000 in all (`sessions.rs:22-25`, `sessions.rs:149-164`) |

## V8 Authorization

| Requirement | Status | Evidence |
|---|---|---|
| 8.1.1: authorization rules are documented | Partly | ADR-0024 "What each role may do". The code is stricter than the ADR in one place: the ADR lets viewers validate a change, `config_api.rs:356` requires operator |
| 8.2.1, 8.3.1: function-level checks on the server for every endpoint | Met | Every `/api/v1` route sits behind `caller::authenticate` (`routes.rs:101-106`) and each handler calls `need` (`manage.rs`, `config_api.rs`, `resources.rs`, `stream.rs:306`, `routes.rs:209`, `routes.rs:234`); `/api/openapi.json` and `/metrics` also check (`routes.rs:128-137`, `routes.rs:177-187`) |
| 8.2.2: object-level checks | Met | Non-admins see and revoke only their own tokens and sessions (`manage.rs:313-322`, `manage.rs:421-424`, `account.rs:546`, `account.rs:568-570`) |
| 8.3.2: permission changes apply at once | Met | Token access is recomputed from the creator's current role on each request, and disabled creators' tokens stop (`caller.rs:206-216`); role changes end sessions (`manage.rs:206`) |
| 8.4.2: the admin surface never relies on network location alone | Met | Authentication is required on loopback too (`caller.rs:153-225`); open `/metrics` is an explicit opt-in limited to loopback (`server.rs:161`) |
| Tokens cannot extend their own reach | Met (finding 2, fixed) | A token may create new tokens (`manage.rs:344-350`; `need_recent` is always true for tokens, `caller.rs:101`). The new token is owned by the same creator but has a fresh lifetime of up to 365 days (or none when `allow_no_expiry` is on) and its own `allowed_from`, which may be empty (`manage.rs:364-389`). A leaked, expiring, network-restricted token can mint an unrestricted successor |
| Token `allowed_from` is enforced | Partly | `crates/rdock-admin/src/tokens.rs:223-226`. The client address is taken from `X-Forwarded-For` when the peer is loopback (`auth.rs:41-54`), so a process on the same host can claim any address |

## V9 Self-contained Tokens

| Requirement | Status | Evidence |
|---|---|---|
| Self-contained tokens (JWT and similar) | N/A | Sessions and API tokens are opaque and looked up on the server (`sessions.rs`, `tokens.rs`) |

## V10 OAuth and OIDC

| Requirement | Status | Evidence |
|---|---|---|
| OAuth and OIDC | N/A | The admin surface has no OAuth or OIDC in v0.5 |

## V11 Cryptography

| Requirement | Status | Evidence |
|---|---|---|
| 11.4.2: passwords use an approved hash with current parameters | Met | Argon2id, default m=19456 KiB, t=2, p=1 (OWASP minimum), weaker values refused (`passwords.rs:76-85`, `passwords.rs:122-124`, `settings.rs:262-283`, `validate.rs:1480-1495`); only Argon2id hashes verify (`passwords.rs:87-95`); test `bcrypt_and_argon2i_hashes_never_match` |
| Random values come from a CSPRNG | Met | `ring::rand::SystemRandom` for salts, sessions, CSRF tokens, TOTP secrets, recovery codes, API tokens (rejection sampling) and the bootstrap token (`passwords.rs:78-80`, `sessions.rs:79-83`, `totp.rs:13-17`, `tokens.rs:36-50`, `bootstrap.rs:36-39`) |
| 11.2.4: secrets are compared in constant time | Met | `subtle::ConstantTimeEq` for CSRF tokens, TOTP codes, recovery codes, API token hashes and the bootstrap token (`account.rs:38`, `totp.rs:92`, `totp.rs:128`, `tokens.rs:217-221`, `bootstrap.rs:74`) |
| High-entropy secrets are stored only as hashes | Met | API tokens (190 bits) as SHA-256 (`tokens.rs:78-80`, `tokens.rs:195`); session IDs as SHA-256 (`sessions.rs:85-89`); bootstrap token as SHA-256 in memory (`bootstrap.rs:88-92`) |
| TOTP uses the algorithm authenticator apps support | Met | HMAC-SHA1 as RFC 6238 specifies, 160-bit secret (`totp.rs:52-55`, `totp.rs:66-78`) |
| Low-entropy lookup secrets use a salted, slow hash | Partly | Recovery codes, see V6.5 (`totp.rs:114-121`) |

## V12 Secure Communication

| Requirement | Status | Evidence |
|---|---|---|
| TLS is required when the admin listener is off loopback | Met | Validation error without `admin.tls` (`crates/rdock-model/src/validate.rs:1563-1568`) |
| Only strong TLS versions | Met | TLS 1.3 only on the admin listener (`server.rs:235-236`) |
| A wildcard listener must name its host names | Met | `validate.rs:1583-1590` |
| The CLI protects its credential in transit | Met (finding 1, fixed) | `crates/rdock/src/ctl.rs:148-199` speaks plain HTTP over TCP and sends `RDOCK_ADMIN_TOKEN` in `Authorization` (`ctl.rs:169-171`) to any `--admin` address, including a remote TLS listener, where the token crosses the network in clear text before the handshake fails |
| Outbound alert channels use TLS | Met | Webhook URLs must be `https://` unless `allow_private_targets` is set (`validate.rs:1699-1710`); plain SMTP only to a loopback relay (`validate.rs:1741-1750`); certificates are verified with the platform verifier (`crates/rdock-observability/src/alerts/deliver.rs:100-111`) |
| Audit records forwarded to syslog are protected in transit | Partly | UDP or plain TCP only (`crates/rdock-admin/src/audit.rs:416-440`; `settings.rs:174-183`); no TLS option |
| The CLI socket is restricted to its owner | Met | Mode 0600 (`server.rs:240-259`); test `the_socket_is_owner_only_needs_no_token_and_is_removed_on_stop` |

## V13 Configuration

| Requirement | Status | Evidence |
|---|---|---|
| 13.4.5: API documentation and monitoring endpoints are not exposed unless intended | Met | `/api/openapi.json` needs viewer (`routes.rs:128-137`); `/metrics` needs a token unless opted in on loopback (`routes.rs:177-187`, `settings.rs:108-110`); test `roles_limit_tokens_and_metrics_needs_one` |
| DNS rebinding: `Host` is checked against an allow-list | Met | `guard.rs:19-46`, `guard.rs:84-90` (421 otherwise); defaults in `server.rs:117-121`; test `health_answers_with_security_headers_and_foreign_hosts_are_refused` |
| Safe defaults | Met | Admin on `127.0.0.1:2080`, MFA for admins, tokens expire after 90 days, no non-expiring tokens, `/metrics` closed (`settings.rs:118-137`, `settings.rs:195-202`) |
| Test and debug features are absent from release builds | Met | Fault injection is a non-default Cargo feature (`crates/rdock-admin/Cargo.toml`, `crates/rdock/Cargo.toml:19-23`) |
| GitOps mode can turn off every API write | Met | `config_api.rs:127-136`, called by each write handler |

## V14 Data Protection

| Requirement | Status | Evidence |
|---|---|---|
| Secrets in the configuration are masked in every API answer and export | Met (findings 5 and 16, fixed) | `config_api.rs:34-66` masks the fields listed in `crates/rdock-model/src/interpolation.rs:21-34`; import refuses masked values (`config_api.rs:497`); test `secrets_are_masked_unless_they_are_references`. Basic-auth `users` entries show as `name:***` and the v0.3 `observability.alerts.webhook.url` as `***` (`ALSO_MASKED`); a `***` written back keeps the current value (`restore_masked`) |
| Configuration history does not leak sources | Met | The history list returns ids, summaries and a flag only (`crates/rdock/src/engine.rs:892-911`) |
| Credential files are readable by their owner only | Met | `users.json`, `tokens.json` and the bootstrap token are written with mode 0600 (`crates/rdock-config/src/state.rs:136-153`); the audit directory is 0700 and its files 0600 (`audit.rs:138-154`); test `records_chain_across_rotation_and_restarts` |
| New secrets are shown once | Met | API tokens (`manage.rs:383-403`), recovery codes (`account.rs:330-332`, `account.rs:375`) |
| TOTP secrets at rest | Met | Kept in `users.json` (mode 0600) because the server needs the plain secret to compute codes (`users.rs:45-55`) |
| Sensitive answers are not cached | Met | `Cache-Control: no-store` (`guard.rs:113`); `Clear-Site-Data` on logout (`account.rs:527-530`) |

## V15 Secure Coding and Architecture

| Requirement | Status | Evidence |
|---|---|---|
| The admin surface cannot take resources from the data plane | Met | Its own runtime and threads (`server.rs:170-199`); H-ENG-04 fault harness in progress (`crates/rdock-admin/src/fault.rs`) |
| Memory-safe code; no `unsafe` | Met | `unsafe_code = "forbid"` (`Cargo.toml:161`) |
| Third-party components are pinned and checked | Partly | `Cargo.lock` and `cargo deny check` in CI (`.github/workflows/ci.yml:155-159`), unknown registries and git sources denied (`deny.toml:66-68`); `pnpm-lock.yaml` with `--frozen-lockfile` (`ci.yml:179`) and exact versions in `apps/dashboard/package.json`; Dependabot for npm (`.github/dependabot.yml:51-52`). No CI step checks the dashboard's npm dependencies against an advisory database |
| Concurrency: shared state is safe under races | Met | Mutex-guarded stores; first-admin creation is atomic (`users.rs:143-151`); token and user writes roll back on a failed save (`tokens.rs:199-205`, `users.rs:219-230`) |
| Unbounded growth is prevented | Met | Rate-limit keys capped and fail closed (`limits.rs:11-13`, `limits.rs:45-52`); sessions capped (`sessions.rs:22-25`); stream queues bounded (`stream.rs:27-32`) |

## V16 Security Logging and Error Handling

| Requirement | Status | Evidence |
|---|---|---|
| 16.2.x: records have UTC time, actor, method, client, action, resource and result | Met | `audit.rs:203-219`; RFC 3339 UTC time (`crates/rdock-observability/src/access.rs:191-207`) |
| 16.3.1, 16.3.2: logins, MFA events, refusals and admin changes are logged | Met | Logins and failures (`auth.rs:236-287`), MFA and re-authentication (`account.rs:205-213`, `488-498`), 403 refusals (`caller.rs:249-256`), token failures (`caller.rs:190-198`), user, token and configuration changes (`manage.rs`, `config_api.rs:180-189`); test `logins_writes_and_refusals_land_in_an_intact_audit_chain` |
| No credentials in logs or audit records | Met | Tokens are recorded by public ID only (`caller.rs:109`, `manage.rs:392-397`); passwords typed into the name field are never recorded (`auth.rs:230-235`); the bootstrap token's value is never logged (`server.rs:88-92`) |
| 16.4.2: audit records are protected from modification | Partly | Each line carries the SHA-256 of the previous one and `rdock audit verify` checks it (`audit.rs:200-233`, `audit.rs:344-380`); test `an_edited_or_removed_line_breaks_the_chain`. The chain has no key, so someone who can write the files can rewrite the whole chain or cut its tail without detection; only forwarding to syslog keeps a copy elsewhere |
| 16.4.3: records can be sent to a separate system | Met | Syslog forwarding, RFC 5424 (`audit.rs:396-440`); security events also raise alerts (`audit.rs:234-249`) |
| A failed audit write is noticed | Partly | `audit.rs:194-198` logs an error and the action still succeeds |
| Error messages do not reveal internals | Met | Internal errors answer fixed text and log the detail (`account.rs:148-151`, `auth.rs:205-208`, `manage.rs` `internal`); one answer for unknown user and wrong password (`auth.rs:33`) |

## Findings

Severity is for the admin surface as shipped with default settings.

| # | Finding | Severity | Recommended fix | Status |
|---|---|---|---|---|
| 1 | The CLI sends `RDOCK_ADMIN_TOKEN` over plain TCP to any `--admin` address (`ctl.rs:148-199`), including a remote TLS listener, where the token crosses the network in clear text before the handshake fails. | Medium | Refuse non-loopback `--admin` addresses without TLS, or add a rustls client with certificate verification and an `https://` form of `--admin`. | Fixed: the CLI refuses to send a token to a non-loopback address over plain HTTP (`ctl.rs` `refuse_plain_token`). |
| 2 | API tokens can create tokens (`manage.rs:344-350`, `caller.rs:101`), with a fresh lifetime and no `allowed_from`, so a leaked restricted token can mint an unrestricted successor. | Medium | Allow token creation only from a session after re-authentication or from the socket; or cap a token-made token at its parent's expiry and `allowed_from`. Record the parent token in the audit event. | Fixed: tokens cannot create tokens (`caller.rs` `need_not_token`; test `roles_limit_tokens_and_metrics_needs_one`). |
| 3 | The alert SSRF guard is skipped for IP-literal URLs: `hyper-util`'s `HttpConnector` does not call the resolver when the host is an IP address (`hyper-util` 0.1.21 `src/client/legacy/connect/http.rs:557-560`), so `Guarded` (`deliver.rs:55-91`) never sees `https://169.254.169.254/` or `https://10.0.0.5/`. | Medium | Check IP-literal hosts with `private()` before the request (in `post` and in `validate.rs` `check_alert_channel`), and add a test with a literal private address. | Fixed: `deliver.rs` `private_literal` refuses private IP literals before the request; test `private_ip_literals_in_urls_are_recognised`. |
| 4 | Users cannot change their own password; non-admins keep the first password an admin chose (`routes.rs:85-101`, `manage.rs:159-176`). | Medium | Add `POST /api/v1/auth/password` (current password, new password, policy check, ends other sessions, audited) and a dashboard form. Consider making admin-set passwords one-time, changed at first login. | Fixed: `POST /api/v1/auth/password` and a dashboard form; other sessions end (test `people_change_their_own_password_and_their_other_sessions_end`). |
| 5 | Basic-auth `users` hashes (some may be `$apr1$` or `{SHA}`) and the v0.3 `observability.alerts.webhook.url` are not masked for viewers (`interpolation.rs:21-34`). | Medium | Add both paths to `SECRETS`, or mask basic-auth `users` entries in `config_api::mask`, with tests. | Fixed: `config_api.rs` masks both (`ALSO_MASKED`, basic-auth hashes as `name:***`); test `basic_auth_hashes_and_the_old_webhook_url_are_masked`. |
| 6 | The client address comes from `X-Forwarded-For` on any loopback connection (`auth.rs:38-54`), contrary to ADR-0024 ("never from forwarded headers"). A local process can rotate addresses past the per-address limit and satisfy a token's `allowed_from`. | Low | Trust `X-Forwarded-For` only on connections ReverseDock's own proxy makes (for example a marker header with a per-process secret, or a dedicated internal listener); otherwise use the socket peer. | Open: [#145](https://github.com/Docker-Hunterpedia/ReverseDock/issues/145) |
| 7 | The per-name login window lets anyone keep a known user name at 429 for 15 minutes from any address, and successful logins count toward it (`limits.rs:107-122`). | Low | Count only failures, reset on success, and let a correct password from an address that has not failed pass the per-name limit; keep the per-address limit as is. | Open: [#146](https://github.com/Docker-Hunterpedia/ReverseDock/issues/146) |
| 8 | Recovery codes have 50 bits and are stored as unsalted SHA-256 (`totp.rs:100-121`). The TOTP secret sits in the same file, so the practical gain is small. | Low | Store recovery codes as Argon2id hashes (they are checked rarely), or raise them to 112+ bits. | Open: [#147](https://github.com/Docker-Hunterpedia/ReverseDock/issues/147) |
| 9 | Dashboard polling keeps the idle timer fresh, so a visible, unattended tab stays logged in until the absolute timeout (`Shell.tsx:42-46`, `sessions.rs:170-181`). | Low | Do not refresh `seen` for background reads (for example a request header the dashboard sets on polls), or end the session in the dashboard after idle input. | Open: [#148](https://github.com/Docker-Hunterpedia/ReverseDock/issues/148) |
| 10 | The audit hash chain has no key; whoever can write the files can rewrite it or cut its tail (`audit.rs:200-233`). Forwarding is UDP or plain TCP (`audit.rs:416-440`), and a failed write does not stop the action (`audit.rs:194-198`). | Low | Document syslog forwarding as the tamper-resistant copy; add syslog over TLS (RFC 5425); consider an HMAC chain with a key outside the audit directory and a metric for failed audit writes. | Open: [#149](https://github.com/Docker-Hunterpedia/ReverseDock/issues/149) |
| 11 | The admin listener has no header-read timeout or connection cap (`server.rs:323-338`). Only the admin runtime is affected. | Low | Set `http1().timer(...)` with a header-read timeout and limit concurrent connections. | Fixed: at most 256 open TCP connections (more are closed at once) and a 10 s header and TLS-handshake timeout (`server.rs` `MAX_CONNECTIONS`, `HEADER_TIMEOUT`). |
| 12 | The CSP allows `style-src 'unsafe-inline'` (`guard.rs:15`). | Low | Remove it if CodeMirror and uPlot work with nonces or hashed styles; otherwise record why it stays. | Open: [#150](https://github.com/Docker-Hunterpedia/ReverseDock/issues/150) |
| 13 | No CI step checks the dashboard's npm dependencies against an advisory database. | Low | Add `pnpm audit --prod` (or OSV-Scanner) for `apps/dashboard` to CI or the weekly workflow. | Open: [#151](https://github.com/Docker-Hunterpedia/ReverseDock/issues/151) |
| 14 | The CLI formats user-supplied values into request paths without percent-encoding (`ctl.rs:168`, `admin_cli.rs:388`). The user can only affect their own request. | Info | Percent-encode path segments. | Open: [#152](https://github.com/Docker-Hunterpedia/ReverseDock/issues/152) |
| 15 | No test covers the 1 MiB body limit (413). ADR-0024 says viewers may validate changes, but `config_api.rs:356` requires operator. | Info | Add the test; align the ADR's role table or the code. | Open: [#153](https://github.com/Docker-Hunterpedia/ReverseDock/issues/153) |
| 16 | Found while fixing 5: documents read through the API carry secrets as `***`, and writing such a document back (the dashboard's editor saves the whole document) stored the literal `***` in place of the secret. | Medium | Restore `***` from the current value on write; refuse it where there is none. | Fixed: `config_api.rs` `restore_masked`; test `masked_values_written_back_keep_the_current_secret`. |