//! Who is calling and what they may do (ADR-0024, "What each role may do"). Every request to
//! `/api/v1` outside the login endpoints is identified once, by the Unix socket, a complete
//! session (with its CSRF token on unsafe methods) or an API token, and handlers check the
//! access they need on the server; the dashboard only hides what the server would refuse.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use axum::extract::{Request, State as Extract};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use http::{HeaderMap, Method, StatusCode, header};
use serde::{Deserialize, Serialize};

use crate::audit::{Event, Outcome};
use crate::auth::{Peer, client};
use crate::routes::Denied;
use crate::sessions::Stage;
use crate::users::Role;
use crate::{State, Transport, account};

/// What a caller may do, in increasing order. `metrics` reads `/metrics` only, for
/// Prometheus; the others are the user roles.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, utoipa::ToSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum Access {
    /// `/metrics` only.
    Metrics,
    /// Reads everything except secrets, users and the audit log.
    Viewer,
    /// Also reloads, drains backends and edits API-owned configuration.
    Operator,
    /// Also manages users, tokens, sessions and admin settings.
    Admin,
}

impl From<Role> for Access {
    fn from(role: Role) -> Self {
        match role {
            Role::Viewer => Self::Viewer,
            Role::Operator => Self::Operator,
            Role::Admin => Self::Admin,
        }
    }
}

/// Who an identified caller is.
#[derive(Debug, Clone)]
pub(crate) enum Who {
    /// The Unix socket: the owner of the data directory.
    Cli,
    /// An API token, limited to its creator's current role and tenant.
    Token {
        id: String,
        access: Access,
        owner: String,
        tenant: Option<String>,
    },
    /// A complete dashboard session; the tenant is the user's current one.
    Session {
        user: String,
        role: Role,
        authenticated: Instant,
        tenant: Option<String>,
    },
}

/// An identified caller and where the request came from.
#[derive(Debug, Clone)]
pub(crate) struct Caller {
    pub(crate) who: Who,
    pub(crate) client: Option<IpAddr>,
    /// The resolved tenant scope of a scoped caller, set by [`authenticate`] for the
    /// operations [`crate::tenancy::OPERATIONS`] lets it reach.
    pub(crate) scope: crate::tenancy::Scoped,
}

impl Caller {
    pub(crate) fn access(&self) -> Access {
        match &self.who {
            Who::Cli => Access::Admin,
            Who::Token { access, .. } => *access,
            Who::Session { role, .. } => Access::from(*role),
        }
    }

    /// The tenant the caller is scoped to, if any; the socket never is.
    pub(crate) fn tenant(&self) -> Option<&str> {
        match &self.who {
            Who::Cli => None,
            Who::Token { tenant, .. } | Who::Session { tenant, .. } => tenant.as_deref(),
        }
    }

    /// The resolved scope of a scoped caller.
    pub(crate) fn scope(&self) -> Option<&crate::tenancy::Scope> {
        self.scope.as_deref()
    }

    /// The name recorded as owner: the user, the token's creator, or `cli`.
    pub(crate) fn name(&self) -> &str {
        match &self.who {
            Who::Cli => "cli",
            Who::Token { owner, .. } => owner,
            Who::Session { user, .. } => user,
        }
    }

    /// Whether a sensitive change may proceed: a person must have confirmed their password in
    /// the last five minutes (ASVS 7.5.1); the socket and tokens cannot re-authenticate.
    pub(crate) fn recently_authenticated(&self) -> bool {
        match &self.who {
            Who::Session { authenticated, .. } => {
                authenticated.elapsed() <= crate::sessions::REAUTH
            }
            Who::Cli | Who::Token { .. } => true,
        }
    }

    /// Whose request budget this call takes from: one per token, per user across their
    /// sessions, and one for the socket.
    fn budget_key(&self) -> String {
        match &self.who {
            Who::Cli => "cli".to_owned(),
            Who::Token { id, .. } => format!("token:{id}"),
            Who::Session { user, .. } => format!("user:{user}"),
        }
    }

    /// An audit event by this caller.
    pub(crate) fn event(&self, action: &'static str) -> Event {
        let (actor, method) = match &self.who {
            Who::Cli => ("cli".to_owned(), "socket"),
            Who::Token { id, .. } => (format!("token:{id}"), "token"),
            Who::Session { user, .. } => (user.clone(), "session"),
        };
        Event {
            client: self.client,
            tenant: self.tenant().map(str::to_owned),
            ..Event::new(actor, method, action)
        }
    }
}

/// 403 unless `caller` has at least `access`.
pub(crate) fn need(caller: &Caller, access: Access) -> Result<(), Denied> {
    if caller.access() >= access {
        Ok(())
    } else {
        Err(Denied(StatusCode::FORBIDDEN, "your role cannot do this"))
    }
}

/// 403 unless a person confirmed their password recently.
pub(crate) fn need_recent(caller: &Caller) -> Result<(), Denied> {
    if caller.recently_authenticated() {
        Ok(())
    } else {
        Err(Denied(
            StatusCode::FORBIDDEN,
            "confirm your password first: POST /api/v1/auth/reauth",
        ))
    }
}

/// Refuses API tokens: a token must not create its own successors, which would outlive its
/// expiry and drop its `allowed_from` networks. People and the socket may.
pub(crate) fn need_not_token(caller: &Caller) -> Result<(), Denied> {
    if matches!(caller.who, Who::Token { .. }) {
        Err(Denied(
            StatusCode::FORBIDDEN,
            "API tokens cannot create tokens; log in or use `rdock tokens create`",
        ))
    } else {
        Ok(())
    }
}

fn unauthorized() -> Denied {
    Denied(StatusCode::UNAUTHORIZED, "log in or send a valid API token")
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

/// The caller of a request, or the answer refusing it.
pub(crate) fn identify(
    state: &State,
    method: &Method,
    headers: &HeaderMap,
    transport: Option<Transport>,
    peer: Option<Peer>,
) -> Result<Caller, Denied> {
    if transport == Some(Transport::Socket) {
        return Ok(Caller {
            who: Who::Cli,
            client: None,
            scope: None,
        });
    }
    let address: Option<IpAddr> = client(state.trust_forwarded, peer, headers);
    let session = account::cookie(headers)
        .and_then(|value| {
            if headers.contains_key(crate::sessions::BACKGROUND_HEADER) {
                state.sessions.peek(value)
            } else {
                state.sessions.get(value)
            }
        })
        .filter(|s| s.stage == Stage::Full);
    if let Some(session) = session {
        let safe = matches!(*method, Method::GET | Method::HEAD);
        if !safe && !account::csrf_ok(headers, &session) {
            return Err(Denied(
                StatusCode::FORBIDDEN,
                "missing or wrong X-CSRF-Token",
            ));
        }
        let tenant = state.users.find(&session.user).and_then(|u| u.tenant);
        return Ok(Caller {
            who: Who::Session {
                user: session.user,
                role: session.role,
                authenticated: session.authenticated,
                tenant,
            },
            client: address,
            scope: None,
        });
    }
    let Some(presented) = bearer(headers) else {
        return Err(unauthorized());
    };
    let Some((token, moved)) = state.tokens.verify(presented, address) else {
        state.audit.record(Event {
            client: address,
            outcome: Outcome::Denied,
            reason: Some("unknown, expired or revoked token".into()),
            ..Event::new("-", "token", "auth")
        });
        return Err(unauthorized());
    };
    if moved {
        state.audit.record(Event {
            client: address,
            resource: Some(token.id.clone()),
            ..Event::new(format!("token:{}", token.id), "token", "token.new_address")
        });
    }
    // A token never outlives, outranks or leaves the tenant of its creator.
    let owner = if token.created_by == "cli" {
        Some((Access::Admin, None))
    } else {
        state
            .users
            .find(&token.created_by)
            .filter(|u| !u.disabled)
            .map(|u| (Access::from(u.role), u.tenant))
    };
    let (owner_access, owner_tenant) = owner.ok_or_else(unauthorized)?;
    let tenant = match (owner_tenant, token.tenant) {
        // The creator moved to another tenant: the token no longer matches either.
        (Some(a), Some(b)) if a != b => return Err(unauthorized()),
        (Some(a), _) => Some(a),
        (None, b) => b,
    };
    Ok(Caller {
        who: Who::Token {
            id: token.id,
            access: token.role.min(owner_access),
            owner: token.created_by,
            tenant,
        },
        client: address,
        scope: None,
    })
}

/// Identifies the caller of every `/api/v1` request behind it and stores it for handlers.
/// Requests per second each caller may make, and the burst above it. A dashboard page makes a
/// few a second; the isolation test showed one script making ~500 a second takes most of a
/// CPU from a 2-CPU proxy.
const REQUESTS_PER_SECOND: u32 = 20;
const REQUEST_BURST: u32 = 100;

/// The per-caller request budget, tracking at most 4,096 callers.
pub(crate) fn request_limiter() -> rdock_limits::RateLimiter {
    rdock_limits::RateLimiter::new(
        REQUESTS_PER_SECOND,
        std::time::Duration::from_secs(1),
        REQUEST_BURST,
        4096,
    )
}

/// Marks a response whose refusal was already audited, so the generic 403 record is not
/// written twice.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Audited;

/// A 403 for a scoped caller, audited with `reason`.
pub(crate) fn tenant_denied(
    state: &State,
    caller: &Caller,
    path: String,
    reason: &str,
) -> Response {
    state.audit.record(Event {
        resource: Some(path),
        outcome: Outcome::Denied,
        reason: Some(format!("outside the caller's tenant: {reason}")),
        ..caller.event("access")
    });
    let mut response = crate::routes::error(
        StatusCode::FORBIDDEN,
        &format!("tenant-scoped callers cannot do this: {reason}"),
    );
    response.extensions_mut().insert(Audited);
    response
}

/// Retires the users and tokens of tenants that are no longer in `tenants`, for good: users
/// are disabled (their tenant stays recorded) and their sessions ended, tokens revoked, each
/// audited. A tenant that is added again later under the same name starts without them, so a
/// removed tenant's principals never attach to whoever gets the name next. Runs whenever the
/// admin API reads the tenants (every scoped request, every user or token change that names
/// one).
pub(crate) fn retire_orphans(state: &State, tenants: &rdock_model::tenant::Tenants) {
    let orphan =
        |tenant: &Option<String>| tenant.as_ref().is_some_and(|t| !tenants.contains_key(t));
    for user in state.users.list() {
        if user.disabled || !orphan(&user.tenant) {
            continue;
        }
        match state.users.update(&user.name, |u| u.disabled = true) {
            Ok(()) => {
                state.sessions.end_user(&user.name, None);
                tracing::warn!(user = %user.name, tenant = ?user.tenant, "disabled a user whose tenant was removed");
                state.audit.record(Event {
                    resource: Some(user.name.clone()),
                    reason: Some("its tenant was removed".into()),
                    tenant: user.tenant.clone(),
                    ..Event::new("rdock".to_owned(), "system", "user.disable")
                });
            }
            Err(err) => tracing::error!(error = %err, user = %user.name, "cannot disable a user"),
        }
    }
    for token in state.tokens.list(None) {
        if !orphan(&token.tenant) {
            continue;
        }
        match state.tokens.revoke(&token.id, |_| true) {
            Ok(true) => {
                tracing::warn!(token = %token.id, tenant = ?token.tenant, "revoked a token whose tenant was removed");
                state.audit.record(Event {
                    resource: Some(token.id.clone()),
                    reason: Some("its tenant was removed".into()),
                    tenant: token.tenant.clone(),
                    ..Event::new("rdock".to_owned(), "system", "token.revoke")
                });
            }
            Ok(false) => {}
            Err(err) => tracing::error!(error = %err, token = %token.id, "cannot revoke a token"),
        }
    }
}

/// Resolves a scoped caller's tenant for an operation it may reach, or refuses it.
async fn scope(
    state: &State,
    caller: &mut Caller,
    method: &Method,
    template: Option<&str>,
    path: &str,
) -> Result<(), Box<Response>> {
    let Some(tenant) = caller.tenant().map(str::to_owned) else {
        return Ok(());
    };
    if let crate::tenancy::Tenancy::Denied(reason) = crate::tenancy::classify(method, template) {
        return Err(Box::new(tenant_denied(
            state,
            caller,
            path.to_owned(),
            reason,
        )));
    }
    let control = state.control.clone();
    let tenants = state
        .main
        .spawn(async move { control.tenants().await })
        .await
        .unwrap_or_default();
    retire_orphans(state, &tenants);
    match tenants.get(&tenant) {
        Some(found) => {
            caller.scope = Some(Arc::new(crate::tenancy::Scope {
                prefix: found.prefix_of(&tenant),
                name: tenant,
            }));
            Ok(())
        }
        None => Err(Box::new(tenant_denied(
            state,
            caller,
            path.to_owned(),
            "the caller's tenant is not in `tenants`",
        ))),
    }
}

/// Calls with an unsafe method that change nothing stored and are not refused when the audit
/// log cannot be written (ADR-0033): ending one's own sessions and the steps of logging in
/// (a full disk must not lock operators out of the read-only views that show it), and the dry
/// runs.
const UNGATED: [(&str, &str); 6] = [
    ("POST", "/api/v1/auth/logout"),
    ("POST", "/api/v1/auth/mfa"),
    ("POST", "/api/v1/auth/reauth"),
    ("DELETE", "/api/v1/auth/sessions/{id}"),
    ("POST", "/api/v1/config/validate"),
    ("POST", "/api/v1/routes/explain"),
];

/// Whether a call is a mutating one that [`audit_gate`] holds back while the audit log cannot
/// take its record.
pub(crate) fn is_gated(method: &Method, template: Option<&str>) -> bool {
    if matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) {
        return false;
    }
    let template = template.unwrap_or_default();
    !UNGATED
        .iter()
        .any(|(m, path)| method.as_str() == *m && template == *path)
}

/// Refuses a mutating call with `507 Insufficient Storage` before it changes anything when
/// its audit record could not be written (ADR-0033). Read-only calls are never held back.
pub(crate) fn audit_gate(
    state: &State,
    caller: &Caller,
    method: &Method,
    template: Option<&str>,
) -> Result<(), Box<Response>> {
    if !is_gated(method, template) {
        return Ok(());
    }
    state.audit.prepare().map_err(|err| {
        state.audit.refused();
        tracing::warn!(error = %err, actor = caller.name(), %method,
            path = template.unwrap_or_default(),
            "refused a mutating admin call: its audit record cannot be written");
        Box::new(crate::routes::error(
            StatusCode::INSUFFICIENT_STORAGE,
            &format!(
                "the audit log cannot be written ({err}); changes are refused until it can, read-only calls still work"
            ),
        ))
    })
}

pub(crate) async fn authenticate(
    Extract(state): Extract<Arc<State>>,
    mut request: Request,
    next: Next,
) -> Response {
    let transport = request.extensions().get::<Transport>().copied();
    let peer = request.extensions().get::<Peer>().copied();
    let identified = identify(&state, request.method(), request.headers(), transport, peer);
    // A browser's EventSource reconnects after errors but stops at 204: a stream whose
    // session or token was revoked gets 204, so it does not retry forever.
    let stream = request.uri().path().ends_with("/stream");
    let credentials = request.headers().contains_key(header::AUTHORIZATION)
        || account::cookie(request.headers()).is_some();
    if identified.is_err() && stream && credentials {
        return StatusCode::NO_CONTENT.into_response();
    }
    match identified {
        Ok(mut caller) => {
            if let rdock_limits::Decision::Deny { retry_after } = state
                .api_rate
                .check(&caller.budget_key(), std::time::Instant::now())
            {
                return crate::auth::too_many(retry_after);
            }
            let path = request.uri().path().to_owned();
            let template = request
                .extensions()
                .get::<axum::extract::MatchedPath>()
                .map(|m| m.as_str().to_owned());
            let method = request.method().clone();
            if let Err(refused) =
                scope(&state, &mut caller, &method, template.as_deref(), &path).await
            {
                return *refused;
            }
            if let Err(refused) = audit_gate(&state, &caller, &method, template.as_deref()) {
                return *refused;
            }
            request.extensions_mut().insert(caller.clone());
            let response = next.run(request).await;
            if response.status() == StatusCode::FORBIDDEN
                && response.extensions().get::<Audited>().is_none()
            {
                state.audit.record(Event {
                    resource: Some(path),
                    outcome: Outcome::Denied,
                    reason: Some("role or recent password check missing".into()),
                    ..caller.event("access")
                });
            }
            response
        }
        Err(denied) => denied.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_is_ordered_and_metrics_is_the_least() {
        assert!(Access::Metrics < Access::Viewer);
        assert!(Access::Viewer < Access::Operator && Access::Operator < Access::Admin);
        assert_eq!(Access::from(Role::Operator), Access::Operator);
        let token = Caller {
            who: Who::Token {
                id: "x".into(),
                access: Access::Metrics,
                owner: "root".into(),
                tenant: None,
            },
            client: None,
            scope: None,
        };
        assert!(need(&token, Access::Metrics).is_ok());
        assert!(need(&token, Access::Viewer).is_err());
        assert_eq!(token.event("access").actor, "token:x");
        let cli = Caller {
            who: Who::Cli,
            client: None,
            scope: None,
        };
        assert!(need(&cli, Access::Admin).is_ok());
    }
}
