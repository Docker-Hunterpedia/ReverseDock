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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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
    /// An API token, limited to its creator's current role.
    Token {
        id: String,
        access: Access,
        owner: String,
    },
    /// A complete dashboard session.
    Session {
        user: String,
        role: Role,
        authenticated: Instant,
    },
}

/// An identified caller and where the request came from.
#[derive(Debug, Clone)]
pub(crate) struct Caller {
    pub(crate) who: Who,
    pub(crate) client: Option<IpAddr>,
}

impl Caller {
    pub(crate) fn access(&self) -> Access {
        match &self.who {
            Who::Cli => Access::Admin,
            Who::Token { access, .. } => *access,
            Who::Session { role, .. } => Access::from(*role),
        }
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

    /// An audit event by this caller.
    pub(crate) fn event(&self, action: &'static str) -> Event {
        let (actor, method) = match &self.who {
            Who::Cli => ("cli".to_owned(), "socket"),
            Who::Token { id, .. } => (format!("token:{id}"), "token"),
            Who::Session { user, .. } => (user.clone(), "session"),
        };
        Event {
            client: self.client,
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
        });
    }
    let address: Option<IpAddr> = client(peer, headers);
    let session = account::cookie(headers)
        .and_then(|value| state.sessions.get(value))
        .filter(|s| s.stage == Stage::Full);
    if let Some(session) = session {
        let safe = matches!(*method, Method::GET | Method::HEAD);
        if !safe && !account::csrf_ok(headers, &session) {
            return Err(Denied(
                StatusCode::FORBIDDEN,
                "missing or wrong X-CSRF-Token",
            ));
        }
        return Ok(Caller {
            who: Who::Session {
                user: session.user,
                role: session.role,
                authenticated: session.authenticated,
            },
            client: address,
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
    // A token never outlives or outranks its creator.
    let owner_access = if token.created_by == "cli" {
        Some(Access::Admin)
    } else {
        state
            .users
            .find(&token.created_by)
            .filter(|u| !u.disabled)
            .map(|u| Access::from(u.role))
    };
    let owner_access = owner_access.ok_or_else(unauthorized)?;
    Ok(Caller {
        who: Who::Token {
            id: token.id,
            access: token.role.min(owner_access),
            owner: token.created_by,
        },
        client: address,
    })
}

/// Identifies the caller of every `/api/v1` request behind it and stores it for handlers.
pub(crate) async fn authenticate(
    Extract(state): Extract<Arc<State>>,
    mut request: Request,
    next: Next,
) -> Response {
    let transport = request.extensions().get::<Transport>().copied();
    let peer = request.extensions().get::<Peer>().copied();
    match identify(&state, request.method(), request.headers(), transport, peer) {
        Ok(caller) => {
            let path = request.uri().path().to_owned();
            request.extensions_mut().insert(caller.clone());
            let response = next.run(request).await;
            if response.status() == StatusCode::FORBIDDEN {
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
            },
            client: None,
        };
        assert!(need(&token, Access::Metrics).is_ok());
        assert!(need(&token, Access::Viewer).is_err());
        assert_eq!(token.event("access").actor, "token:x");
        let cli = Caller {
            who: Who::Cli,
            client: None,
        };
        assert!(need(&cli, Access::Admin).is_ok());
    }
}
