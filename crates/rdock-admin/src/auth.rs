//! First-admin setup with the bootstrap token, and password login, which starts a session
//! (ADR-0024).

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Extension, State as Extract};
use axum::response::{IntoResponse, Response};
use http::{HeaderMap, HeaderValue, StatusCode, header};
use serde::Deserialize;

use crate::account::{self, mfa_required};
use crate::audit::{Event, Outcome};
use crate::passwords::Verified;
use crate::routes::error;
use crate::sessions::Stage;
use crate::users::{AddError, Role, User, normalize_name};
use crate::{State, Transport};

/// The remote address of a TCP connection.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Peer(pub(crate) SocketAddr);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Credentials {
    name: String,
    password: String,
}

const WRONG: &str = "wrong user name or password";

/// The rate-limit key for setup attempts; `@` keeps it apart from every user name.
const SETUP_KEY: &str = "@setup";

/// The client's address for limits and logs: the socket's peer, or, on a connection from
/// loopback (ReverseDock forwarding a route to its own admin listener), the last
/// `X-Forwarded-For` entry, which the proxy appended. Never a header from anyone else.
pub(crate) fn client(peer: Option<Peer>, headers: &HeaderMap) -> Option<IpAddr> {
    let ip = peer?.0.ip();
    if !ip.is_loopback() {
        return Some(ip);
    }
    let forwarded = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|v| v.trim().parse::<IpAddr>().ok())
        .next_back();
    Some(forwarded.unwrap_or(ip))
}

pub(crate) fn too_many(wait: Duration) -> Response {
    let mut response = error(
        StatusCode::TOO_MANY_REQUESTS,
        "too many attempts; try again later",
    );
    let seconds = wait.as_secs() + u64::from(wait.subsec_nanos() > 0);
    if let Ok(value) = HeaderValue::from_str(&seconds.to_string()) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    response
}

fn busy() -> Response {
    let mut response = error(StatusCode::SERVICE_UNAVAILABLE, "busy; try again");
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    response
}

/// Runs password hashing on a blocking thread, at most two at a time (19 MiB each by
/// default); `None` when the queue is full or the runtime is stopping.
pub(crate) async fn hashing<T: Send + 'static>(
    state: &State,
    work: impl FnOnce() -> T + Send + 'static,
) -> Option<T> {
    let _admitted = state.hashing.admit(&()).await.ok()?;
    tokio::task::spawn_blocking(work).await.ok()
}

fn account(user: &User) -> Response {
    axum::Json(serde_json::json!({ "name": user.name, "role": user.role })).into_response()
}

/// Starts a session after a correct password: complete, or waiting for the second factor or
/// for enrolment when the user has none and the policy requires one.
fn start_session(state: &State, user: &User, address: Option<IpAddr>) -> Response {
    let step = if user.mfa.is_some() {
        Stage::Mfa
    } else if mfa_required(state.mfa, user.role) {
        Stage::Enrol
    } else {
        Stage::Full
    };
    match state.sessions.create(&user.name, user.role, step, address) {
        Some((cookie, session)) => account::reply(StatusCode::OK, &session, Some(&cookie)),
        None => busy(),
    }
}

fn bearer(headers: &HeaderMap) -> &str {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or_default()
}

/// `GET /api/v1/setup`: whether the first admin still has to be created, so the dashboard
/// can show the first-run page.
pub(crate) async fn setup_needed(Extract(state): Extract<Arc<State>>) -> Response {
    axum::Json(serde_json::json!({ "needed": !state.users.has_admin() })).into_response()
}

/// `POST /api/v1/setup`: creates the first admin. Over TCP it needs the bootstrap token as
/// a bearer token; on the Unix socket the file permissions are the proof.
pub(crate) async fn setup(
    Extract(state): Extract<Arc<State>>,
    Extension(transport): Extension<Transport>,
    peer: Option<Extension<Peer>>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<Credentials>,
) -> Response {
    if state.users.has_admin() {
        return error(StatusCode::CONFLICT, "an admin user exists; log in instead");
    }
    let address = client(peer.map(|p| p.0), &headers);
    if let Err(wait) = state.limits.attempt(address, SETUP_KEY) {
        return too_many(wait);
    }
    if transport != Transport::Socket && !state.bootstrap.accepts(bearer(&headers)) {
        let mut response = error(
            StatusCode::UNAUTHORIZED,
            "the bootstrap token from the data directory is required",
        );
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        return response;
    }
    let Some(name) = normalize_name(&body.name) else {
        return error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "a user name is 1-64 letters, digits, '.', '_' or '-'",
        );
    };
    if let Err(weak) = state.policy.check(&body.password) {
        return error(StatusCode::UNPROCESSABLE_ENTITY, &weak.to_string());
    }
    let worker = state.clone();
    let created = hashing(&state, move || {
        let hash = worker
            .policy
            .hash(&body.password)
            .map_err(|err| AddError::Io(std::io::Error::other(err.to_string())))?;
        let user = User::new(name, Role::Admin, hash);
        worker.users.add_first_admin(user.clone()).map(|()| user)
    })
    .await;
    match created {
        None => busy(),
        Some(Ok(user)) => {
            if let Err(err) = state.bootstrap.consume() {
                tracing::warn!(error = %err, file = %state.bootstrap.file().display(), "cannot delete the bootstrap token");
            }
            tracing::info!(user = %user.name, "created the first admin user");
            let method = if transport == Transport::Socket {
                "socket"
            } else {
                "bootstrap"
            };
            state.audit.record(Event {
                client: address,
                resource: Some(user.name.clone()),
                ..Event::new(
                    if transport == Transport::Socket {
                        "cli"
                    } else {
                        "bootstrap"
                    },
                    method,
                    "user.create_first_admin",
                )
            });
            (StatusCode::CREATED, account(&user)).into_response()
        }
        Some(Err(AddError::AdminExists | AddError::Exists)) => {
            error(StatusCode::CONFLICT, "an admin user exists; log in instead")
        }
        Some(Err(AddError::Io(err))) => {
            tracing::error!(error = %err, "cannot create the first admin user");
            error(StatusCode::INTERNAL_SERVER_ERROR, "cannot save the user")
        }
    }
}

/// `POST /api/v1/auth/login`: checks a user name and password and starts a session.
/// Unknown names, disabled users and wrong passwords get the same answer after the same
/// Argon2 work.
pub(crate) async fn login(
    Extract(state): Extract<Arc<State>>,
    peer: Option<Extension<Peer>>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<Credentials>,
) -> Response {
    let address = client(peer.map(|p| p.0), &headers);
    let name = normalize_name(&body.name).unwrap_or_default();
    // Only well-formed names are recorded: a password typed into the name field never is.
    let actor = if name.is_empty() {
        "-".to_owned()
    } else {
        name.clone()
    };
    if let Err(wait) = state.limits.attempt(address, &name) {
        state.audit.record(Event {
            client: address,
            outcome: Outcome::Denied,
            reason: Some("rate limited".into()),
            ..Event::new(actor, "password", "login")
        });
        return too_many(wait);
    }
    let worker = state.clone();
    let checked = hashing(&state, move || {
        let user = worker.users.find(&name);
        let verified = if let Some(user) = &user {
            worker.policy.verify(&body.password, &user.password)
        } else {
            worker.policy.verify_nobody(&body.password);
            Verified::No
        };
        let user = user.filter(|u| !u.disabled && verified != Verified::No)?;
        if verified == Verified::Rehash {
            let upgraded = worker
                .policy
                .hash(&body.password)
                .map_err(|err| std::io::Error::other(err.to_string()))
                .and_then(|hash| worker.users.update(&user.name, |u| u.password = hash));
            if let Err(err) = upgraded {
                tracing::warn!(user = %user.name, error = %err, "cannot upgrade the password hash");
            }
        }
        Some(user)
    })
    .await;
    match checked {
        None => busy(),
        Some(Some(user)) => {
            state.audit.record(Event {
                client: address,
                ..Event::new(user.name.clone(), "password", "login")
            });
            start_session(&state, &user, address)
        }
        Some(None) => {
            tracing::info!(client = ?address, "admin login failed");
            state.audit.record(Event {
                client: address,
                outcome: Outcome::Denied,
                reason: Some("wrong user name or password".into()),
                ..Event::new(actor, "password", "login")
            });
            error(StatusCode::UNAUTHORIZED, WRONG)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(s: &str) -> Option<Peer> {
        s.parse().ok().map(Peer)
    }

    #[test]
    fn forwarded_addresses_count_only_from_loopback() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.9, 198.51.100.7"),
        );
        assert_eq!(
            client(peer("127.0.0.1:5000"), &headers),
            Some("198.51.100.7".parse().unwrap())
        );
        assert_eq!(
            client(peer("192.0.2.4:5000"), &headers),
            Some("192.0.2.4".parse().unwrap())
        );
        assert_eq!(
            client(peer("[::1]:5000"), &HeaderMap::new()),
            Some("::1".parse().unwrap())
        );
        assert_eq!(client(None, &headers), None);
    }
}
