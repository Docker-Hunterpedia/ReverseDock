//! First-admin setup with the bootstrap token, and password login (ADR-0024). Sessions,
//! MFA and CSRF tokens build on this in the next step of the milestone.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Extension, State as Extract};
use axum::response::{IntoResponse, Response};
use http::{HeaderMap, HeaderValue, StatusCode, header};
use serde::Deserialize;

use crate::passwords::Verified;
use crate::routes::error;
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
fn client(peer: Option<Peer>, headers: &HeaderMap) -> Option<IpAddr> {
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

fn too_many(wait: Duration) -> Response {
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
async fn hashing<T: Send + 'static>(
    state: &State,
    work: impl FnOnce() -> T + Send + 'static,
) -> Option<T> {
    let _admitted = state.hashing.admit(&()).await.ok()?;
    tokio::task::spawn_blocking(work).await.ok()
}

fn account(user: &User) -> Response {
    axum::Json(serde_json::json!({ "name": user.name, "role": user.role })).into_response()
}

fn bearer(headers: &HeaderMap) -> &str {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or_default()
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
    if let Err(wait) = state
        .limits
        .attempt(client(peer.map(|p| p.0), &headers), SETUP_KEY)
    {
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

/// `POST /api/v1/auth/login`: checks a user name and password. Unknown names, disabled
/// users and wrong passwords get the same answer after the same Argon2 work.
pub(crate) async fn login(
    Extract(state): Extract<Arc<State>>,
    peer: Option<Extension<Peer>>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<Credentials>,
) -> Response {
    let address = client(peer.map(|p| p.0), &headers);
    let name = normalize_name(&body.name).unwrap_or_default();
    if let Err(wait) = state.limits.attempt(address, &name) {
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
                .and_then(|hash| worker.users.set_password(&user.name, hash));
            if let Err(err) = upgraded {
                tracing::warn!(user = %user.name, error = %err, "cannot upgrade the password hash");
            }
        }
        Some(user)
    })
    .await;
    match checked {
        None => busy(),
        Some(Some(user)) => account(&user),
        Some(None) => {
            tracing::info!(client = ?address, "admin login failed");
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
