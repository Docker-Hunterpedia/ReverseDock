//! Managing users and API tokens (ADR-0024). Users are an admin matter; anyone may create
//! tokens up to their own role. Every change by a person needs a password check in the last
//! five minutes, and every change to a user ends that user's sessions.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Extension, Path, State as Extract};
use axum::response::{IntoResponse, Response};
use http::StatusCode;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::State;
use crate::auth::hashing;
use crate::caller::{Access, Caller, need, need_recent};
use crate::routes::error;
use crate::tokens::{NewToken, Token};
use crate::users::{AddError, Role, User, normalize_name};

macro_rules! check {
    ($result:expr) => {
        if let Err(denied) = $result {
            return denied.into_response();
        }
    };
}

fn internal(err: &std::io::Error) -> Response {
    tracing::error!(error = %err, "cannot save the admin state");
    error(StatusCode::INTERNAL_SERVER_ERROR, "cannot save the change")
}

#[derive(Serialize)]
struct UserView {
    name: String,
    role: Role,
    disabled: bool,
    created_at: u64,
    mfa: bool,
}

impl From<User> for UserView {
    fn from(user: User) -> Self {
        Self {
            name: user.name,
            role: user.role,
            disabled: user.disabled,
            created_at: user.created_at,
            mfa: user.mfa.is_some(),
        }
    }
}

/// `GET /api/v1/users`.
pub(crate) async fn users(
    Extract(state): Extract<Arc<State>>,
    Extension(caller): Extension<Caller>,
) -> Response {
    check!(need(&caller, Access::Admin));
    let list: Vec<UserView> = state.users.list().into_iter().map(UserView::from).collect();
    axum::Json(list).into_response()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NewUser {
    name: String,
    role: Role,
    password: String,
}

/// `POST /api/v1/users`: a new user with a first password, who enrols MFA at first login
/// when the policy asks for it.
pub(crate) async fn create_user(
    Extract(state): Extract<Arc<State>>,
    Extension(caller): Extension<Caller>,
    axum::Json(body): axum::Json<NewUser>,
) -> Response {
    check!(need(&caller, Access::Admin));
    check!(need_recent(&caller));
    let Some(name) = normalize_name(&body.name) else {
        return error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "a user name is 1-64 letters, digits, '.', '_' or '-'",
        );
    };
    if name == "cli" {
        return error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "`cli` is reserved for the admin socket",
        );
    }
    if let Err(weak) = state.policy.check(&body.password) {
        return error(StatusCode::UNPROCESSABLE_ENTITY, &weak.to_string());
    }
    let worker = state.clone();
    let created = hashing(&state, move || {
        let hash = worker
            .policy
            .hash(&body.password)
            .map_err(|err| AddError::Io(std::io::Error::other(err.to_string())))?;
        let user = User::new(name, body.role, hash);
        worker.users.add(user.clone()).map(|()| user)
    })
    .await;
    match created {
        None => error(StatusCode::SERVICE_UNAVAILABLE, "busy; try again"),
        Some(Ok(user)) => {
            tracing::info!(user = %user.name, by = caller.name(), "created a user");
            (StatusCode::CREATED, axum::Json(UserView::from(user))).into_response()
        }
        Some(Err(AddError::Exists | AddError::AdminExists)) => {
            error(StatusCode::CONFLICT, "a user with this name exists")
        }
        Some(Err(AddError::Io(err))) => internal(&err),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UserChange {
    #[serde(default)]
    role: Option<Role>,
    #[serde(default)]
    disabled: Option<bool>,
    #[serde(default)]
    password: Option<String>,
    /// Removes the user's second factor, so they enrol again at the next login.
    #[serde(default)]
    reset_mfa: bool,
}

/// `PATCH /api/v1/users/{name}`: role, disabled, a new password or an MFA reset. Ends the
/// user's sessions; refuses to leave no enabled admin.
pub(crate) async fn change_user(
    Extract(state): Extract<Arc<State>>,
    Extension(caller): Extension<Caller>,
    Path(name): Path<String>,
    axum::Json(body): axum::Json<UserChange>,
) -> Response {
    check!(need(&caller, Access::Admin));
    check!(need_recent(&caller));
    if let Some(password) = &body.password
        && let Err(weak) = state.policy.check(password)
    {
        return error(StatusCode::UNPROCESSABLE_ENTITY, &weak.to_string());
    }
    let name = name.to_ascii_lowercase();
    let hash = match body.password.clone() {
        None => None,
        Some(password) => {
            let worker = state.clone();
            match hashing(&state, move || worker.policy.hash(&password)).await {
                None => return error(StatusCode::SERVICE_UNAVAILABLE, "busy; try again"),
                Some(Err(err)) => return internal(&std::io::Error::other(err.to_string())),
                Some(Ok(hash)) => Some(hash),
            }
        }
    };
    let changed = state.users.update_keeping_an_admin(&name, |user| {
        if let Some(role) = body.role {
            user.role = role;
        }
        if let Some(disabled) = body.disabled {
            user.disabled = disabled;
        }
        if let Some(hash) = hash {
            user.password = hash;
        }
        if body.reset_mfa {
            user.mfa = None;
        }
    });
    match changed {
        Err(err) => internal(&err),
        Ok(None) => error(StatusCode::NOT_FOUND, "no such user"),
        Ok(Some(false)) => error(
            StatusCode::CONFLICT,
            "at least one enabled admin must remain",
        ),
        Ok(Some(true)) => {
            state.sessions.end_user(&name, None);
            tracing::info!(user = %name, by = caller.name(), "changed a user");
            match state.users.find(&name) {
                Some(user) => axum::Json(UserView::from(user)).into_response(),
                None => error(StatusCode::NOT_FOUND, "no such user"),
            }
        }
    }
}

/// `DELETE /api/v1/users/{name}`: removes the user, their sessions and their tokens.
pub(crate) async fn delete_user(
    Extract(state): Extract<Arc<State>>,
    Extension(caller): Extension<Caller>,
    Path(name): Path<String>,
) -> Response {
    check!(need(&caller, Access::Admin));
    check!(need_recent(&caller));
    let name = name.to_ascii_lowercase();
    match state.users.remove(&name) {
        Err(err) => internal(&err),
        Ok(None) => error(StatusCode::NOT_FOUND, "no such user"),
        Ok(Some(false)) => error(
            StatusCode::CONFLICT,
            "at least one enabled admin must remain",
        ),
        Ok(Some(true)) => {
            state.sessions.end_user(&name, None);
            if let Err(err) = state.tokens.revoke_user(&name) {
                return internal(&err);
            }
            tracing::info!(user = %name, by = caller.name(), "deleted a user");
            StatusCode::NO_CONTENT.into_response()
        }
    }
}

#[derive(Serialize)]
struct TokenView {
    id: String,
    name: String,
    role: Access,
    created_by: String,
    created_at: u64,
    expires_at: Option<u64>,
    allowed_from: Vec<IpNet>,
    last_used_at: Option<u64>,
    last_used_from: Option<std::net::IpAddr>,
}

impl From<Token> for TokenView {
    fn from(token: Token) -> Self {
        Self {
            id: token.id,
            name: token.name,
            role: token.role,
            created_by: token.created_by,
            created_at: token.created_at,
            expires_at: token.expires_at,
            allowed_from: token.allowed_from,
            last_used_at: token.last_used_at,
            last_used_from: token.last_used_from,
        }
    }
}

/// `GET /api/v1/tokens`: the caller's tokens, or everyone's for an admin.
pub(crate) async fn tokens(
    Extract(state): Extract<Arc<State>>,
    Extension(caller): Extension<Caller>,
) -> Response {
    check!(need(&caller, Access::Viewer));
    let owner = (caller.access() < Access::Admin).then(|| caller.name().to_owned());
    let list: Vec<TokenView> = state
        .tokens
        .list(owner.as_deref())
        .into_iter()
        .map(TokenView::from)
        .collect();
    axum::Json(list).into_response()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TokenRequest {
    name: String,
    role: Access,
    /// Days until it expires; `0` never, when `admin.tokens.allow_no_expiry` allows it.
    #[serde(default)]
    expires_in_days: Option<u16>,
    #[serde(default)]
    allowed_from: Vec<IpNet>,
}

/// `POST /api/v1/tokens`: a new token, shown once, with a role no higher than the caller's.
pub(crate) async fn create_token(
    Extract(state): Extract<Arc<State>>,
    Extension(caller): Extension<Caller>,
    axum::Json(body): axum::Json<TokenRequest>,
) -> Response {
    check!(need(&caller, Access::Viewer));
    check!(need_recent(&caller));
    let name = body.name.trim();
    if name.is_empty() || name.chars().count() > 64 {
        return error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "name the token in 1-64 characters",
        );
    }
    if body.role > caller.access() {
        return error(
            StatusCode::FORBIDDEN,
            "a token cannot have a higher role than yours",
        );
    }
    let days = body
        .expires_in_days
        .unwrap_or(state.token_rules.default_expiry_days);
    let lifetime = match days {
        0 if state.token_rules.allow_no_expiry => None,
        0 => {
            return error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "tokens must expire; admin.tokens.allow_no_expiry is off",
            );
        }
        1..=365 => Some(Duration::from_secs(u64::from(days) * 86_400)),
        _ => {
            return error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "expires_in_days is at most 365",
            );
        }
    };
    let created = state.tokens.create(NewToken {
        name: name.to_owned(),
        role: body.role,
        created_by: caller.name().to_owned(),
        lifetime,
        allowed_from: body.allowed_from,
    });
    match created {
        Err(err) => internal(&err),
        Ok((value, token)) => {
            tracing::info!(token = %token.id, by = caller.name(), "created an API token");
            let mut view = serde_json::to_value(TokenView::from(token)).unwrap_or_default();
            view["token"] = serde_json::Value::String(value);
            (StatusCode::CREATED, axum::Json(view)).into_response()
        }
    }
}

/// `DELETE /api/v1/tokens/{id}`: revokes one of the caller's tokens, or anyone's for an
/// admin. Takes effect at once.
pub(crate) async fn revoke_token(
    Extract(state): Extract<Arc<State>>,
    Extension(caller): Extension<Caller>,
    Path(id): Path<String>,
) -> Response {
    check!(need(&caller, Access::Viewer));
    let admin = caller.access() == Access::Admin;
    match state
        .tokens
        .revoke(&id, |t| admin || t.created_by == caller.name())
    {
        Err(err) => internal(&err),
        Ok(false) => error(StatusCode::NOT_FOUND, "no such token"),
        Ok(true) => {
            tracing::info!(token = %id, by = caller.name(), "revoked an API token");
            StatusCode::NO_CONTENT.into_response()
        }
    }
}
