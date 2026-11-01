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
use utoipa::{IntoParams, ToSchema};

use crate::State;
use crate::audit::Event;
use crate::auth::hashing;
use crate::caller::{Access, Caller, need, need_not_token, need_recent};
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

#[derive(Serialize, ToSchema)]
pub(crate) struct UserView {
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

/// `GET /api/v1/users`: every user (admin role).
#[utoipa::path(get, path = "/users", tag = "users",
    responses((status = OK, description = "The users", body = [UserView])))]
pub(crate) async fn users(
    Extract(state): Extract<Arc<State>>,
    Extension(caller): Extension<Caller>,
) -> Response {
    check!(need(&caller, Access::Admin));
    let list: Vec<UserView> = state.users.list().into_iter().map(UserView::from).collect();
    axum::Json(list).into_response()
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct NewUser {
    name: String,
    role: Role,
    password: String,
}

/// `POST /api/v1/users`: a new user with a first password, who enrols MFA at first login
/// when the policy asks for it. Admin role and a recent password check.
#[utoipa::path(post, path = "/users", tag = "users", request_body = NewUser,
    responses(
        (status = CREATED, description = "Created", body = UserView),
        (status = CONFLICT, description = "The name is taken", body = crate::openapi::ErrorBody),
        (status = UNPROCESSABLE_ENTITY, description = "Invalid name or weak password", body = crate::openapi::ErrorBody),
        (status = SERVICE_UNAVAILABLE, description = "Too many password hashes at once", body = crate::openapi::ErrorBody),
    ))]
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
            state.audit.record(Event {
                resource: Some(user.name.clone()),
                ..caller.event("user.create")
            });
            (StatusCode::CREATED, axum::Json(UserView::from(user))).into_response()
        }
        Some(Err(AddError::Exists | AddError::AdminExists)) => {
            error(StatusCode::CONFLICT, "a user with this name exists")
        }
        Some(Err(AddError::Io(err))) => internal(&err),
    }
}

#[derive(Deserialize, ToSchema)]
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
#[utoipa::path(patch, path = "/users/{name}", tag = "users", request_body = UserChange,
    params(("name" = String, Path, description = "User name")),
    responses(
        (status = OK, description = "Changed", body = UserView),
        (status = NOT_FOUND, description = "No such user", body = crate::openapi::ErrorBody),
        (status = CONFLICT, description = "No enabled admin would remain", body = crate::openapi::ErrorBody),
        (status = UNPROCESSABLE_ENTITY, description = "Weak password", body = crate::openapi::ErrorBody),
    ))]
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
            let what = [
                body.role.map(|r| format!("role={r:?}").to_lowercase()),
                body.disabled.map(|d| format!("disabled={d}")),
                body.password.as_ref().map(|_| "password".to_owned()),
                body.reset_mfa.then(|| "reset_mfa".to_owned()),
            ];
            let what: Vec<String> = what.into_iter().flatten().collect();
            state.audit.record(Event {
                resource: Some(name.clone()),
                reason: Some(what.join(",")),
                ..caller.event("user.change")
            });
            match state.users.find(&name) {
                Some(user) => axum::Json(UserView::from(user)).into_response(),
                None => error(StatusCode::NOT_FOUND, "no such user"),
            }
        }
    }
}

/// `DELETE /api/v1/users/{name}`: removes the user, their sessions and their tokens.
#[utoipa::path(delete, path = "/users/{name}", tag = "users",
    params(("name" = String, Path, description = "User name")),
    responses(
        (status = NO_CONTENT, description = "Deleted"),
        (status = NOT_FOUND, description = "No such user", body = crate::openapi::ErrorBody),
        (status = CONFLICT, description = "No enabled admin would remain", body = crate::openapi::ErrorBody),
    ))]
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
            state.audit.record(Event {
                resource: Some(name.clone()),
                ..caller.event("user.delete")
            });
            StatusCode::NO_CONTENT.into_response()
        }
    }
}

#[derive(Serialize, ToSchema)]
pub(crate) struct TokenView {
    id: String,
    name: String,
    role: Access,
    created_by: String,
    created_at: u64,
    expires_at: Option<u64>,
    #[schema(value_type = Vec<String>)]
    allowed_from: Vec<IpNet>,
    last_used_at: Option<u64>,
    #[schema(value_type = Option<String>)]
    last_used_from: Option<std::net::IpAddr>,
}

/// A new token: the value is shown only in this answer.
#[derive(Serialize, ToSchema)]
pub(crate) struct CreatedToken {
    #[serde(flatten)]
    view: TokenView,
    /// `rdk_pat_…`
    token: String,
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
#[utoipa::path(get, path = "/tokens", tag = "tokens",
    responses((status = OK, description = "The tokens", body = [TokenView])))]
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

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct TokenRequest {
    name: String,
    role: Access,
    /// Days until it expires; `0` never, when `admin.tokens.allow_no_expiry` allows it.
    #[serde(default)]
    expires_in_days: Option<u16>,
    /// Networks the token may be used from; empty means anywhere.
    #[serde(default)]
    #[schema(value_type = Vec<String>)]
    allowed_from: Vec<IpNet>,
}

/// `POST /api/v1/tokens`: a new token, shown once, with a role no higher than the caller's.
/// People and the CLI only: a token cannot create tokens.
#[utoipa::path(post, path = "/tokens", tag = "tokens", request_body = TokenRequest,
    responses(
        (status = CREATED, description = "Created; the value is not shown again", body = CreatedToken),
        (status = UNPROCESSABLE_ENTITY, description = "Invalid name or expiry", body = crate::openapi::ErrorBody),
    ))]
pub(crate) async fn create_token(
    Extract(state): Extract<Arc<State>>,
    Extension(caller): Extension<Caller>,
    axum::Json(body): axum::Json<TokenRequest>,
) -> Response {
    check!(need(&caller, Access::Viewer));
    check!(need_not_token(&caller));
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
            state.audit.record(Event {
                resource: Some(token.id.clone()),
                ..caller.event("token.create")
            });
            let created = CreatedToken {
                view: TokenView::from(token),
                token: value,
            };
            (StatusCode::CREATED, axum::Json(created)).into_response()
        }
    }
}

/// `DELETE /api/v1/tokens/{id}`: revokes one of the caller's tokens, or anyone's for an
/// admin. Takes effect at once.
#[utoipa::path(delete, path = "/tokens/{id}", tag = "tokens",
    params(("id" = String, Path, description = "Token ID")),
    responses(
        (status = NO_CONTENT, description = "Revoked"),
        (status = NOT_FOUND, description = "No such token", body = crate::openapi::ErrorBody),
    ))]
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
            state.audit.record(Event {
                resource: Some(id.clone()),
                ..caller.event("token.revoke")
            });
            StatusCode::NO_CONTENT.into_response()
        }
    }
}

/// `GET /api/v1/audit?limit=100&before=<seq>`: recent audit records, newest first. Admins
/// only.
#[utoipa::path(get, path = "/audit", tag = "audit", params(AuditQuery),
    responses((status = OK, description = "Audit records, newest first", body = [crate::openapi::AuditRecord])))]
pub(crate) async fn audit(
    Extract(state): Extract<Arc<State>>,
    Extension(caller): Extension<Caller>,
    axum::extract::Query(query): axum::extract::Query<AuditQuery>,
) -> Response {
    check!(need(&caller, Access::Admin));
    let limit = query.limit.unwrap_or(100).clamp(1, 1000);
    match state.audit.recent(limit, query.before) {
        Ok(records) => axum::Json(records).into_response(),
        Err(err) => internal(&err),
    }
}

#[derive(Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub(crate) struct AuditQuery {
    /// How many records, 1 to 1000; 100 by default.
    #[serde(default)]
    limit: Option<usize>,
    /// Only records with a sequence number below this one.
    #[serde(default)]
    before: Option<u64>,
}
