//! The logged-in user's own session: second factor, TOTP enrolment, re-authentication,
//! logout and session lists (ADR-0024). Every unsafe request here carries the session's
//! synchronizer token in `X-CSRF-Token`.

use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use axum::extract::{Extension, Path, State as Extract};
use axum::response::{IntoResponse, Response};
use http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use rdock_model::settings::MfaPolicy;
use serde::Deserialize;
use subtle::ConstantTimeEq;

use crate::auth::{Peer, client, hashing, too_many};
use crate::passwords::Verified;
use crate::routes::{Denied, error};
use crate::sessions::{COOKIE, REAUTH, Session, Stage};
use crate::users::{Mfa, Role};
use crate::{State, totp};

/// The session cookie's value, if the request has one.
pub(crate) fn cookie(headers: &HeaderMap) -> Option<&str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|pair| pair.trim().strip_prefix(COOKIE)?.strip_prefix('='))
}

/// Whether the request carries the session's CSRF token.
pub(crate) fn csrf_ok(headers: &HeaderMap, session: &Session) -> bool {
    headers
        .get("x-csrf-token")
        .is_some_and(|v| bool::from(v.as_bytes().ct_eq(session.csrf.as_bytes())))
}

fn set_cookie(response: &mut Response, value: &str) {
    let cookie = format!("{COOKIE}={value}; Path=/; Secure; HttpOnly; SameSite=Strict");
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}

/// Whether `policy` makes a user with `role` enrol a second factor.
pub(crate) fn mfa_required(policy: MfaPolicy, role: Role) -> bool {
    match policy {
        MfaPolicy::Required => true,
        MfaPolicy::RequiredForAdmins => role == Role::Admin,
        MfaPolicy::Optional => false,
    }
}

/// What a session's own user sees of it.
fn describe(session: &Session) -> serde_json::Value {
    serde_json::json!({
        "name": session.user,
        "role": session.role,
        "stage": session.stage,
        "csrf_token": session.csrf,
    })
}

fn respond(status: StatusCode, body: serde_json::Value, new_cookie: Option<&str>) -> Response {
    let mut response = (status, axum::Json(body)).into_response();
    if let Some(value) = new_cookie {
        set_cookie(&mut response, value);
    }
    response
}

/// The session described to its own user, with the cookie set when it is new.
pub(crate) fn reply(status: StatusCode, session: &Session, new_cookie: Option<&str>) -> Response {
    respond(status, describe(session), new_cookie)
}

/// The caller's session in one of `stages`, with the CSRF token checked on unsafe methods.
fn current<'h>(
    state: &State,
    method: &Method,
    headers: &'h HeaderMap,
    stages: &[Stage],
) -> Result<(&'h str, Session), Denied> {
    let Some((value, session)) =
        cookie(headers).and_then(|v| state.sessions.get(v).map(|s| (v, s)))
    else {
        return Err(Denied(StatusCode::UNAUTHORIZED, "log in first"));
    };
    let safe = matches!(*method, Method::GET | Method::HEAD);
    if !safe && !csrf_ok(headers, &session) {
        return Err(Denied(
            StatusCode::FORBIDDEN,
            "missing or wrong X-CSRF-Token",
        ));
    }
    if !stages.contains(&session.stage) {
        let message = match session.stage {
            Stage::Mfa => "enter your authentication code first",
            Stage::Enrol => "set up an authenticator app first",
            Stage::Full => "you are logged in already",
        };
        return Err(Denied(StatusCode::CONFLICT, message));
    }
    Ok((value, session))
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Checks a TOTP code or a recovery code for `user` and records it as used.
fn second_factor(state: &State, user: &str, code: &str) -> std::io::Result<bool> {
    state.users.update(user, |u| {
        let Some(mfa) = u.mfa.as_mut() else {
            return false;
        };
        if let Some(step) = totp::verify(&mfa.secret, code, now_unix(), mfa.last_step) {
            mfa.last_step = step;
            true
        } else if let Some(index) = totp::match_recovery(&mfa.recovery, code) {
            mfa.recovery.remove(index);
            true
        } else {
            false
        }
    })
}

fn internal(err: &std::io::Error) -> Response {
    tracing::error!(error = %err, "cannot save the users file");
    error(StatusCode::INTERNAL_SERVER_ERROR, "cannot save the user")
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Code {
    code: String,
}

/// `GET /api/v1/auth/session`: who is logged in, how far, and the CSRF token.
pub(crate) async fn session(
    Extract(state): Extract<Arc<State>>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    match current(
        &state,
        &method,
        &headers,
        &[Stage::Mfa, Stage::Enrol, Stage::Full],
    ) {
        Ok((_, session)) => reply(StatusCode::OK, &session, None),
        Err(refused) => refused.into_response(),
    }
}

/// `POST /api/v1/auth/mfa`: the second step of a login, with a TOTP or recovery code.
pub(crate) async fn mfa(
    Extract(state): Extract<Arc<State>>,
    method: Method,
    peer: Option<Extension<Peer>>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<Code>,
) -> Response {
    let (value, session) = match current(&state, &method, &headers, &[Stage::Mfa]) {
        Ok(found) => found,
        Err(refused) => return refused.into_response(),
    };
    if let Err(wait) = state
        .limits
        .attempt(client(peer.map(|p| p.0), &headers), &session.user)
    {
        return too_many(wait);
    }
    match second_factor(&state, &session.user, &body.code) {
        Err(err) => internal(&err),
        Ok(false) => error(StatusCode::UNAUTHORIZED, "wrong code"),
        Ok(true) => match state.sessions.rotate(value, |s| s.stage = Stage::Full) {
            Some((cookie, session)) => reply(StatusCode::OK, &session, Some(&cookie)),
            None => error(StatusCode::UNAUTHORIZED, "log in first"),
        },
    }
}

/// `POST /api/v1/auth/totp`: a new TOTP secret to enrol, confirmed with
/// `POST /api/v1/auth/totp/confirm`.
pub(crate) async fn enrol(
    Extract(state): Extract<Arc<State>>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    let (value, session) = match current(&state, &method, &headers, &[Stage::Enrol, Stage::Full]) {
        Ok(found) => found,
        Err(refused) => return refused.into_response(),
    };
    if state
        .users
        .find(&session.user)
        .is_some_and(|u| u.mfa.is_some())
    {
        return error(
            StatusCode::CONFLICT,
            "an authenticator app is set up already",
        );
    }
    let Some(secret) = totp::new_secret() else {
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "the random generator failed",
        );
    };
    state
        .sessions
        .modify(value, |s| s.pending_totp = Some(secret.clone()));
    let uri = totp::uri(&session.user, &secret);
    axum::Json(serde_json::json!({ "secret": secret, "uri": uri })).into_response()
}

/// `POST /api/v1/auth/totp/confirm`: saves the secret once the app shows a matching code,
/// returns ten recovery codes (shown once) and ends the user's other sessions.
pub(crate) async fn confirm(
    Extract(state): Extract<Arc<State>>,
    method: Method,
    peer: Option<Extension<Peer>>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<Code>,
) -> Response {
    let (value, session) = match current(&state, &method, &headers, &[Stage::Enrol, Stage::Full]) {
        Ok(found) => found,
        Err(refused) => return refused.into_response(),
    };
    let Some(secret) = session.pending_totp.clone() else {
        return error(StatusCode::CONFLICT, "start with POST /api/v1/auth/totp");
    };
    if let Err(wait) = state
        .limits
        .attempt(client(peer.map(|p| p.0), &headers), &session.user)
    {
        return too_many(wait);
    }
    let Some(step) = totp::verify(&secret, &body.code, now_unix(), 0) else {
        return error(StatusCode::UNAUTHORIZED, "wrong code");
    };
    let Some((shown, stored)) = totp::recovery_codes() else {
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "the random generator failed",
        );
    };
    let saved = state.users.update(&session.user, |u| {
        u.mfa.is_none().then(|| {
            u.mfa = Some(Mfa {
                secret,
                last_step: step,
                recovery: stored,
            });
        })
    });
    match saved {
        Err(err) => return internal(&err),
        Ok(None) => {
            return error(
                StatusCode::CONFLICT,
                "an authenticator app is set up already",
            );
        }
        Ok(Some(())) => {}
    }
    state.sessions.end_user(&session.user, Some(value));
    let rotated = state.sessions.rotate(value, |s| {
        s.stage = Stage::Full;
        s.pending_totp = None;
        s.authenticated = Instant::now();
    });
    let Some((cookie, session)) = rotated else {
        return error(StatusCode::UNAUTHORIZED, "log in first");
    };
    tracing::info!(user = %session.user, "enrolled an authenticator app");
    let mut body = describe(&session);
    body["recovery_codes"] = serde_json::json!(shown);
    respond(StatusCode::OK, body, Some(&cookie))
}

/// `POST /api/v1/auth/recovery-codes`: replaces the caller's recovery codes with ten new
/// ones, shown once. Needs the password (and code) confirmed in the last five minutes; the
/// old codes stop working at once.
pub(crate) async fn new_recovery_codes(
    Extract(state): Extract<Arc<State>>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    let (_, session) = match current(&state, &method, &headers, &[Stage::Full]) {
        Ok(found) => found,
        Err(refused) => return refused.into_response(),
    };
    if session.authenticated.elapsed() > REAUTH {
        return error(
            StatusCode::FORBIDDEN,
            "confirm your password first: POST /api/v1/auth/reauth",
        );
    }
    let Some((shown, stored)) = totp::recovery_codes() else {
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "the random generator failed",
        );
    };
    let replaced = state.users.update(&session.user, |u| {
        u.mfa.as_mut().map(|mfa| mfa.recovery = stored)
    });
    match replaced {
        Err(err) => internal(&err),
        Ok(None) => error(StatusCode::CONFLICT, "set up an authenticator app first"),
        Ok(Some(())) => {
            tracing::info!(user = %session.user, "replaced the recovery codes");
            axum::Json(serde_json::json!({ "recovery_codes": shown })).into_response()
        }
    }
}

/// `GET /api/v1/auth/mfa`: whether the caller has a second factor and how many recovery
/// codes are left.
pub(crate) async fn mfa_state(
    Extract(state): Extract<Arc<State>>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    let (_, session) = match current(&state, &method, &headers, &[Stage::Full]) {
        Ok(found) => found,
        Err(refused) => return refused.into_response(),
    };
    let mfa = state.users.find(&session.user).and_then(|u| u.mfa);
    axum::Json(serde_json::json!({
        "enrolled": mfa.is_some(),
        "recovery_codes_left": mfa.map_or(0, |m| m.recovery.len()),
        "required": mfa_required(state.mfa, session.role),
    }))
    .into_response()
}

/// `DELETE /api/v1/auth/totp`: removes the caller's second factor, when the policy allows
/// it and the password was confirmed in the last five minutes.
pub(crate) async fn unenrol(
    Extract(state): Extract<Arc<State>>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    let (value, session) = match current(&state, &method, &headers, &[Stage::Full]) {
        Ok(found) => found,
        Err(refused) => return refused.into_response(),
    };
    if mfa_required(state.mfa, session.role) {
        return error(
            StatusCode::FORBIDDEN,
            "a second factor is required for your role",
        );
    }
    if session.authenticated.elapsed() > REAUTH {
        return error(
            StatusCode::FORBIDDEN,
            "confirm your password first: POST /api/v1/auth/reauth",
        );
    }
    if let Err(err) = state.users.update(&session.user, |u| u.mfa = None) {
        return internal(&err);
    }
    state.sessions.end_user(&session.user, Some(value));
    match state.sessions.rotate(value, |_| {}) {
        Some((cookie, session)) => reply(StatusCode::OK, &session, Some(&cookie)),
        None => error(StatusCode::UNAUTHORIZED, "log in first"),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Reauth {
    password: String,
    #[serde(default)]
    code: Option<String>,
}

/// `POST /api/v1/auth/reauth`: confirms the password (and code) again before a sensitive
/// change (ASVS 7.5.1).
pub(crate) async fn reauth(
    Extract(state): Extract<Arc<State>>,
    method: Method,
    peer: Option<Extension<Peer>>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<Reauth>,
) -> Response {
    let (value, session) = match current(&state, &method, &headers, &[Stage::Full]) {
        Ok(found) => found,
        Err(refused) => return refused.into_response(),
    };
    if let Err(wait) = state
        .limits
        .attempt(client(peer.map(|p| p.0), &headers), &session.user)
    {
        return too_many(wait);
    }
    let worker = state.clone();
    let name = session.user.clone();
    let checked = hashing(&state, move || {
        let user = worker.users.find(&name)?;
        let password_ok = worker.policy.verify(&body.password, &user.password) != Verified::No;
        let code_ok = match (&user.mfa, body.code.as_deref()) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(_), Some(code)) => second_factor(&worker, &name, code).unwrap_or(false),
        };
        Some(password_ok && code_ok)
    })
    .await;
    match checked {
        None => error(StatusCode::SERVICE_UNAVAILABLE, "busy; try again"),
        Some(Some(true)) => {
            state
                .sessions
                .modify(value, |s| s.authenticated = Instant::now());
            StatusCode::NO_CONTENT.into_response()
        }
        Some(_) => error(StatusCode::UNAUTHORIZED, "wrong password or code"),
    }
}

/// `POST /api/v1/auth/logout`: ends the session and tells the browser to forget it.
pub(crate) async fn logout(
    Extract(state): Extract<Arc<State>>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    let (value, _) = match current(
        &state,
        &method,
        &headers,
        &[Stage::Mfa, Stage::Enrol, Stage::Full],
    ) {
        Ok(found) => found,
        Err(refused) => return refused.into_response(),
    };
    state.sessions.remove(value);
    let mut response = StatusCode::NO_CONTENT.into_response();
    let expired = format!("{COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0");
    if let Ok(value) = HeaderValue::from_str(&expired) {
        response.headers_mut().insert(header::SET_COOKIE, value);
    }
    response.headers_mut().insert(
        "clear-site-data",
        HeaderValue::from_static("\"cache\", \"cookies\""),
    );
    response
}

/// `GET /api/v1/auth/sessions`: the caller's sessions, or everyone's for an admin.
pub(crate) async fn sessions(
    Extract(state): Extract<Arc<State>>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    let (value, session) = match current(&state, &method, &headers, &[Stage::Full]) {
        Ok(found) => found,
        Err(refused) => return refused.into_response(),
    };
    let user = (session.role != Role::Admin).then_some(session.user.as_str());
    axum::Json(state.sessions.list(user, value)).into_response()
}

/// `DELETE /api/v1/auth/sessions/{id}`: ends one of the caller's sessions, or anyone's for
/// an admin.
pub(crate) async fn end_session(
    Extract(state): Extract<Arc<State>>,
    method: Method,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let (_, session) = match current(&state, &method, &headers, &[Stage::Full]) {
        Ok(found) => found,
        Err(refused) => return refused.into_response(),
    };
    let ended = state.sessions.end_by_id(&id, |s| {
        session.role == Role::Admin || s.user == session.user
    });
    if ended {
        StatusCode::NO_CONTENT.into_response()
    } else {
        error(StatusCode::NOT_FOUND, "no such session")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_session_cookie_is_found_among_others() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("theme=dark; __Host-rdock_session=abc; other=1"),
        );
        assert_eq!(cookie(&headers), Some("abc"));
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("__Host-rdock_sessionx=abc"),
        );
        assert_eq!(cookie(&headers), None);
    }

    #[test]
    fn the_policy_decides_who_must_enrol() {
        assert!(mfa_required(MfaPolicy::RequiredForAdmins, Role::Admin));
        assert!(!mfa_required(MfaPolicy::RequiredForAdmins, Role::Operator));
        assert!(mfa_required(MfaPolicy::Required, Role::Viewer));
        assert!(!mfa_required(MfaPolicy::Optional, Role::Admin));
    }
}
