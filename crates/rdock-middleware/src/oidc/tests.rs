use super::cookie::{self, LoginState, Purpose, Sealer, Session};
use super::*;
use crate::test_support::request;

const KEY_A: &[u8] = b"0123456789abcdef0123456789abcdef-a";
const KEY_B: &[u8] = b"0123456789abcdef0123456789abcdef-b";

fn session() -> Session {
    Session {
        sub: "user-1".into(),
        consumer: "alice@example.com".into(),
        groups: vec!["staff".into()],
        email: Some("alice@example.com".into()),
        claims: vec![("email".into(), "alice@example.com".into())],
        login: 1,
        expires: u64::MAX,
        refresh_at: u64::MAX,
        refresh_token: None,
        access_token: None,
    }
}

#[test]
fn token_sessions_open_only_with_the_right_key_purpose_and_binding() {
    let keys = Sealer::new(&[KEY_A.to_vec()], Purpose::Session, "iss\0client").unwrap();
    let token = cookie::seal_json(&keys, &session()).unwrap();
    assert!(token.starts_with("v1."));
    assert_eq!(cookie::open_json::<Session>(&keys, &token), Some(session()));
    // Two seals of the same value differ (random nonce).
    assert_ne!(token, cookie::seal_json(&keys, &session()).unwrap());

    let other_key = Sealer::new(&[KEY_B.to_vec()], Purpose::Session, "iss\0client").unwrap();
    assert!(other_key.open(&token).is_none(), "foreign key");
    let state = Sealer::new(&[KEY_A.to_vec()], Purpose::State, "iss\0client").unwrap();
    assert!(
        state.open(&token).is_none(),
        "a session is not a state cookie"
    );
    let other_client = Sealer::new(&[KEY_A.to_vec()], Purpose::Session, "iss\0other").unwrap();
    assert!(other_client.open(&token).is_none(), "another relying party");

    // Tampering anywhere, truncation, or another version are refused.
    let mut bytes = token.clone().into_bytes();
    let last = bytes.len() - 5;
    bytes[last] = if bytes[last] == b'A' { b'B' } else { b'A' };
    assert!(keys.open(std::str::from_utf8(&bytes).unwrap()).is_none());
    assert!(keys.open(&token[..token.len() - 4]).is_none());
    assert!(keys.open(&token.replacen("v1.", "v2.", 1)).is_none());
    assert!(keys.open("v1.").is_none());
    assert!(keys.open("").is_none());
}

#[test]
fn rotation_decrypts_with_previous_keys_and_seals_with_the_first() {
    let old = Sealer::new(&[KEY_B.to_vec()], Purpose::Session, "b").unwrap();
    let rotated = Sealer::new(&[KEY_A.to_vec(), KEY_B.to_vec()], Purpose::Session, "b").unwrap();
    let sealed_old = cookie::seal_json(&old, &session()).unwrap();
    assert_eq!(
        cookie::open_json::<Session>(&rotated, &sealed_old),
        Some(session())
    );
    let sealed_new = cookie::seal_json(&rotated, &session()).unwrap();
    assert!(
        old.open(&sealed_new).is_none(),
        "new cookies use the new key"
    );
}

#[test]
fn large_values_are_split_and_joined() {
    let value = "x".repeat(cookie::CHUNK * 2 + 10);
    let parts = cookie::split("__Host-s", &value).unwrap();
    assert_eq!(parts.len(), 3);
    assert_eq!(parts[0].0, "__Host-s_0");
    let header = parts
        .iter()
        .map(|(n, v)| format!("{n}={v}"))
        .collect::<Vec<_>>()
        .join("; ");
    let req = request("GET", "/", &[("cookie", &format!("a=b; {header}"))]);
    assert_eq!(
        cookie::read_split(&cookie::pairs(&req), "__Host-s"),
        Some(value)
    );
    // Too large for the cap.
    assert!(cookie::split("s", &"x".repeat(cookie::CHUNK * cookie::MAX_CHUNKS + 1)).is_none());
    // A repeated cookie is refused rather than guessed.
    let req = request("GET", "/", &[("cookie", "s=1; s=2")]);
    assert_eq!(cookie::read_split(&cookie::pairs(&req), "s"), None);
    let req = request("GET", "/", &[("cookie", "s=one")]);
    assert_eq!(
        cookie::read_split(&cookie::pairs(&req), "s").as_deref(),
        Some("one")
    );
}

#[test]
fn the_post_login_target_is_a_local_path() {
    let target = |t: &str| login_target(&request("GET", t, &[]));
    assert_eq!(target("/app/page?x=1"), "/app/page?x=1");
    assert_eq!(target("//evil.example/x"), "/");
    assert_eq!(target("/\\evil.example"), "/");
    assert_eq!(target("http://evil.example/next"), "/next");
    assert_eq!(target(&format!("/{}", "a".repeat(3000))), "/");
}

#[test]
fn only_page_navigations_are_redirected() {
    let html = "text/html,application/xhtml+xml";
    assert!(is_navigation(&request("GET", "/", &[("accept", html)])));
    assert!(!is_navigation(&request(
        "GET",
        "/",
        &[("accept", "application/json")]
    )));
    assert!(!is_navigation(&request("GET", "/", &[])));
    assert!(!is_navigation(&request(
        "GET",
        "/",
        &[("accept", html), ("sec-fetch-mode", "cors")]
    )));
    assert!(is_navigation(&request(
        "GET",
        "/",
        &[("accept", "*/*"), ("sec-fetch-mode", "navigate")]
    )));
    assert!(!is_navigation(&request(
        "GET",
        "/",
        &[("accept", html), ("x-requested-with", "XMLHttpRequest")]
    )));
}

#[test]
fn at_hash_is_the_left_half_of_the_access_token_hash() {
    // Computed independently: base64url(SHA-256(token)[..16]) with Python's hashlib.
    let token = "jHkWEdUXMU1BwAsC4vtUsZwnNkKOQe7CqVf8n2sPlrA";
    assert!(at_hash_matches(
        JwtAlgorithm::Rs256,
        token,
        "k4I0m4RuqDFQyGEqcHiC2g"
    ));
    assert!(!at_hash_matches(
        JwtAlgorithm::Rs256,
        token,
        "k4I0m4RuqDFQyGEqcHiC2h"
    ));
    assert!(!at_hash_matches(
        JwtAlgorithm::Rs384,
        token,
        "k4I0m4RuqDFQyGEqcHiC2g"
    ));
}

#[test]
fn login_states_round_trip() {
    let sealer = Sealer::new(&[KEY_A.to_vec()], Purpose::State, "b").unwrap();
    let state = LoginState {
        state: "id.secret".into(),
        nonce: "n".into(),
        verifier: "v".into(),
        redirect_uri: "https://app.example.com/_rdock/oidc/callback".into(),
        target: "/".into(),
        expires: 10,
    };
    let value = cookie::seal_json(&sealer, &state).unwrap();
    assert_eq!(
        cookie::open_json::<LoginState>(&sealer, &value),
        Some(state)
    );
}

#[test]
fn the_fuzz_entry_point_returns_on_garbage() {
    for input in [
        &b""[..],
        b"v1.",
        b"v1.AAAA",
        b"__Host-rdock_oidc_0=v1.x; __Host-rdock_oidc_1=y",
        b"\xff\xfe",
        b"__Host-rdock_oidc=v1.!!!!",
    ] {
        cookie::fuzz_decode(input);
    }
}
