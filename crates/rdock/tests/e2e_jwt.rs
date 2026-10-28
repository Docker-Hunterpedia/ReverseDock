//! End-to-end: the `jwt` middleware with a JWKS file and a JWKS URL (M-SEC-01).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rdock_testkit::backend::Backend;
use rdock_testkit::client::{self, get};
use rdock_testkit::free_port;
use rdock_testkit::rdock::Rdock;
use ring::rand::SystemRandom;
use ring::signature::{self, EcdsaKeyPair, KeyPair};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const RDOCK: &str = env!("CARGO_BIN_EXE_rdock");

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

struct Issuer {
    pair: EcdsaKeyPair,
    kid: &'static str,
}

impl Issuer {
    fn new(kid: &'static str) -> Self {
        let rng = SystemRandom::new();
        let alg = &signature::ECDSA_P256_SHA256_FIXED_SIGNING;
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(alg, &rng).unwrap();
        Self {
            pair: EcdsaKeyPair::from_pkcs8(alg, pkcs8.as_ref(), &rng).unwrap(),
            kid,
        }
    }

    fn jwks(&self) -> String {
        let point = self.pair.public_key().as_ref();
        json!({ "keys": [{ "kty": "EC", "crv": "P-256", "kid": self.kid, "x": b64(&point[1..33]), "y": b64(&point[33..]) }] })
            .to_string()
    }

    fn token(&self, claims: &Value) -> String {
        let header = json!({ "alg": "ES256", "kid": self.kid, "typ": "JWT" });
        let input = format!(
            "{}.{}",
            b64(header.to_string().as_bytes()),
            b64(claims.to_string().as_bytes())
        );
        let sig = self
            .pair
            .sign(&SystemRandom::new(), input.as_bytes())
            .unwrap();
        format!("{input}.{}", b64(sig.as_ref()))
    }
}

fn claims(sub: &str) -> Value {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    json!({ "iss": "https://idp.test", "aud": "api", "sub": sub, "tenant": "acme", "exp": now + 300 })
}

fn bearer(token: &str) -> http::Request<http_body_util::Full<bytes::Bytes>> {
    let mut req = get("api.test", "/");
    req.headers_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    req.headers_mut()
        .insert("x-tenant", "spoofed".parse().unwrap());
    req
}

fn config(port: u16, backend: SocketAddr, keys: &str) -> String {
    format!(
        r#"
listeners:
  web: {{ address: "127.0.0.1:{port}" }}
defaults: {{ listeners: [web], tls: off }}
routes:
  api: {{ match: "PathPrefix(`/`)", service: api, middlewares: [auth] }}
middlewares:
  auth:
    type: jwt
    {keys}
    issuer: https://idp.test
    audiences: [api]
    algorithms: [ES256]
    claims_to_headers: {{ tenant: x-tenant }}
services:
  api: {{ backends: [{{ address: "{backend}" }}] }}
"#
    )
}

#[tokio::test]
async fn tokens_are_verified_against_a_jwks_file() {
    let issuer = Issuer::new("k1");
    let dir = tempfile::tempdir().unwrap();
    let jwks = dir.path().join("jwks.json");
    std::fs::write(&jwks, issuer.jwks()).unwrap();
    let backend = Backend::start("api").await;
    let port = free_port();
    let keys = format!("jwks_file: \"{}\"", jwks.display());
    let rdock = Rdock::start(RDOCK, &config(port, backend.addr, &keys));

    let missing = client::http1(addr(port), get("api.test", "/")).await;
    assert_eq!(missing.status, 401);
    assert_eq!(missing.header("www-authenticate"), Some("Bearer"));

    let ok = client::http1(addr(port), bearer(&issuer.token(&claims("alice")))).await;
    assert_eq!(ok.status, 200);
    let headers = &ok.json()["headers"];
    assert_eq!(
        headers["x-tenant"][0], "acme",
        "the claim, not the spoofed header"
    );
    assert!(
        headers["authorization"][0]
            .as_str()
            .unwrap()
            .starts_with("Bearer ")
    );

    let stranger = Issuer::new("k1");
    let forged = client::http1(addr(port), bearer(&stranger.token(&claims("mallory")))).await;
    assert_eq!(forged.status, 401);
    assert_eq!(
        forged.header("www-authenticate"),
        Some("Bearer error=\"invalid_token\"")
    );
    let mut wrong_aud = claims("alice");
    wrong_aud["aud"] = json!("billing");
    let refused = client::http1(addr(port), bearer(&issuer.token(&wrong_aud))).await;
    assert_eq!(refused.status, 401);
    assert_eq!(
        backend.traffic(),
        1,
        "only the valid token reached the backend"
    );
    let users: Vec<Value> = rdock
        .access_log()
        .iter()
        .map(|r| r["user"].clone())
        .collect();
    assert!(
        users.contains(&json!("alice")),
        "the access log names the subject: {users:?}"
    );
}

/// Serves `body` as JSON to every request and counts them.
async fn jwks_server(body: String) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                continue;
            };
            counter.fetch_add(1, Ordering::SeqCst);
            let body = body.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf).await;
                let reply = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(reply.as_bytes()).await;
            });
        }
    });
    (address, hits)
}

#[tokio::test]
async fn keys_come_from_a_jwks_url_in_the_background() {
    let issuer = Issuer::new("k1");
    let (jwks, hits) = jwks_server(issuer.jwks()).await;
    let backend = Backend::start("api").await;
    let port = free_port();
    let keys = format!("jwks_url: \"http://{jwks}/.well-known/jwks.json\"");
    let _rdock = Rdock::start(RDOCK, &config(port, backend.addr, &keys));
    // The first request waits for the first key set; later ones use the cache.
    for _ in 0..5 {
        let ok = client::http1(addr(port), bearer(&issuer.token(&claims("bob")))).await;
        assert_eq!(ok.status, 200);
    }
    assert_eq!(hits.load(Ordering::SeqCst), 1, "fetched once, then cached");
}
