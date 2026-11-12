//! A fake Cloudflare Access team: the certs endpoint in Cloudflare's shape (`keys`,
//! `public_cert`, `public_certs`, as documented on 2026-11-02 at
//! <https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/>)
//! with two RSA keys from `testdata`, one of which is published at a time or both (the 7-day
//! overlap after a rotation), and application tokens signed RS256 the way Access signs them.
//!
//! The keys are throw-away test keys; they protect nothing.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::SystemRandom;
use ring::signature::{self, RsaKeyPair};
use serde_json::{Value, json};

use crate::fake_api::{FakeApi, Reply};

const KEYS: [&[u8]; 2] = [
    include_bytes!("../testdata/access-test-rsa-1.pk8"),
    include_bytes!("../testdata/access-test-rsa-2.pk8"),
];

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Seconds since the Unix epoch.
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// The fake team.
#[derive(Clone)]
pub struct FakeAccess {
    api: FakeApi,
    team: String,
    keys: Arc<Vec<RsaKeyPair>>,
    published: Arc<Mutex<Vec<usize>>>,
    hits: Arc<AtomicUsize>,
}

impl FakeAccess {
    /// A team named `team` publishing key 0.
    pub async fn start(team: &str) -> Self {
        let keys: Arc<Vec<RsaKeyPair>> = Arc::new(
            KEYS.iter()
                .map(|der| RsaKeyPair::from_pkcs8(der).unwrap())
                .collect(),
        );
        let published = Arc::new(Mutex::new(vec![0]));
        let hits = Arc::new(AtomicUsize::new(0));
        let api = FakeApi::start().await;
        let (k, p, h) = (keys.clone(), published.clone(), hits.clone());
        api.route("GET", "/cdn-cgi/access/certs", move |_, _| {
            h.fetch_add(1, Ordering::SeqCst);
            let published = p.lock().unwrap().clone();
            Reply::json(200, certs(&k, &published))
        });
        Self {
            api,
            team: team.to_owned(),
            keys,
            published,
            hits,
        }
    }

    /// The URL to give `certs_url`.
    pub fn certs_url(&self) -> String {
        format!("{}/cdn-cgi/access/certs", self.api.url())
    }

    /// `https://<team>.cloudflareaccess.com`.
    pub fn issuer(&self) -> String {
        format!("https://{}.cloudflareaccess.com", self.team)
    }

    /// Publishes these keys (by index, 0 or 1) from now on.
    pub fn publish(&self, keys: &[usize]) {
        *self.published.lock().unwrap() = keys.to_vec();
    }

    /// How often the certs were fetched.
    pub fn fetches(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }

    /// The claims of a user's token for `aud`, valid for five minutes.
    pub fn user_claims(&self, aud: &str, email: &str) -> Value {
        let now = now();
        json!({
            "aud": [aud], "email": email, "exp": now + 300, "iat": now, "nbf": now,
            "iss": self.issuer(), "type": "app", "identity_nonce": "6ei69kawdKzMIAPF",
            "sub": "7335d417-61da-459d-899c-0a01c76a2f94", "country": "US",
        })
    }

    /// The claims of a service token's token for `aud`: empty `sub`, `common_name` set.
    pub fn service_claims(&self, aud: &str, client_id: &str) -> Value {
        let now = now();
        json!({
            "aud": [aud], "common_name": client_id, "exp": now + 300, "iat": now, "nbf": now,
            "iss": self.issuer(), "type": "app", "identity_nonce": "6ei69kawdKzMIAPF", "sub": "",
        })
    }

    /// A token with `claims` signed RS256 by key `index`.
    pub fn token(&self, index: usize, claims: &Value) -> String {
        let header = json!({ "alg": "RS256", "kid": kid(index), "typ": "JWT" });
        let input = format!(
            "{}.{}",
            b64(header.to_string().as_bytes()),
            b64(claims.to_string().as_bytes())
        );
        let pair = &self.keys[index];
        let mut sig = vec![0; pair.public().modulus_len()];
        pair.sign(
            &signature::RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            input.as_bytes(),
            &mut sig,
        )
        .unwrap();
        format!("{input}.{}", b64(&sig))
    }
}

fn kid(index: usize) -> String {
    format!("access-test-key-{index}")
}

/// The certs document for the published keys.
fn certs(keys: &[RsaKeyPair], published: &[usize]) -> Value {
    let jwks: Vec<Value> = published
        .iter()
        .map(|&i| {
            let public: signature::RsaPublicKeyComponents<Vec<u8>> = keys[i].public().into();
            json!({ "kid": kid(i), "kty": "RSA", "alg": "RS256", "use": "sig", "e": b64(&public.e), "n": b64(&public.n) })
        })
        .collect();
    let pems: Vec<Value> = published
        .iter()
        .map(|&i| json!({ "kid": kid(i), "cert": "-----BEGIN CERTIFICATE-----\nMIIDfake\n-----END CERTIFICATE-----\n" }))
        .collect();
    json!({
        "keys": jwks,
        "public_cert": pems.first().cloned().unwrap_or(Value::Null),
        "public_certs": pems,
    })
}
