//! A fake `HashiCorp` Vault / `OpenBao` server with the KV version 2 read and the Kubernetes login,
//! as rdock uses them (W-OBS-02): `GET /v1/<mount>/data/<path>` and
//! `POST /v1/auth/<mount>/login`, in the shapes documented at
//! <https://openbao.org/docs/api/secret/kv/kv-v2/> and
//! <https://openbao.org/docs/api/auth/kubernetes/> (checked 2026-11-12).
//!
//! Tokens are random per fake and protect nothing. Values can be rotated, every read can be
//! made to fail, login leases can be short, and every request is recorded.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use ring::rand::{SecureRandom, SystemRandom};
use serde_json::{Value, json};

use crate::fake_api::{FakeApi, Recorded, Reply};

fn random_token(prefix: &str) -> String {
    let mut bytes = [0u8; 16];
    SystemRandom::new().fill(&mut bytes).unwrap();
    let hex = bytes.iter().fold(String::new(), |mut out, b| {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
        out
    });
    format!("{prefix}{hex}")
}

#[derive(Default)]
struct State {
    /// `<mount>/<path>` → (version, data).
    secrets: BTreeMap<String, (u64, Value)>,
    /// Tokens accepted for reads.
    tokens: Vec<String>,
    /// Kubernetes roles: (auth mount, role) → service-account JWT accepted.
    roles: BTreeMap<(String, String), String>,
    /// Lease of tokens issued by a login, in seconds.
    lease: u64,
}

/// The running fake.
#[derive(Clone)]
pub struct FakeVault {
    api: FakeApi,
    root: String,
    state: Arc<Mutex<State>>,
    failing: Arc<AtomicBool>,
    logins: Arc<AtomicU64>,
}

impl FakeVault {
    /// Starts a fake on a free loopback port with a random root token.
    pub async fn start() -> Self {
        let api = FakeApi::start().await;
        let root = random_token("hvs.");
        let state = Arc::new(Mutex::new(State {
            tokens: vec![root.clone()],
            lease: 3600,
            ..State::default()
        }));
        let failing = Arc::new(AtomicBool::new(false));
        let logins = Arc::new(AtomicU64::new(0));
        let (s, f, l) = (state.clone(), failing.clone(), logins.clone());
        api.guard(move |request| Some(answer(request, &s, &f, &l)));
        Self {
            api,
            root,
            state,
            failing,
            logins,
        }
    }

    /// `http://127.0.0.1:<port>`, for `secrets.vault.address`.
    pub fn url(&self) -> &str {
        self.api.url()
    }

    /// The root token, accepted for every read.
    pub fn root_token(&self) -> &str {
        &self.root
    }

    /// Writes (or rotates) the secret at `<mount>/<path>`; each write is a new version.
    #[allow(clippy::needless_pass_by_value)] // takes `json!(…)` temporaries
    pub fn put(&self, location: &str, data: Value) {
        let mut state = self.state.lock().unwrap();
        let version = state.secrets.get(location).map_or(1, |(v, _)| v + 1);
        state.secrets.insert(location.to_owned(), (version, data));
    }

    /// Accepts Kubernetes logins at `auth/<mount>/login` as `role` with this service-account
    /// token.
    pub fn kubernetes_role(&self, mount: &str, role: &str, jwt: &str) {
        self.state
            .lock()
            .unwrap()
            .roles
            .insert((mount.to_owned(), role.to_owned()), jwt.to_owned());
    }

    /// The lease, in seconds, of tokens issued by later logins.
    pub fn set_lease(&self, seconds: u64) {
        self.state.lock().unwrap().lease = seconds;
    }

    /// Revokes every token issued by a login (the root token stays).
    pub fn revoke_logins(&self) {
        let root = self.root.clone();
        self.state.lock().unwrap().tokens.retain(|t| *t == root);
    }

    /// While on, every request is answered `503`, as a sealed or unreachable server would.
    pub fn set_failing(&self, failing: bool) {
        self.failing.store(failing, Ordering::SeqCst);
    }

    /// How many logins succeeded.
    pub fn logins(&self) -> u64 {
        self.logins.load(Ordering::SeqCst)
    }

    /// Every request received.
    pub fn requests(&self) -> Vec<Recorded> {
        self.api.requests()
    }

    /// The request lines received (`GET /v1/secret/data/app`).
    pub fn lines(&self) -> Vec<String> {
        self.api.lines()
    }
}

fn errors(status: u16, message: &str) -> Reply {
    Reply::json(status, json!({ "errors": [message] }))
}

fn answer(
    request: &Recorded,
    state: &Mutex<State>,
    failing: &AtomicBool,
    logins: &AtomicU64,
) -> Reply {
    if failing.load(Ordering::SeqCst) {
        return errors(503, "Vault is sealed");
    }
    let path = request.path.strip_prefix("/v1/").unwrap_or_default();
    let mut state = state.lock().unwrap();
    if request.method == http::Method::POST
        && let Some(mount) = path
            .strip_prefix("auth/")
            .and_then(|rest| rest.strip_suffix("/login"))
    {
        let body = request.json();
        let role = body["role"].as_str().unwrap_or_default().to_owned();
        let jwt = body["jwt"].as_str().unwrap_or_default();
        return match state.roles.get(&(mount.to_owned(), role)) {
            Some(expected) if expected == jwt => {
                let token = random_token("hvs.k8s.");
                state.tokens.push(token.clone());
                logins.fetch_add(1, Ordering::SeqCst);
                Reply::json(
                    200,
                    json!({ "auth": { "client_token": token, "lease_duration": state.lease, "renewable": true, "policies": ["rdock"] } }),
                )
            }
            _ => errors(403, "permission denied"),
        };
    }
    if request.method != http::Method::GET {
        return errors(405, "unsupported operation");
    }
    let token = request.header("x-vault-token").unwrap_or_default();
    if !state.tokens.iter().any(|t| t == token) {
        return errors(403, "permission denied");
    }
    let Some((mount, rest)) = path.split_once("/data/") else {
        return errors(404, "no handler for route");
    };
    match state.secrets.get(&format!("{mount}/{rest}")) {
        Some((version, data)) => Reply::json(
            200,
            json!({
                "request_id": "00000000-0000-0000-0000-000000000000",
                "lease_id": "", "renewable": false, "lease_duration": 0,
                "data": { "data": data, "metadata": { "version": version, "destroyed": false, "deletion_time": "" } },
            }),
        ),
        None => errors(404, ""),
    }
}
