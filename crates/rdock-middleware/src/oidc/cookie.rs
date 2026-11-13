//! The sealed cookies of `oidc`: the session and the per-login state, encrypted and
//! authenticated with ChaCha20-Poly1305 under keys derived by HKDF-SHA256 from the configured
//! key, one key per purpose (session, state) and per relying party (issuer and client ID), so
//! a cookie of one kind or one middleware never opens as another.
//!
//! A sealed value is `v1.` followed by the unpadded base64url of a random 96-bit nonce and the
//! ciphertext with its tag. Values longer than [`CHUNK`] are split over numbered cookies
//! (`name_0`, `name_1`, …), at most [`MAX_CHUNKS`].

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use pingora::http::RequestHeader;
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use ring::hkdf;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

/// Format version, the prefix of every sealed value.
const VERSION: &str = "v1.";
/// Salt of the key derivation (fixed: the input key is already high-entropy).
const SALT: &[u8] = b"rdock-oidc-cookie-v1";
/// Longest value in one cookie; browsers keep at least 4096 bytes per cookie, name and
/// attributes included (RFC 6265 §6.1).
pub(crate) const CHUNK: usize = 3800;
/// Most cookies one session is split over.
pub(crate) const MAX_CHUNKS: usize = 4;
/// Shortest configured key.
pub(crate) const MIN_KEY: usize = 32;

/// What a sealed cookie is for; each purpose has its own key.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Purpose {
    Session,
    State,
}

impl Purpose {
    fn label(self) -> &'static [u8] {
        match self {
            Self::Session => b"session",
            Self::State => b"state",
        }
    }
}

/// Seals with the first key, opens with any (rotation).
pub(crate) struct Sealer {
    keys: Vec<LessSafeKey>,
    random: SystemRandom,
}

impl std::fmt::Debug for Sealer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sealer")
            .field("keys", &self.keys.len())
            .finish_non_exhaustive()
    }
}

impl Sealer {
    /// Keys for `purpose`, bound to `binding` (the relying party), from each secret.
    pub(crate) fn new(secrets: &[Vec<u8>], purpose: Purpose, binding: &str) -> Option<Self> {
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, SALT);
        let mut keys = Vec::with_capacity(secrets.len());
        for secret in secrets {
            let prk = salt.extract(secret);
            let info = [purpose.label(), b"\0", binding.as_bytes()];
            let okm = prk.expand(&info, &CHACHA20_POLY1305).ok()?;
            keys.push(LessSafeKey::new(UnboundKey::from(okm)));
        }
        (!keys.is_empty()).then(|| Self {
            keys,
            random: SystemRandom::new(),
        })
    }

    /// Encrypts `plaintext` into a cookie value.
    pub(crate) fn seal(&self, plaintext: &[u8]) -> Option<String> {
        let key = self.keys.first()?;
        let mut nonce = [0u8; NONCE_LEN];
        self.random.fill(&mut nonce).ok()?;
        let mut data = plaintext.to_vec();
        key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(VERSION.as_bytes()),
            &mut data,
        )
        .ok()?;
        let mut out = nonce.to_vec();
        out.extend_from_slice(&data);
        Some(format!("{VERSION}{}", URL_SAFE_NO_PAD.encode(out)))
    }

    /// Decrypts a cookie value; `None` for anything not sealed by one of the keys.
    pub(crate) fn open(&self, value: &str) -> Option<Vec<u8>> {
        if value.len() > CHUNK * MAX_CHUNKS + VERSION.len() {
            return None;
        }
        let bytes = URL_SAFE_NO_PAD.decode(value.strip_prefix(VERSION)?).ok()?;
        if bytes.len() < NONCE_LEN + CHACHA20_POLY1305.tag_len() {
            return None;
        }
        let (nonce, sealed) = bytes.split_at(NONCE_LEN);
        let nonce: [u8; NONCE_LEN] = nonce.try_into().ok()?;
        self.keys.iter().find_map(|key| {
            let mut data = sealed.to_vec();
            key.open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(VERSION.as_bytes()),
                &mut data,
            )
            .ok()
            .map(|plain| plain.to_vec())
        })
    }
}

/// What a session cookie holds: only what later requests need.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Session {
    /// `sub` of the ID token.
    pub(crate) sub: String,
    /// The consumer name.
    pub(crate) consumer: String,
    /// The groups.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) groups: Vec<String>,
    /// The verified e-mail address, for `allowed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) email: Option<String>,
    /// Claims passed on as headers, already as header text.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) claims: Vec<(String, String)>,
    /// Login time (Unix seconds).
    pub(crate) login: u64,
    /// When the session ends whatever happens (Unix seconds).
    pub(crate) expires: u64,
    /// When the tokens expire and a refresh is due (Unix seconds).
    pub(crate) refresh_at: u64,
    /// The refresh token, when the provider issued one and `refresh` is on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) refresh_token: Option<String>,
    /// The access token, with `forward_access_token`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) access_token: Option<String>,
}

/// What a state cookie holds for one login in progress.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct LoginState {
    /// The full `state` sent to the provider.
    pub(crate) state: String,
    /// The `nonce` the ID token must carry.
    pub(crate) nonce: String,
    /// The PKCE code verifier.
    pub(crate) verifier: String,
    /// The redirect URI sent with the authorization request.
    pub(crate) redirect_uri: String,
    /// Where to go after the login (a path on the same host).
    pub(crate) target: String,
    /// When the login expires (Unix seconds).
    pub(crate) expires: u64,
}

/// Seals a serializable value.
pub(crate) fn seal_json<T: Serialize>(sealer: &Sealer, value: &T) -> Option<String> {
    sealer.seal(&serde_json::to_vec(value).ok()?)
}

/// Opens and parses a sealed value.
pub(crate) fn open_json<T: for<'de> Deserialize<'de>>(sealer: &Sealer, value: &str) -> Option<T> {
    serde_json::from_slice(&sealer.open(value)?).ok()
}

/// Every `name=value` pair of the request's `Cookie` headers.
pub(crate) fn pairs(req: &RequestHeader) -> Vec<(&str, &str)> {
    req.headers
        .get_all(http::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .map(|(n, v)| (n.trim(), v.trim().trim_matches('"')))
        .collect()
}

/// The sealed session value of cookie `base`: the cookie itself, or its numbered chunks joined.
/// `None` when absent, repeated or malformed.
pub(crate) fn read_split(cookies: &[(&str, &str)], base: &str) -> Option<String> {
    let find = |name: &str| {
        let mut values = cookies.iter().filter(|(n, _)| *n == name).map(|(_, v)| *v);
        match (values.next(), values.next()) {
            (Some(v), None) => Ok(Some(v)),
            (None, _) => Ok(None),
            (Some(_), Some(_)) => Err(()),
        }
    };
    if let Some(whole) = find(base).ok()? {
        return Some(whole.to_owned());
    }
    let mut out = String::new();
    for i in 0..MAX_CHUNKS {
        match find(&format!("{base}_{i}")).ok()? {
            Some(part) => out.push_str(part),
            None if i == 0 => return None,
            None => break,
        }
    }
    Some(out)
}

/// Splits a sealed value into cookies: `[(base, value)]` when it fits one, otherwise
/// `[(base_0, …), (base_1, …)]`. `None` when it needs more than [`MAX_CHUNKS`].
pub(crate) fn split(base: &str, value: &str) -> Option<Vec<(String, String)>> {
    if value.len() <= CHUNK {
        return Some(vec![(base.to_owned(), value.to_owned())]);
    }
    let parts: Vec<&str> = value
        .as_bytes()
        .chunks(CHUNK)
        .filter_map(|c| std::str::from_utf8(c).ok())
        .collect();
    if parts.len() > MAX_CHUNKS || parts.iter().map(|p| p.len()).sum::<usize>() != value.len() {
        return None;
    }
    Some(
        parts
            .into_iter()
            .enumerate()
            .map(|(i, p)| (format!("{base}_{i}"), p.to_owned()))
            .collect(),
    )
}

/// The names a session cookie `base` may use.
pub(crate) fn session_names(base: &str) -> Vec<String> {
    let mut names = vec![base.to_owned()];
    names.extend((0..MAX_CHUNKS).map(|i| format!("{base}_{i}")));
    names
}

/// Random bytes as unpadded base64url.
pub(crate) fn random_token(random: &SystemRandom, bytes: usize) -> Option<String> {
    let mut buf = vec![0u8; bytes];
    random.fill(&mut buf).ok()?;
    Some(URL_SAFE_NO_PAD.encode(buf))
}

/// Fuzzing entry point: opens `input` as a cookie header and as a sealed value. It must only
/// ever return.
#[doc(hidden)]
pub fn fuzz_decode(input: &[u8]) {
    use std::sync::OnceLock;
    static SEALER: OnceLock<Option<Sealer>> = OnceLock::new();
    let Some(sealer) = SEALER
        .get_or_init(|| {
            Sealer::new(
                &[b"fuzzing-key-fuzzing-key-fuzzing-key!".to_vec()],
                Purpose::Session,
                "https://idp.test\0client",
            )
        })
        .as_ref()
    else {
        return;
    };
    let Ok(text) = std::str::from_utf8(input) else {
        return;
    };
    let _ = open_json::<Session>(sealer, text);
    let _ = open_json::<LoginState>(sealer, text);
    if let Ok(mut req) = RequestHeader::build("GET", b"/", None)
        && req.insert_header(http::header::COOKIE, text).is_ok()
        && let Some(value) = read_split(&pairs(&req), "__Host-rdock_oidc")
    {
        let _ = open_json::<Session>(sealer, &value);
    }
}
