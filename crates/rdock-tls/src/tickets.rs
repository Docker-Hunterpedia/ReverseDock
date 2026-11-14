//! TLS session resumption shared between listeners and kept across reloads and binary upgrades
//! (H-PERF-02, ADR-0031).
//!
//! rustls's own `Ticketer::new()` makes fresh random keys for every server configuration, so a
//! ticket issued by one listener is refused by another, and every rebuilt acceptor (a TLS
//! reload) and every new process (an upgrade) forgets them. Here one [`Ticketer`] and one
//! session cache exist per **security class** for the life of the process, and the keys can be
//! exported to the next process and imported there.
//!
//! A security class is everything that decides what a resumed session may be trusted for.
//! rustls warns (`rustls` 0.23.46, `src/server/server_conn.rs` lines 269-292, read 2026-11-13)
//! that configurations sharing a ticketer or session store must have equivalent client
//! authentication (`verifier`) and server identities (`cert_resolver`); otherwise a session
//! started without a client certificate could be resumed on a listener that requires one, and
//! rustls enforces nothing. The class key ([`ClassKey`]) is therefore made of the TLS policy
//! (versions and cipher suites), the client-authentication mode and the identity of its trust
//! anchors, the listener for listeners that serve their own certificates, and the resumption
//! settings themselves. Two listeners share tickets only when all of these are equal. Keys from
//! an operator's key file are bound to the class too (HKDF with the class id as salt,
//! [`TicketKey::bound_to`]), so one key file used by two classes still keeps them apart.
//!
//! Tickets are ChaCha20-Poly1305 over the session state, as rustls's ring ticketer makes them
//! (`src/crypto/ring/ticketer.rs`): a 16-byte key name, a random 12-byte nonce, the ciphertext
//! and the tag, the key name as associated data. The key name is compared in constant time; a
//! ticket whose name is neither the current nor the previous key fails to decrypt and the
//! client gets a full handshake.

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use rustls::server::{ProducesTickets, ServerSessionMemoryCache, StoresServerSessions};
use subtle::ConstantTimeEq;

/// Length of a ticket key's name, carried in every ticket.
pub const NAME_LEN: usize = 16;
/// Length of a ticket key (ChaCha20-Poly1305).
pub const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// The longest ticket lifetime a TLS 1.3 server may announce: "Servers MUST NOT use any value
/// greater than 604800 seconds (7 days)" (RFC 8446 §4.6.1).
pub const MAX_LIFETIME: Duration = Duration::from_secs(604_800);
/// The rotation interval when `tls.tickets.rotate` is not set: rustls's own ring ticketer
/// rotates every 6 hours (`rustls` 0.23.46, `src/crypto/ring/ticketer.rs` line 30, read
/// 2026-11-13).
pub const DEFAULT_ROTATE: Duration = Duration::from_secs(6 * 60 * 60);
/// The longest rotation interval: a key encrypts tickets for one interval and decrypts them
/// for the next, so tickets never outlive two intervals, which must stay within
/// [`MAX_LIFETIME`].
pub const MAX_ROTATE: Duration = Duration::from_secs(302_400);
/// Keys read from a key file at most (the first is current, the others decrypt only).
pub const MAX_FILE_KEYS: usize = 8;
/// A key file older than this is reported: rotation is then the operator's job.
pub const KEY_FILE_MAX_AGE: Duration = Duration::from_secs(24 * 60 * 60);
/// Largest ticket accepted for decryption. rustls's tickets are a few hundred bytes; a client
/// certificate chain in the session can make them a few kilobytes.
const MAX_TICKET_LEN: usize = 16 * 1024;

/// Why ticket keys could not be made or read.
#[derive(Debug, thiserror::Error)]
pub enum TicketError {
    /// The system random source failed.
    #[error("the system random source failed")]
    Random,
    /// The key file could not be read.
    #[error("cannot read the ticket key file {path}: {source}")]
    Read {
        /// The file.
        path: PathBuf,
        /// What the operating system said.
        source: std::io::Error,
    },
    /// The key file may be read by other users.
    #[error(
        "the ticket key file {path} may be read or written by other users (mode {mode:o}); allow its owner only (chmod 600)"
    )]
    Mode {
        /// The file.
        path: PathBuf,
        /// Its permission bits.
        mode: u32,
    },
    /// The key file's content is not in the expected format.
    #[error("the ticket key file {path}: {message}")]
    Format {
        /// The file.
        path: PathBuf,
        /// What is wrong.
        message: String,
    },
}

/// One ticket key: a name and a ChaCha20-Poly1305 key. `Debug` never shows the key.
#[derive(Clone, PartialEq, Eq)]
pub struct TicketKey {
    name: [u8; NAME_LEN],
    key: [u8; KEY_LEN],
}

impl fmt::Debug for TicketKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TicketKey([redacted])")
    }
}

impl TicketKey {
    /// A new random key with a random name.
    ///
    /// # Errors
    ///
    /// The system random source failed.
    pub fn generate() -> Result<Self, TicketError> {
        let rng = SystemRandom::new();
        let mut name = [0; NAME_LEN];
        let mut key = [0; KEY_LEN];
        rng.fill(&mut name).map_err(|_| TicketError::Random)?;
        rng.fill(&mut key).map_err(|_| TicketError::Random)?;
        Ok(Self { name, key })
    }

    /// A key from 32 bytes of operator-provided material (a key file): the name is derived
    /// from the key, so every instance that reads the same file names it the same way.
    #[must_use]
    pub fn from_secret(key: [u8; KEY_LEN]) -> Self {
        let mut context = ring::digest::Context::new(&ring::digest::SHA256);
        context.update(b"rdock tls ticket key name v1\0");
        context.update(&key);
        let digest = context.finish();
        let mut name = [0; NAME_LEN];
        name.copy_from_slice(&digest.as_ref()[..NAME_LEN]);
        Self { name, key }
    }

    /// The name and the key, for handing to the next process in a binary upgrade. Treat the
    /// result as a secret: never log it or write it to disk.
    #[must_use]
    pub fn expose(&self) -> [u8; NAME_LEN + KEY_LEN] {
        let mut out = [0; NAME_LEN + KEY_LEN];
        out[..NAME_LEN].copy_from_slice(&self.name);
        out[NAME_LEN..].copy_from_slice(&self.key);
        out
    }

    /// The key [`Self::expose`] gave.
    #[must_use]
    pub fn from_exposed(bytes: &[u8; NAME_LEN + KEY_LEN]) -> Self {
        let mut name = [0; NAME_LEN];
        let mut key = [0; KEY_LEN];
        name.copy_from_slice(&bytes[..NAME_LEN]);
        key.copy_from_slice(&bytes[NAME_LEN..]);
        Self { name, key }
    }

    /// This key bound to one security class: HKDF-SHA256 with the class id as salt, so that
    /// two classes reading the same key file (a listener with client authentication and one
    /// without, say) never accept each other's tickets. Every instance with the same class
    /// derives the same key, so sharing across instances still works.
    #[must_use]
    pub fn bound_to(&self, class: &[u8; 32]) -> Self {
        let prk = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, class).extract(&self.key);
        let mut key = [0; KEY_LEN];
        // `fill` fails only for an output longer than 255 hash lengths; 32 bytes never is.
        let filled = prk
            .expand(&[b"rdock tls ticket key v1"], Len(KEY_LEN))
            .and_then(|okm| okm.fill(&mut key));
        if filled.is_err() {
            // Unreachable; a key no instance shares only makes resumption fail.
            return Self {
                name: self.name,
                key: [0; KEY_LEN],
            };
        }
        Self::from_secret(key)
    }

    fn aead(&self) -> Option<LessSafeKey> {
        UnboundKey::new(&CHACHA20_POLY1305, &self.key)
            .ok()
            .map(LessSafeKey::new)
    }
}

/// An HKDF output length.
struct Len(usize);

impl ring::hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

/// The keys of a ticketer: the current one encrypts and decrypts, the previous one only
/// decrypts. `rotated_at` is when `current` became current (Unix seconds).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySet {
    /// Encrypts new tickets.
    pub current: TicketKey,
    /// Still decrypts the tickets of the last interval.
    pub previous: Vec<TicketKey>,
    /// When `current` became current (Unix seconds).
    pub rotated_at: u64,
}

impl KeySet {
    fn fresh(now: u64) -> Result<Self, TicketError> {
        Ok(Self {
            current: TicketKey::generate()?,
            previous: Vec::new(),
            rotated_at: now,
        })
    }
}

/// Reads a key file: one or more keys, each 32 bytes in standard base64 on its own line (what
/// `openssl rand -base64 32` prints); the first is current, the others (at most
/// [`MAX_FILE_KEYS`] in all) decrypt only. Empty lines and lines starting with `#` are
/// ignored. On Unix the file must not be readable or writable by the group or others.
///
/// Returns the keys and the file's age, so the caller can warn when it is older than
/// [`KEY_FILE_MAX_AGE`].
///
/// # Errors
///
/// The file cannot be read, is open to other users, or is not in this format.
pub fn read_key_file(path: &Path) -> Result<(Vec<TicketKey>, Option<Duration>), TicketError> {
    use base64::Engine as _;
    let read = |source| TicketError::Read {
        path: path.to_owned(),
        source,
    };
    let format = |message: String| TicketError::Format {
        path: path.to_owned(),
        message,
    };
    let metadata = std::fs::metadata(path).map_err(read)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(TicketError::Mode {
                path: path.to_owned(),
                mode,
            });
        }
    }
    let age = metadata
        .modified()
        .ok()
        .and_then(|m| SystemTime::now().duration_since(m).ok());
    let text = std::fs::read_to_string(path).map_err(read)?;
    let mut keys = Vec::new();
    for (number, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(line)
            .map_err(|_| format(format!("line {} is not base64", number + 1)))?;
        let key: [u8; KEY_LEN] = bytes.try_into().map_err(|b: Vec<u8>| {
            format(format!(
                "line {} holds {} bytes; a key is {KEY_LEN} bytes (`openssl rand -base64 32`)",
                number + 1,
                b.len()
            ))
        })?;
        keys.push(TicketKey::from_secret(key));
    }
    if keys.is_empty() {
        return Err(format("it holds no key".to_owned()));
    }
    if keys.len() > MAX_FILE_KEYS {
        return Err(format(format!(
            "it holds {} keys; at most {MAX_FILE_KEYS} are read",
            keys.len()
        )));
    }
    Ok((keys, age))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The ticket keys of one security class, with rotation.
pub struct Ticketer {
    enabled: bool,
    rotate: Duration,
    /// Keys from a key file are never rotated here: that is the operator's job.
    from_file: bool,
    keys: RwLock<KeySet>,
    rng: SystemRandom,
}

impl fmt::Debug for Ticketer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ticketer")
            .field("enabled", &self.enabled)
            .field("rotate", &self.rotate)
            .field("from_file", &self.from_file)
            .finish_non_exhaustive()
    }
}

impl Ticketer {
    /// A ticketer with `keys`, rotating every `rotate` unless the keys came from a file.
    #[must_use]
    pub fn new(enabled: bool, rotate: Duration, keys: KeySet, from_file: bool) -> Self {
        Self {
            enabled,
            rotate: rotate.clamp(Duration::from_secs(1), MAX_ROTATE),
            from_file,
            keys: RwLock::new(keys),
            rng: SystemRandom::new(),
        }
    }

    /// Replaces the keys (a changed key file, or keys handed over by the previous process).
    pub fn set_keys(&self, keys: KeySet) {
        *self.keys.write().unwrap_or_else(PoisonError::into_inner) = keys;
    }

    /// The keys in use, for handing over in a binary upgrade.
    #[must_use]
    pub fn keys(&self) -> KeySet {
        self.keys
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Makes a new current key; the current one becomes the previous one and the one before is
    /// dropped, so its tickets no longer decrypt.
    ///
    /// # Errors
    ///
    /// The system random source failed; the keys are unchanged.
    pub fn rotate(&self) -> Result<(), TicketError> {
        let next = TicketKey::generate()?;
        let mut keys = self.keys.write().unwrap_or_else(PoisonError::into_inner);
        let old = std::mem::replace(&mut keys.current, next);
        keys.previous = vec![old];
        keys.rotated_at = unix_now();
        Ok(())
    }

    /// Rotates when the interval is over (keys from a file are left alone).
    fn rotate_if_due(&self) {
        if self.from_file {
            return;
        }
        let due = {
            let keys = self.keys.read().unwrap_or_else(PoisonError::into_inner);
            unix_now() >= keys.rotated_at.saturating_add(self.rotate.as_secs())
        };
        if due {
            // Another thread may have rotated meanwhile; check again under the write lock.
            let mut keys = self.keys.write().unwrap_or_else(PoisonError::into_inner);
            let now = unix_now();
            if now >= keys.rotated_at.saturating_add(self.rotate.as_secs())
                && let Ok(next) = TicketKey::generate()
            {
                let old = std::mem::replace(&mut keys.current, next);
                keys.previous = vec![old];
                keys.rotated_at = now;
            }
        }
    }
}

impl ProducesTickets for Ticketer {
    fn enabled(&self) -> bool {
        self.enabled
    }

    fn lifetime(&self) -> u32 {
        // A key encrypts for one interval and decrypts for the next.
        let lifetime = self.rotate.saturating_mul(2).min(MAX_LIFETIME);
        u32::try_from(lifetime.as_secs()).unwrap_or(u32::MAX)
    }

    fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>> {
        if !self.enabled {
            return None;
        }
        self.rotate_if_due();
        let keys = self.keys.read().unwrap_or_else(PoisonError::into_inner);
        let key = keys.current.aead()?;
        let mut nonce = [0u8; NONCE_LEN];
        self.rng.fill(&mut nonce).ok()?;
        let mut out = Vec::with_capacity(NAME_LEN + NONCE_LEN + plain.len() + TAG_LEN);
        out.extend_from_slice(&keys.current.name);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(plain);
        let tag = key
            .seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(keys.current.name),
                &mut out[NAME_LEN + NONCE_LEN..],
            )
            .ok()?;
        out.extend_from_slice(tag.as_ref());
        Some(out)
    }

    fn decrypt(&self, cipher: &[u8]) -> Option<Vec<u8>> {
        if !self.enabled || cipher.len() > MAX_TICKET_LEN {
            return None;
        }
        self.rotate_if_due();
        let (name, rest) = cipher.split_at_checked(NAME_LEN)?;
        let (nonce, sealed) = rest.split_at_checked(NONCE_LEN)?;
        if sealed.len() < TAG_LEN {
            return None;
        }
        let keys = self.keys.read().unwrap_or_else(PoisonError::into_inner);
        // Every candidate is compared, so the time taken does not tell which one matched.
        let mut found: Option<&TicketKey> = None;
        for candidate in std::iter::once(&keys.current).chain(keys.previous.iter()) {
            if bool::from(candidate.name.ct_eq(name)) {
                found = Some(candidate);
            }
        }
        let key = found?;
        let nonce: [u8; NONCE_LEN] = nonce.try_into().ok()?;
        let mut buffer = sealed.to_vec();
        let plain = key
            .aead()?
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(key.name),
                &mut buffer,
            )
            .ok()?
            .len();
        buffer.truncate(plain);
        Some(buffer)
    }
}

/// Resumption settings of a listener (`listeners.<l>.tls.tickets` and `.session_cache`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ResumptionSettings {
    /// Issue and accept session tickets.
    pub tickets: bool,
    /// How often the ticket key changes.
    pub rotate: Duration,
    /// Keys provided by the operator instead of generated ones.
    pub key_file: Option<PathBuf>,
    /// Sessions kept in memory for stateful resumption (0: none).
    pub cache_size: usize,
}

impl Default for ResumptionSettings {
    fn default() -> Self {
        Self {
            tickets: true,
            rotate: DEFAULT_ROTATE,
            key_file: None,
            cache_size: 256,
        }
    }
}

/// What makes resumption between two listeners safe; see the module documentation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClassKey {
    /// TLS versions and cipher suites (`modern`, `intermediate`).
    pub policy: String,
    /// Client authentication: `None` without it, else whether a certificate is required and
    /// the SHA-256 identity of the trust anchors ([`crate::ClientAuth::identity`]).
    pub client_auth: Option<(bool, [u8; 32])>,
    /// The listener, for a listener that serves certificates of its own (different server
    /// identities); `None` for listeners that serve the shared certificates.
    pub scope: Option<String>,
    /// The resumption settings.
    pub settings: ResumptionSettings,
}

impl ClassKey {
    /// A stable identifier of the class (SHA-256 of its parts), the same in every process and
    /// build that sees the same configuration, so keys can be handed over by class.
    #[must_use]
    pub fn id(&self) -> [u8; 32] {
        let mut context = ring::digest::Context::new(&ring::digest::SHA256);
        let mut part = |bytes: &[u8]| {
            context.update(&u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
            context.update(bytes);
        };
        part(b"rdock tls resumption class v1");
        part(self.policy.as_bytes());
        match &self.client_auth {
            None => part(b"no-client-auth"),
            Some((required, roots)) => {
                part(if *required { b"required" } else { b"optional" });
                part(roots);
            }
        }
        part(self.scope.as_deref().unwrap_or("").as_bytes());
        part(&[u8::from(self.scope.is_some())]);
        let s = &self.settings;
        part(&[u8::from(s.tickets)]);
        part(&s.rotate.as_secs().to_be_bytes());
        part(
            s.key_file
                .as_deref()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default()
                .as_bytes(),
        );
        part(
            &u64::try_from(s.cache_size)
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        let digest = context.finish();
        let mut id = [0; 32];
        id.copy_from_slice(digest.as_ref());
        id
    }
}

/// What a server configuration of one class shares with the others.
#[derive(Debug, Clone)]
pub struct Resumption {
    /// Stateless resumption (tickets).
    pub ticketer: Arc<Ticketer>,
    /// Stateful resumption (TLS 1.2 session IDs, and TLS 1.3 when tickets are off).
    pub cache: Arc<dyn StoresServerSessions>,
    /// TLS 1.3 tickets sent after a full handshake (0 when tickets are off).
    pub tls13_tickets: usize,
}

impl Resumption {
    /// Resumption for a configuration that shares nothing (the admin listener): fresh keys and
    /// rustls's defaults.
    ///
    /// # Errors
    ///
    /// The system random source failed.
    pub fn standalone() -> Result<Self, TicketError> {
        Ok(Self {
            ticketer: Arc::new(Ticketer::new(
                true,
                DEFAULT_ROTATE,
                KeySet::fresh(unix_now())?,
                false,
            )),
            cache: ServerSessionMemoryCache::new(256),
            tls13_tickets: 2,
        })
    }
}

/// The ticket keys of one class, as handed to the next process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassKeys {
    /// [`ClassKey::id`].
    pub class: [u8; 32],
    /// The keys.
    pub keys: KeySet,
}

struct Class {
    resumption: Resumption,
    /// The key file's keys last applied, to notice a change.
    file_keys: Option<Vec<TicketKey>>,
}

/// Every class's ticketer and session cache, for the life of the process.
#[derive(Default)]
pub struct TicketRegistry {
    classes: Mutex<HashMap<ClassKey, Class>>,
    /// Keys handed over by the previous process, by class id, until the class is made.
    imported: Mutex<HashMap<[u8; 32], KeySet>>,
}

impl fmt::Debug for TicketRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let classes = self
            .classes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len();
        f.debug_struct("TicketRegistry")
            .field("classes", &classes)
            .finish_non_exhaustive()
    }
}

impl TicketRegistry {
    /// The resumption state of `class`, made on first use. `file_keys` are the keys read from
    /// the class's key file (`None` without one); a change replaces the keys in place, so
    /// running acceptors pick them up.
    ///
    /// # Errors
    ///
    /// The system random source failed.
    pub fn resumption(
        &self,
        class: &ClassKey,
        file_keys: Option<Vec<TicketKey>>,
    ) -> Result<Resumption, TicketError> {
        let mut classes = self.classes.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(existing) = classes.get_mut(class) {
            if let Some(keys) = &file_keys
                && existing.file_keys.as_ref() != Some(keys)
            {
                existing
                    .resumption
                    .ticketer
                    .set_keys(key_set(keys, &class.id(), unix_now()));
                existing.file_keys = file_keys;
            }
            return Ok(existing.resumption.clone());
        }
        let now = unix_now();
        let imported = self
            .imported
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&class.id());
        let from_file = file_keys.is_some();
        let keys = match (&file_keys, imported) {
            (Some(keys), _) => key_set(keys, &class.id(), now),
            (None, Some(keys)) => keys,
            (None, None) => KeySet::fresh(now)?,
        };
        let settings = &class.settings;
        let resumption = Resumption {
            ticketer: Arc::new(Ticketer::new(
                settings.tickets,
                settings.rotate,
                keys,
                from_file,
            )),
            cache: if settings.cache_size == 0 {
                Arc::new(rustls::server::NoServerSessionStorage {})
            } else {
                ServerSessionMemoryCache::new(settings.cache_size)
            },
            tls13_tickets: if settings.tickets { 2 } else { 0 },
        };
        classes.insert(
            class.clone(),
            Class {
                resumption: resumption.clone(),
                file_keys,
            },
        );
        Ok(resumption)
    }

    /// The keys of every class that issues tickets, for the next process (binary upgrade).
    /// Keys from a key file are left out: the next process reads the file itself.
    #[must_use]
    pub fn export(&self) -> Vec<ClassKeys> {
        self.classes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|(key, class)| key.settings.tickets && class.file_keys.is_none())
            .map(|(key, class)| ClassKeys {
                class: key.id(),
                keys: class.resumption.ticketer.keys(),
            })
            .collect()
    }

    /// Keys from the previous process; each is used when its class is first made here (before
    /// the first configuration is applied).
    pub fn import(&self, keys: Vec<ClassKeys>) {
        let mut imported = self.imported.lock().unwrap_or_else(PoisonError::into_inner);
        for class in keys {
            imported.insert(class.class, class.keys);
        }
    }
}

/// The keys of a key file, bound to `class` ([`TicketKey::bound_to`]).
fn key_set(keys: &[TicketKey], class: &[u8; 32], now: u64) -> KeySet {
    let mut iter = keys.iter().map(|k| k.bound_to(class));
    // `read_key_file` never returns an empty list; a generated key would only make resumption
    // across instances fail, never succeed wrongly.
    let current = iter
        .next()
        .or_else(|| TicketKey::generate().ok())
        .unwrap_or_else(|| TicketKey::from_secret([0; KEY_LEN]));
    KeySet {
        current,
        previous: iter.collect(),
        rotated_at: now,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ticketer(rotate: u64) -> Ticketer {
        Ticketer::new(
            true,
            Duration::from_secs(rotate),
            KeySet::fresh(unix_now()).unwrap(),
            false,
        )
    }

    #[test]
    fn a_ticket_round_trips_and_a_tampered_one_does_not() {
        let t = ticketer(3600);
        let ticket = t.encrypt(b"session state").unwrap();
        assert_eq!(t.decrypt(&ticket).unwrap(), b"session state");
        for i in [0, NAME_LEN, NAME_LEN + NONCE_LEN, ticket.len() - 1] {
            let mut bad = ticket.clone();
            bad[i] ^= 1;
            assert!(t.decrypt(&bad).is_none(), "byte {i} changed");
        }
        assert!(t.decrypt(&ticket[..NAME_LEN + NONCE_LEN + 3]).is_none());
        assert!(t.decrypt(&[]).is_none());
    }

    #[test]
    fn rotation_keeps_the_previous_key_and_drops_the_one_before() {
        let t = ticketer(3600);
        let first = t.encrypt(b"a").unwrap();
        t.rotate().unwrap();
        let second = t.encrypt(b"b").unwrap();
        assert_eq!(t.decrypt(&first).unwrap(), b"a", "previous key still valid");
        t.rotate().unwrap();
        assert!(t.decrypt(&first).is_none(), "the key before is gone");
        assert_eq!(t.decrypt(&second).unwrap(), b"b");
    }

    #[test]
    fn rotation_happens_when_the_interval_is_over() {
        let t = ticketer(1);
        let mut keys = t.keys();
        keys.rotated_at -= 2;
        t.set_keys(keys.clone());
        let _ = t.encrypt(b"x").unwrap();
        let now = t.keys();
        assert_ne!(now.current, keys.current);
        assert_eq!(now.previous, vec![keys.current]);
    }

    #[test]
    fn lifetime_is_two_intervals_capped_at_seven_days() {
        assert_eq!(ticketer(6 * 3600).lifetime(), 12 * 3600);
        let long = Ticketer::new(
            true,
            Duration::from_secs(10 * 86_400),
            KeySet::fresh(0).unwrap(),
            false,
        );
        assert_eq!(long.lifetime(), 604_800);
    }

    #[test]
    fn a_disabled_ticketer_issues_nothing() {
        let t = Ticketer::new(false, DEFAULT_ROTATE, KeySet::fresh(0).unwrap(), false);
        assert!(!t.enabled());
        assert!(t.encrypt(b"x").is_none());
    }

    #[test]
    fn keys_move_between_ticketers() {
        let a = ticketer(3600);
        let ticket = a.encrypt(b"carried").unwrap();
        let exposed: Vec<[u8; 48]> = std::iter::once(&a.keys().current)
            .map(TicketKey::expose)
            .collect();
        let b = Ticketer::new(
            true,
            Duration::from_secs(3600),
            KeySet {
                current: TicketKey::from_exposed(&exposed[0]),
                previous: Vec::new(),
                rotated_at: unix_now(),
            },
            false,
        );
        assert_eq!(b.decrypt(&ticket).unwrap(), b"carried");
        assert!(
            ticketer(3600).decrypt(&ticket).is_none(),
            "an unknown key fails"
        );
        assert_eq!(format!("{:?}", a.keys().current), "TicketKey([redacted])");
    }

    fn class(client_auth: Option<(bool, [u8; 32])>) -> ClassKey {
        ClassKey {
            policy: "intermediate".into(),
            client_auth,
            scope: None,
            settings: ResumptionSettings::default(),
        }
    }

    #[test]
    fn classes_share_by_key_and_survive_lookups() {
        let registry = TicketRegistry::default();
        let plain = registry.resumption(&class(None), None).unwrap();
        let again = registry.resumption(&class(None), None).unwrap();
        assert!(Arc::ptr_eq(&plain.ticketer, &again.ticketer));
        let mtls = registry
            .resumption(&class(Some((true, [7; 32]))), None)
            .unwrap();
        assert!(!Arc::ptr_eq(&plain.ticketer, &mtls.ticketer));
        let ticket = plain.ticketer.encrypt(b"no client cert").unwrap();
        assert!(
            mtls.ticketer.decrypt(&ticket).is_none(),
            "a session without client authentication never resumes where it is required"
        );
        assert_ne!(class(None).id(), class(Some((false, [7; 32]))).id());
        assert_ne!(
            class(Some((false, [7; 32]))).id(),
            class(Some((true, [7; 32]))).id()
        );
    }

    #[test]
    fn exported_keys_are_used_by_the_next_process() {
        let old = TicketRegistry::default();
        let r = old.resumption(&class(None), None).unwrap();
        let ticket = r.ticketer.encrypt(b"s").unwrap();
        let new = TicketRegistry::default();
        new.import(old.export());
        let r2 = new.resumption(&class(None), None).unwrap();
        assert_eq!(r2.ticketer.decrypt(&ticket).unwrap(), b"s");
    }

    #[test]
    fn key_files_are_read_and_checked() {
        use base64::Engine as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys");
        let b64 = |b: u8| base64::engine::general_purpose::STANDARD.encode([b; 32]);
        std::fs::write(&path, format!("# keys\n{}\n\n{}\n", b64(1), b64(2))).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(matches!(
                read_key_file(&path),
                Err(TicketError::Mode { mode: 0o644, .. })
            ));
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let (keys, age) = read_key_file(&path).unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0], TicketKey::from_secret([1; 32]));
        assert!(age.is_some_and(|a| a < KEY_FILE_MAX_AGE));
        std::fs::write(&path, "AAAA\n").unwrap();
        assert!(
            read_key_file(&path)
                .unwrap_err()
                .to_string()
                .contains("holds 3 bytes")
        );
        std::fs::write(&path, "# none\n").unwrap();
        assert!(read_key_file(&path).is_err());
    }

    #[test]
    fn a_changed_key_file_replaces_the_keys_in_place() {
        let registry = TicketRegistry::default();
        let settings = ResumptionSettings {
            key_file: Some("/k".into()),
            ..ResumptionSettings::default()
        };
        let key = ClassKey {
            settings,
            ..class(None)
        };
        let first = registry
            .resumption(&key, Some(vec![TicketKey::from_secret([1; 32])]))
            .unwrap();
        let ticket = first.ticketer.encrypt(b"x").unwrap();
        let second = registry
            .resumption(&key, Some(vec![TicketKey::from_secret([2; 32])]))
            .unwrap();
        assert!(Arc::ptr_eq(&first.ticketer, &second.ticketer));
        assert!(second.ticketer.decrypt(&ticket).is_none());
        assert!(
            registry.export().is_empty(),
            "file keys are not handed over"
        );
    }

    #[test]
    fn one_key_file_never_joins_two_classes() {
        let registry = TicketRegistry::default();
        let file = Some(vec![TicketKey::from_secret([3; 32])]);
        let with_file = |client_auth| ClassKey {
            settings: ResumptionSettings {
                key_file: Some("/k".into()),
                ..ResumptionSettings::default()
            },
            ..class(client_auth)
        };
        let open = registry.resumption(&with_file(None), file.clone()).unwrap();
        let mtls = registry
            .resumption(&with_file(Some((true, [7; 32]))), file.clone())
            .unwrap();
        let ticket = open.ticketer.encrypt(b"no client cert").unwrap();
        assert!(mtls.ticketer.decrypt(&ticket).is_none());
        // Another instance with the same class derives the same keys.
        let other = TicketRegistry::default();
        let same = other.resumption(&with_file(None), file).unwrap();
        assert_eq!(same.ticketer.decrypt(&ticket).unwrap(), b"no client cert");
    }
}
