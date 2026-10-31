//! Password rules and Argon2id hashing for dashboard users (ADR-0024). Hashing is CPU and
//! memory heavy (19 MiB per hash by default), so callers run it on a blocking thread behind
//! the admin's hashing limiter, never on a runtime worker.

use std::collections::HashSet;
use std::path::Path;
use std::sync::LazyLock;

use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use argon2::{Algorithm, Argon2, Params, Version};
use rdock_model::settings::{AdminPasswords, Argon2Cost};

/// Longest password accepted, in characters. Longer input only costs hashing time.
pub const MAX_LENGTH: usize = 128;

static COMMON: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    include_str!("../data/common-passwords.txt")
        .lines()
        .collect()
});

/// Why a new password is refused. The messages are shown to the user who chose it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Weak {
    /// Fewer characters than `admin.passwords.min_length`.
    #[error("use at least {0} characters")]
    TooShort(usize),
    /// More than [`MAX_LENGTH`] characters.
    #[error("use at most {MAX_LENGTH} characters")]
    TooLong,
    /// On the bundled list of common passwords or the configured blocklist.
    #[error("this password is too common; choose another")]
    Common,
}

/// The password rules and the Argon2id cost in force.
#[derive(Debug, Clone)]
pub struct Policy {
    min_length: usize,
    params: Params,
    blocklist: HashSet<String>,
}

impl Policy {
    /// Builds the policy, reading `blocklist_file` once. The values were validated with the
    /// configuration, so only an unreadable file fails here.
    pub fn new(settings: &AdminPasswords) -> std::io::Result<Self> {
        let blocklist = match &settings.blocklist_file {
            Some(path) => read_blocklist(path)?,
            None => HashSet::new(),
        };
        Ok(Self {
            min_length: usize::from(settings.min_length),
            params: params(settings.argon2)?,
            blocklist,
        })
    }

    /// Whether `password` may be chosen.
    pub fn check(&self, password: &str) -> Result<(), Weak> {
        let length = password.chars().count();
        if length < self.min_length {
            return Err(Weak::TooShort(self.min_length));
        }
        if length > MAX_LENGTH {
            return Err(Weak::TooLong);
        }
        let folded = password.to_lowercase();
        if COMMON.contains(folded.as_str()) || self.blocklist.contains(&folded) {
            return Err(Weak::Common);
        }
        Ok(())
    }

    /// A new PHC string (`$argon2id$v=19$m=…`) with a random 16-byte salt.
    pub fn hash(&self, password: &str) -> Result<String, argon2::password_hash::Error> {
        let mut salt = [0u8; 16];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut salt)
            .map_err(|_| argon2::password_hash::Error::Crypto)?;
        let hash = self
            .argon2()
            .hash_password_with_salt(password.as_bytes(), &salt)?;
        Ok(hash.to_string())
    }

    /// Checks `password` against a stored PHC string. Anything but a well-formed Argon2id
    /// hash never matches.
    pub fn verify(&self, password: &str, stored: &str) -> Verified {
        let Ok(hash) = PasswordHash::new(stored) else {
            return Verified::No;
        };
        if hash.algorithm.as_str() != "argon2id" {
            return Verified::No;
        }
        // Argon2 reads the cost from the hash itself, so older hashes still verify.
        if self
            .argon2()
            .verify_password(password.as_bytes(), &hash)
            .is_err()
        {
            return Verified::No;
        }
        match Params::try_from(&hash) {
            Ok(old) if self.covers(&old) => Verified::Yes,
            _ => Verified::Rehash,
        }
    }

    /// Spends the same work as [`verify`](Self::verify) for a user who does not exist, so the
    /// answer time does not tell which user names are taken.
    pub fn verify_nobody(&self, password: &str) {
        let _ = self.verify(password, &DUMMY);
    }

    fn covers(&self, old: &Params) -> bool {
        old.m_cost() >= self.params.m_cost()
            && old.t_cost() >= self.params.t_cost()
            && old.p_cost() >= self.params.p_cost()
    }

    fn argon2(&self) -> Argon2<'static> {
        Argon2::new(Algorithm::Argon2id, Version::V0x13, self.params.clone())
    }
}

/// The result of a successful or failed password check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verified {
    /// The password is wrong, or the stored hash is not Argon2id.
    No,
    /// The password is right.
    Yes,
    /// The password is right, but the hash is weaker than the current cost: store a new one.
    Rehash,
}

/// A fixed hash at the default cost, for [`Policy::verify_nobody`]. Its password is unknown
/// and irrelevant; only the work matters.
static DUMMY: LazyLock<String> = LazyLock::new(|| {
    let salt = *b"rdock-dummy-salt";
    Argon2::default()
        .hash_password_with_salt(b"no user has this password", &salt)
        .map(|hash| hash.to_string())
        .unwrap_or_default()
});

fn params(cost: Argon2Cost) -> std::io::Result<Params> {
    Params::new(cost.memory_kib, cost.iterations, cost.parallelism, None)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err.to_string()))
}

fn read_blocklist(path: &Path) -> std::io::Result<HashSet<String>> {
    let text = std::fs::read_to_string(path)?;
    Ok(text
        .lines()
        .map(|line| line.trim_end_matches('\r').to_lowercase())
        .filter(|line| !line.is_empty())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        Policy::new(&AdminPasswords::default()).unwrap()
    }

    #[test]
    fn length_and_common_passwords_are_checked() {
        let policy = policy();
        assert_eq!(policy.check("short"), Err(Weak::TooShort(12)));
        assert_eq!(policy.check(&"x".repeat(129)), Err(Weak::TooLong));
        assert_eq!(policy.check("Password1234"), Err(Weak::Common));
        assert_eq!(policy.check("QWERTYUIOPASDFGHJKL"), Err(Weak::Common));
        assert_eq!(policy.check("correct horse battery staple"), Ok(()));
        // Characters, not bytes: twelve two-byte letters are long enough.
        assert_eq!(policy.check("éééééééééééé"), Ok(()));
    }

    #[test]
    fn the_blocklist_file_is_case_insensitive() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("breached.txt");
        std::fs::write(&file, "Our-Company-2026\r\n\n").unwrap();
        let policy = Policy::new(&AdminPasswords {
            blocklist_file: Some(file),
            ..AdminPasswords::default()
        })
        .unwrap();
        assert_eq!(policy.check("our-company-2026"), Err(Weak::Common));
    }

    #[test]
    fn hashes_verify_and_weaker_ones_ask_for_a_rehash() {
        let policy = policy();
        let hash = policy.hash("correct horse battery staple").unwrap();
        assert!(
            hash.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"),
            "{hash}"
        );
        assert_eq!(
            policy.verify("correct horse battery staple", &hash),
            Verified::Yes
        );
        assert_eq!(
            policy.verify("wrong horse battery staple", &hash),
            Verified::No
        );
        assert_eq!(policy.verify("anything", "plain text"), Verified::No);

        let stronger = Policy::new(&AdminPasswords {
            argon2: Argon2Cost {
                iterations: 3,
                ..Argon2Cost::default()
            },
            ..AdminPasswords::default()
        })
        .unwrap();
        assert_eq!(
            stronger.verify("correct horse battery staple", &hash),
            Verified::Rehash
        );
    }

    #[test]
    fn bcrypt_and_argon2i_hashes_never_match() {
        let policy = policy();
        let argon2i = Argon2::new(Algorithm::Argon2i, Version::V0x13, Params::default())
            .hash_password_with_salt(b"correct horse", b"somesalt12345678")
            .unwrap()
            .to_string();
        assert_eq!(policy.verify("correct horse", &argon2i), Verified::No);
        assert!(!DUMMY.is_empty());
    }
}
