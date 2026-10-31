//! Dashboard users, kept in `$RDOCK_DATA_DIR/admin/users.json` (mode 0600, written
//! atomically). Passwords are stored only as Argon2id PHC strings (ADR-0024).

use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// What a user may do (ADR-0024, "What each role may do").
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Reads everything except secrets, users and the audit log.
    Viewer,
    /// Also drains backends, reloads and edits API-owned configuration.
    Operator,
    /// Also manages users, tokens, sessions and admin settings.
    Admin,
}

/// One user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct User {
    /// Lower-case name, unique.
    pub name: String,
    /// What the user may do.
    pub role: Role,
    /// Argon2id PHC string.
    pub password: String,
    /// Creation time, seconds since the Unix epoch.
    pub created_at: u64,
    /// A disabled user cannot log in.
    #[serde(default)]
    pub disabled: bool,
    /// The user's second factor, once enrolled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mfa: Option<Mfa>,
}

/// A user's TOTP secret and recovery codes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mfa {
    /// Base32 TOTP secret. The users file is readable by its owner only.
    pub secret: String,
    /// The last time step a code was accepted for, so each code works once.
    pub last_step: u64,
    /// SHA-256 hashes of the unused recovery codes.
    pub recovery: Vec<String>,
}

impl User {
    /// A new, enabled user created now.
    #[must_use]
    pub fn new(name: String, role: Role, password: String) -> Self {
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        Self {
            name,
            role,
            password,
            created_at,
            disabled: false,
            mfa: None,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UsersFile {
    version: u32,
    users: Vec<User>,
}

/// Why a user could not be added.
#[derive(Debug, thiserror::Error)]
pub enum AddError {
    /// A user with this name exists.
    #[error("a user with this name exists")]
    Exists,
    /// The first admin was already created.
    #[error("an admin user exists already")]
    AdminExists,
    /// The users file could not be written.
    #[error("cannot save the users file: {0}")]
    Io(#[from] io::Error),
}

/// The user list and its file.
#[derive(Debug)]
pub struct Users {
    path: PathBuf,
    list: Mutex<Vec<User>>,
}

impl Users {
    /// Reads `<dir>/users.json`; a missing file means no users.
    pub fn open(dir: &Path) -> io::Result<Self> {
        let path = dir.join("users.json");
        let list = match std::fs::read(&path) {
            Ok(bytes) => {
                let file: UsersFile = serde_json::from_slice(&bytes)
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
                if file.version != 1 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("unsupported users file version {}", file.version),
                    ));
                }
                file.users
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(err) => return Err(err),
        };
        Ok(Self {
            path,
            list: Mutex::new(list),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<User>> {
        self.list.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether an enabled admin exists; until one does, the bootstrap token is active.
    pub fn has_admin(&self) -> bool {
        has_admin(&self.lock())
    }

    /// The user called `name` (any case).
    pub fn find(&self, name: &str) -> Option<User> {
        let name = name.to_ascii_lowercase();
        self.lock().iter().find(|u| u.name == name).cloned()
    }

    /// Adds the first admin; refused once an enabled admin exists, so two bootstrap requests
    /// racing each other create one admin.
    pub fn add_first_admin(&self, user: User) -> Result<(), AddError> {
        let mut list = self.lock();
        if has_admin(&list) {
            return Err(AddError::AdminExists);
        }
        self.insert(&mut list, user)
    }

    fn insert(&self, list: &mut Vec<User>, user: User) -> Result<(), AddError> {
        if list.iter().any(|u| u.name == user.name) {
            return Err(AddError::Exists);
        }
        list.push(user);
        if let Err(err) = self.save(list) {
            list.pop();
            return Err(err.into());
        }
        Ok(())
    }

    /// Changes the user called `name` with `change` and saves the file; on a failed save the
    /// user is left as it was. Returns what `change` returned.
    pub fn update<T>(&self, name: &str, change: impl FnOnce(&mut User) -> T) -> io::Result<T> {
        let mut list = self.lock();
        let Some(index) = list.iter().position(|u| u.name == name) else {
            return Err(io::Error::new(io::ErrorKind::NotFound, "no such user"));
        };
        let before = list[index].clone();
        let result = change(&mut list[index]);
        if let Err(err) = self.save(&list) {
            list[index] = before;
            return Err(err);
        }
        Ok(result)
    }

    fn save(&self, list: &[User]) -> io::Result<()> {
        let file = UsersFile {
            version: 1,
            users: list.to_vec(),
        };
        let mut bytes = serde_json::to_vec_pretty(&file).map_err(io::Error::other)?;
        bytes.push(b'\n');
        rdock_config::state::write_atomic(&self.path, &bytes)
    }
}

fn has_admin(list: &[User]) -> bool {
    list.iter().any(|u| u.role == Role::Admin && !u.disabled)
}

/// A user name: 1–64 characters of `a-z`, `0-9`, `.`, `_` and `-`, starting with a letter or
/// digit. Returns it lower-cased.
pub fn normalize_name(name: &str) -> Option<String> {
    let name = name.to_ascii_lowercase();
    let mut chars = name.chars();
    let first_ok = chars.next().is_some_and(|c| c.is_ascii_alphanumeric());
    let rest_ok = chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    (first_ok && rest_ok && name.len() <= 64).then_some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_lower_cased_and_restricted() {
        assert_eq!(normalize_name("Oday.B-1"), Some("oday.b-1".into()));
        for bad in ["", "-x", "a b", "ä", &"a".repeat(65)] {
            assert_eq!(normalize_name(bad), None, "{bad}");
        }
    }

    #[test]
    fn the_file_is_private_and_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let users = Users::open(dir.path()).unwrap();
        assert!(!users.has_admin());
        users
            .add_first_admin(User::new("root".into(), Role::Admin, "$argon2id$x".into()))
            .unwrap();
        assert!(matches!(
            users.add_first_admin(User::new("two".into(), Role::Admin, "h".into())),
            Err(AddError::AdminExists)
        ));
        users
            .update("root", |u| u.password = "$argon2id$y".into())
            .unwrap();
        assert!(users.update("nobody", |_| ()).is_err());

        let path = dir.path().join("users.json");
        let mode = std::os::unix::fs::PermissionsExt::mode(
            &std::fs::metadata(&path).unwrap().permissions(),
        );
        assert_eq!(mode & 0o777, 0o600);
        let again = Users::open(dir.path()).unwrap();
        assert!(again.has_admin());
        assert_eq!(again.find("ROOT").unwrap().password, "$argon2id$y");
    }
}
