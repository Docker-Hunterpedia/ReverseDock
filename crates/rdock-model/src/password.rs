//! Ceilings on the work a password hash asks of the proxy (`basic_auth`).
//!
//! An argon2id or bcrypt hash carries its own cost, and verifying it does that work on every
//! request with a wrong password. Unbounded, one hash string (`m=4194304` is 4 GiB per
//! verification, bcrypt cost 31 is about a day of CPU) lets anyone who can send a password
//! exhaust the proxy's memory or threads. The ceilings are several times OWASP's
//! recommended minimums (Password Storage Cheat Sheet,
//! <https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html>, read
//! 2026-11-13: argon2id at least m=19456 KiB, t=2, p=1, or m=47104 KiB, t=1; bcrypt a work
//! factor of at least 10), and the same as the bounds of `admin.passwords.argon2`.

/// Highest argon2id memory per verification, in KiB (256 MiB, over five times OWASP's largest
/// recommended minimum of 46 MiB).
pub const ARGON2_MAX_MEMORY_KIB: u32 = 262_144;
/// Highest argon2id iteration count (five times OWASP's t=2).
pub const ARGON2_MAX_ITERATIONS: u32 = 10;
/// Highest argon2id degree of parallelism.
pub const ARGON2_MAX_PARALLELISM: u32 = 8;
/// Highest bcrypt cost (16 times the work of OWASP's minimum of 10).
pub const BCRYPT_MAX_COST: u32 = 14;

/// Why `hash` asks for more work than the ceilings allow, or `None`. Formats other than
/// argon2id and bcrypt have a fixed cost and always pass.
#[must_use]
pub fn cost_problem(hash: &str) -> Option<String> {
    if let Some(rest) = hash.strip_prefix("$argon2id$") {
        let Some(params) = rest.split('$').find(|part| part.contains("m=")) else {
            return Some("the argon2id hash has no `m=…,t=…,p=…` parameters".to_owned());
        };
        let mut found = (None, None, None);
        for pair in params.split(',') {
            let Some((key, value)) = pair.split_once('=') else {
                return Some("the argon2id hash's parameters cannot be read".to_owned());
            };
            let value = value.parse::<u64>().ok();
            match key {
                "m" => found.0 = value,
                "t" => found.1 = value,
                "p" => found.2 = value,
                _ => {}
            }
        }
        let (Some(m), Some(t), Some(p)) = found else {
            return Some("the argon2id hash's parameters cannot be read".to_owned());
        };
        if m > u64::from(ARGON2_MAX_MEMORY_KIB) {
            return Some(format!(
                "the argon2id hash asks for m={m} KiB of memory per check; the limit is {ARGON2_MAX_MEMORY_KIB}"
            ));
        }
        if t > u64::from(ARGON2_MAX_ITERATIONS) {
            return Some(format!(
                "the argon2id hash asks for t={t} iterations; the limit is {ARGON2_MAX_ITERATIONS}"
            ));
        }
        if p > u64::from(ARGON2_MAX_PARALLELISM) {
            return Some(format!(
                "the argon2id hash asks for p={p} lanes; the limit is {ARGON2_MAX_PARALLELISM}"
            ));
        }
        return None;
    }
    if ["$2a$", "$2b$", "$2x$", "$2y$"]
        .iter()
        .any(|p| hash.starts_with(p))
    {
        let cost = hash.get(4..6).and_then(|c| c.parse::<u32>().ok());
        return match cost {
            Some(cost) if cost > BCRYPT_MAX_COST => Some(format!(
                "the bcrypt hash has cost {cost}; the limit is {BCRYPT_MAX_COST}"
            )),
            Some(_) => None,
            None => Some("the bcrypt hash's cost cannot be read".to_owned()),
        };
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn costs_above_the_ceilings_are_refused() {
        let salt = "c29tZXNhbHQxMjM0NTY3OA$AAAA";
        for ok in [
            format!("$argon2id$v=19$m=19456,t=2,p=1${salt}"),
            format!("$argon2id$v=19$m=262144,t=10,p=8${salt}"),
            "$2b$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234".to_owned(),
            "$2y$14$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234".to_owned(),
            "$apr1$saltsalt$yAAkm4libquA.ZWLHbSBq/".to_owned(),
            "{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=".to_owned(),
        ] {
            assert_eq!(cost_problem(&ok), None, "{ok}");
        }
        for (bad, says) in [
            (
                format!("$argon2id$v=19$m=4194304,t=1,p=1${salt}"),
                "m=4194304",
            ),
            (format!("$argon2id$v=19$m=19456,t=100,p=1${salt}"), "t=100"),
            (format!("$argon2id$v=19$m=19456,t=2,p=64${salt}"), "p=64"),
            (format!("$argon2id$v=19$t=2,p=1${salt}"), "parameters"),
            (
                "$2b$20$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234".to_owned(),
                "cost 20",
            ),
            (
                "$2b$31$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234".to_owned(),
                "limit is 14",
            ),
        ] {
            let problem = cost_problem(&bad).unwrap_or_default();
            assert!(problem.contains(says), "{bad}: {problem}");
        }
    }
}
