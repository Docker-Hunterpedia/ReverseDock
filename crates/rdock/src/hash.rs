//! `rdock hash`: create an argon2id password hash for `basic_auth`.

use std::io::{BufRead, IsTerminal};
use std::process::ExitCode;

use anyhow::{Context, bail};
use argon2::{Argon2, PasswordHasher};

use crate::HashArgs;

/// Reads the password from the first line of standard input, never from the command line, so
/// it does not end up in shell history or the process list.
pub(crate) fn hash(args: &HashArgs) -> anyhow::Result<ExitCode> {
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        eprint!("Password (shown as you type; pipe it in to hide it): ");
    }
    let mut line = String::new();
    stdin
        .lock()
        .read_line(&mut line)
        .context("reading the password from stdin")?;
    let password = line.strip_suffix('\n').unwrap_or(&line);
    let password = password.strip_suffix('\r').unwrap_or(password);
    if password.is_empty() {
        bail!("the password is empty");
    }
    // Argon2::default() is argon2id v19, m=19 MiB, t=2, p=1: the OWASP minimum.
    let hash = Argon2::default()
        .hash_password(password.as_bytes())
        .map_err(|err| anyhow::anyhow!("hashing the password: {err}"))?
        .to_string();
    let entry = match &args.user {
        Some(user) => format!("{user}:{hash}\n"),
        None => format!("{hash}\n"),
    };
    crate::print(&entry)?;
    Ok(ExitCode::SUCCESS)
}
