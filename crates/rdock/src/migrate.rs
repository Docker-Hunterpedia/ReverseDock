//! `rdock migrate traefik`: Traefik labels or dynamic configuration to rdock.yaml (F-MGMT-03).

use std::io::Read;
use std::process::ExitCode;

use anyhow::Context;

use crate::MigrateTraefikArgs;

pub(crate) fn traefik(args: &MigrateTraefikArgs) -> anyhow::Result<ExitCode> {
    let text = if args.input.as_os_str() == "-" {
        let mut text = String::new();
        std::io::stdin()
            .read_to_string(&mut text)
            .context("reading standard input")?;
        text
    } else {
        std::fs::read_to_string(&args.input)
            .with_context(|| format!("reading {}", args.input.display()))?
    };
    let migration = match rdock_migrate::traefik(&text, args.expose_by_default) {
        Ok(migration) => migration,
        Err(err) => {
            eprintln!("error: {}: {err}", args.input.display());
            return Ok(ExitCode::from(1));
        }
    };
    match &args.output {
        Some(path) => std::fs::write(path, &migration.yaml)
            .with_context(|| format!("writing {}", path.display()))?,
        None => print!("{}", migration.yaml),
    }
    if migration.notes.is_empty() {
        eprintln!("migrated everything; check the result with `rdock validate`");
    } else {
        eprintln!(
            "{} note(s) about what was not migrated are at the top of the output; check the result with `rdock validate`",
            migration.notes.len()
        );
    }
    Ok(ExitCode::SUCCESS)
}
