//! `rdock migrate traefik`: Traefik labels or dynamic configuration to rdock.yaml (F-MGMT-03).
//! `rdock migrate config`: an rdock.yaml off deprecated settings (ADR-0033).

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::Context;

use crate::{MigrateConfigArgs, MigrateTraefikArgs};

fn read_input(input: &Path) -> anyhow::Result<String> {
    if input.as_os_str() == "-" {
        let mut text = String::new();
        std::io::stdin()
            .read_to_string(&mut text)
            .context("reading standard input")?;
        Ok(text)
    } else {
        std::fs::read_to_string(input).with_context(|| format!("reading {}", input.display()))
    }
}

/// `rdock migrate config`: exit 0 when the result was written (changed or not), 1 when the
/// input cannot be migrated (not YAML or JSON, an unknown `version`), 2 on an I/O error, as
/// `rdock migrate traefik`.
pub(crate) fn config(args: &MigrateConfigArgs) -> anyhow::Result<ExitCode> {
    let text = read_input(&args.input)?;
    let stdin = args.input.as_os_str() == "-";
    if stdin && args.write {
        anyhow::bail!("--write needs a file, not standard input");
    }
    let format = if stdin {
        rdock_config::Format::Yaml
    } else {
        rdock_config::Format::from_path(&args.input)
    };
    let migration = match rdock_migrate::config::config(&text, format) {
        Ok(migration) => migration,
        Err(err) => {
            eprintln!("error: {}: {err}", args.input.display());
            return Ok(ExitCode::from(1));
        }
    };
    let name = args.input.display().to_string();
    if args.diff {
        print!(
            "{}",
            rdock_migrate::config::diff(&text, &migration.text, &name)
        );
    } else if args.write {
        if migration.changed() {
            let backup = backup_path(&args.input);
            std::fs::copy(&args.input, &backup)
                .with_context(|| format!("copying {} to {}", name, backup.display()))?;
            std::fs::write(&args.input, &migration.text)
                .with_context(|| format!("writing {name}"))?;
            eprintln!("wrote {name}; the original is in {}", backup.display());
        }
    } else if let Some(path) = &args.output {
        std::fs::write(path, &migration.text)
            .with_context(|| format!("writing {}", path.display()))?;
    } else {
        print!("{}", migration.text);
    }
    for change in &migration.done {
        eprintln!(
            "rewrote {} → {} (deprecated since {}, removed in {})",
            change.path,
            change.to.as_deref().unwrap_or("?"),
            change.since,
            change.removal
        );
    }
    for change in &migration.manual {
        eprintln!("left {}: {}", change.path, change.detail);
    }
    if migration.done.is_empty() && migration.manual.is_empty() {
        eprintln!(
            "nothing to migrate: no deprecated settings (configuration schema v{})",
            migration.version
        );
    } else if migration.changed() && !migration.formatting_kept {
        eprintln!(
            "note: the file was written out again, so its comments and formatting are lost (a change could not be made as a text edit); review the result"
        );
    }
    if migration.changed() {
        eprintln!("check the result with `rdock validate`");
    }
    Ok(ExitCode::SUCCESS)
}

/// `<file>.bak`, or `<file>.bak.1`, `<file>.bak.2`, … when taken.
fn backup_path(file: &Path) -> PathBuf {
    let mut name = file.as_os_str().to_owned();
    name.push(".bak");
    let first = PathBuf::from(&name);
    if !first.exists() {
        return first;
    }
    (1..=u32::MAX)
        .map(|n| {
            let mut numbered = name.clone();
            numbered.push(format!(".{n}"));
            PathBuf::from(numbered)
        })
        .find(|p| !p.exists())
        .unwrap_or(first)
}

/// `rdock migrate traefik`: exit 0 when the result was written, 1 when the input is not a
/// Compose file or Traefik configuration, 2 on an error (I/O, a broken report) or, with
/// `--strict`, when a finding is manual or dropped.
pub(crate) fn traefik(args: &MigrateTraefikArgs) -> anyhow::Result<ExitCode> {
    let text = read_input(&args.input)?;
    let mut vars = rdock_migrate::compose::Vars::new();
    for file in &args.env_file {
        let content =
            std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
        let read = rdock_migrate::compose::env_file(&content, &vars)
            .map_err(|err| anyhow::anyhow!("{}: {err}", file.display()))?;
        vars.extend(read);
    }
    if args.process_env {
        // Asked for explicitly: the shell's variables win over the files, as in Compose.
        vars.extend(
            std::env::vars_os().filter_map(|(key, value)| {
                Some((key.into_string().ok()?, value.into_string().ok()?))
            }),
        );
    }
    let static_file = match &args.static_file {
        Some(path) => Some(rdock_migrate::StaticFile {
            name: path.display().to_string(),
            text: std::fs::read_to_string(path)
                .with_context(|| format!("reading {}", path.display()))?,
        }),
        None => None,
    };
    let options = rdock_migrate::Options {
        file: args.input.display().to_string(),
        expose_by_default: args.expose_by_default,
        vars,
        static_file,
        full: args.full,
    };
    let migration = match rdock_migrate::traefik(&text, &options) {
        Ok(migration) => migration,
        Err(rdock_migrate::Error::Input(err)) => {
            eprintln!("error: {}: {err}", args.input.display());
            return Ok(ExitCode::from(1));
        }
        Err(err @ rdock_migrate::Error::Accounting(_)) => return Err(err.into()),
    };
    match &args.output {
        Some(path) => std::fs::write(path, &migration.yaml)
            .with_context(|| format!("writing {}", path.display()))?,
        None => print!("{}", migration.yaml),
    }
    let json = serde_json::to_string_pretty(&migration.report)? + "\n";
    match args.report.as_deref() {
        Some(path) if path.as_os_str() == "-" => eprint!("{json}"),
        Some(path) => {
            std::fs::write(path, &json).with_context(|| format!("writing {}", path.display()))?;
            eprint!("{}", migration.report.text(false));
        }
        None => eprint!("{}", migration.report.text(false)),
    }
    if migration.report.needs_review() {
        eprintln!(
            "review the findings above (also at the top of the output); check the result with `rdock validate`"
        );
        if args.strict {
            return Ok(ExitCode::from(2));
        }
    } else {
        eprintln!("check the result with `rdock validate`");
    }
    Ok(ExitCode::SUCCESS)
}
