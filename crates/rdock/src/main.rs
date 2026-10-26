//! The `rdock` command-line interface.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::Context;
use clap::{Args, Parser, Subcommand, ValueEnum};
use rdock_config::{LoadError, LoadOptions, Loaded, load_file};
use rdock_model::Diagnostic;
use serde::Serialize;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const COMMIT: &str = env!("RDOCK_BUILD_COMMIT");
const RUSTC: &str = env!("RDOCK_BUILD_RUSTC");
const TARGET: &str = env!("RDOCK_BUILD_TARGET");

/// ReverseDock: one reverse proxy for every dock.
#[derive(Parser)]
#[command(name = "rdock", version, about, propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Validate configuration files without starting the proxy.
    Validate(ValidateArgs),
    /// Print the JSON Schema of rdock.yaml.
    Schema,
    /// Print version and build information.
    Version {
        /// Print as JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Args)]
struct ValidateArgs {
    /// Configuration files (YAML, or JSON with a .json extension).
    #[arg(required = true)]
    files: Vec<PathBuf>,
    /// Treat unknown keys as errors.
    #[arg(long)]
    strict: bool,
    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

#[derive(Clone, Copy, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Validate(args) => validate(&args),
        Command::Schema => schema().map(|()| ExitCode::SUCCESS),
        Command::Version { json } => version(json).map(|()| ExitCode::SUCCESS),
    };
    result.unwrap_or_else(|err| {
        eprintln!("error: {err:#}");
        ExitCode::from(2)
    })
}

fn print(text: &str) -> anyhow::Result<()> {
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(text.as_bytes())
        .context("writing to stdout")?;
    stdout.flush().context("writing to stdout")
}

fn schema() -> anyhow::Result<()> {
    print(&rdock_model::json_schema_string().context("serialising the JSON Schema")?)
}

fn version(json: bool) -> anyhow::Result<()> {
    if json {
        let info = serde_json::json!({ "version": VERSION, "commit": COMMIT, "rustc": RUSTC, "target": TARGET });
        print(&format!("{info}\n"))
    } else {
        print(&format!(
            "rdock {VERSION}\ncommit  {COMMIT}\nrustc   {RUSTC}\ntarget  {TARGET}\n"
        ))
    }
}

/// Result of validating one file, as printed by `--format json`.
#[derive(Serialize)]
struct FileReport {
    file: String,
    valid: bool,
    errors: usize,
    warnings: usize,
    diagnostics: Vec<Diagnostic>,
}

fn validate(args: &ValidateArgs) -> anyhow::Result<ExitCode> {
    let options = LoadOptions {
        strict: args.strict,
    };
    let reports: Vec<FileReport> = args
        .files
        .iter()
        .map(|file| report(file, options))
        .collect();
    match args.format {
        OutputFormat::Json => print(&format!("{}\n", serde_json::to_string_pretty(&reports)?))?,
        OutputFormat::Text => print(&render_text(&reports))?,
    }
    Ok(if reports.iter().all(|r| r.valid) {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

fn report(file: &Path, options: LoadOptions) -> FileReport {
    let diagnostics = match load_file(file, options) {
        Ok(Loaded { diagnostics, .. }) => diagnostics,
        Err(err) => vec![load_error(&err)],
    };
    let errors = diagnostics.iter().filter(|d| d.is_error()).count();
    FileReport {
        file: file.display().to_string(),
        valid: errors == 0,
        errors,
        warnings: diagnostics.len() - errors,
        diagnostics,
    }
}

fn load_error(err: &LoadError) -> Diagnostic {
    match err {
        LoadError::Invalid { path, message } => Diagnostic::error(path, message),
        LoadError::Io { .. } | LoadError::Syntax { .. } => {
            Diagnostic::error("(file)", err.to_string())
        }
    }
}

fn render_text(reports: &[FileReport]) -> String {
    let mut lines = Vec::new();
    for report in reports {
        for d in &report.diagnostics {
            lines.push(format!("{}: {}: {}", d.severity, d.path, d.message));
            if let Some(hint) = &d.hint {
                lines.extend(hint.lines().map(|line| format!("    {line}")));
            }
        }
        let summary = match (report.errors, report.warnings) {
            (0, 0) => "valid".to_owned(),
            (0, w) => format!("valid, {w} warning{}", plural(w)),
            (e, w) => format!("{e} error{}, {w} warning{}", plural(e), plural(w)),
        };
        lines.push(format!("{}: {summary}", report.file));
    }
    lines.push(String::new());
    lines.join("\n")
}

fn plural(count: usize) -> &'static str {
    if count == 1 { "" } else { "s" }
}
