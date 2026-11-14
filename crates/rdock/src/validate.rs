//! `rdock validate`: loading, validation and compilation, without starting anything.

use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;

use rdock_config::includes::load_file_with_includes;
use rdock_config::{LoadError, Loaded};
use rdock_model::{Diagnostic, Severity};
use rdock_proxy::{CompileEnv, Mode, compile};
use serde::Serialize;

use crate::{OutputFormat, Registry, ValidateArgs, print};

/// Result of validating one file, as printed by `--format json`.
#[derive(Serialize)]
struct FileReport {
    file: String,
    valid: bool,
    errors: usize,
    warnings: usize,
    diagnostics: Vec<Diagnostic>,
}

pub(crate) fn validate(args: &ValidateArgs, plugins: &Registry) -> anyhow::Result<ExitCode> {
    let reports: Vec<FileReport> = args
        .files
        .iter()
        .map(|file| report(file, args.strict, plugins))
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

/// Load, validation and compile diagnostics of one file.
pub(crate) fn diagnostics(file: &Path, plugins: &Registry) -> Vec<Diagnostic> {
    match load_file_with_includes(file).map(|(loaded, _)| loaded) {
        Ok(Loaded {
            config,
            mut diagnostics,
            ..
        }) => {
            if !diagnostics.iter().any(Diagnostic::is_error) {
                diagnostics.extend(read_vault(&config));
            }
            if !diagnostics.iter().any(Diagnostic::is_error) {
                diagnostics.extend(compile_diagnostics(&config, plugins));
            }
            diagnostics
        }
        Err(err) => vec![load_error(&err)],
    }
}

/// What compiling `config` (as `rdock validate` does, nothing bound or started) finds.
pub(crate) fn compile_diagnostics(
    config: &rdock_model::Config,
    plugins: &Registry,
) -> Vec<Diagnostic> {
    let dns = rdock_proxy::upstream::Dns::default();
    let cloudflare = rdock_proxy::forwarded::CloudflareRanges::default();
    let backends = rdock_balancer::Registry::default();
    compile(
        config,
        &CompileEnv {
            mode: Mode::Validate,
            generation: 0,
            dns: &dns,
            client: Arc::new(rdock_middleware::HttpClient::default()),
            previous: None,
            cloudflare: &cloudflare,
            backends: &backends,
            sticky_key: b"validate",
            live: &rdock_observability::live::Live::default(),
            caches: None,
            plugins,
            metrics: None,
            quotas: None,
            abuse: None,
            shared_limits: None,
        },
    )
    .diagnostics
}

/// Reads the configuration's `${vault:…}` references, as a start would: secret fields that
/// are checked when compiled (a JWT key's length) need their value. On its own thread with its
/// own runtime, so it works whether or not the caller runs in one.
fn read_vault(config: &rdock_model::Config) -> Vec<Diagnostic> {
    let Some(settings) = config.secrets.vault.clone() else {
        return Vec::new();
    };
    let references = crate::engine::vault_references(config);
    if references.is_empty() {
        return Vec::new();
    }
    let read = std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_or_else(
                |e| {
                    vec![Diagnostic::error(
                        "secrets.vault",
                        format!("cannot start the Vault client: {e}"),
                    )]
                },
                |runtime| runtime.block_on(crate::engine::read_vault_once(&settings, &references)),
            )
    });
    read.join().unwrap_or_else(|_| {
        vec![Diagnostic::error(
            "secrets.vault",
            "reading from Vault failed",
        )]
    })
}

fn report(file: &Path, strict: bool, plugins: &Registry) -> FileReport {
    let mut diagnostics = diagnostics(file, plugins);
    if strict {
        for d in &mut diagnostics {
            d.severity = Severity::Error;
        }
    }
    let errors = diagnostics.iter().filter(|d| d.is_error()).count();
    FileReport {
        file: file.display().to_string(),
        valid: errors == 0,
        errors,
        warnings: diagnostics.len() - errors,
        diagnostics,
    }
}

pub(crate) fn load_error(err: &LoadError) -> Diagnostic {
    match err {
        LoadError::Invalid { path, message } => Diagnostic::error(path, message),
        LoadError::Io { .. } | LoadError::Syntax { .. } => {
            Diagnostic::error("(file)", err.to_string())
        }
    }
}

/// Diagnostics as text: one line each with an indented hint, then a summary per file.
pub(crate) fn render_diagnostics(diagnostics: &[Diagnostic]) -> Vec<String> {
    let mut lines = Vec::new();
    for d in diagnostics {
        lines.push(format!("{}: {}: {}", d.severity, d.path, d.message));
        if let Some(hint) = &d.hint {
            lines.extend(hint.lines().map(|line| format!("    {line}")));
        }
    }
    lines
}

fn render_text(reports: &[FileReport]) -> String {
    let mut lines = Vec::new();
    for report in reports {
        lines.extend(render_diagnostics(&report.diagnostics));
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
