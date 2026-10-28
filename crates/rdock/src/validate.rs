//! `rdock validate`: loading, validation and compilation, without starting anything.

use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;

use rdock_config::includes::load_file_with_includes;
use rdock_config::{LoadError, Loaded};
use rdock_model::{Diagnostic, Severity};
use rdock_proxy::{CompileEnv, Mode, compile};
use serde::Serialize;

use crate::{OutputFormat, ValidateArgs, print};

/// Result of validating one file, as printed by `--format json`.
#[derive(Serialize)]
struct FileReport {
    file: String,
    valid: bool,
    errors: usize,
    warnings: usize,
    diagnostics: Vec<Diagnostic>,
}

pub(crate) fn validate(args: &ValidateArgs) -> anyhow::Result<ExitCode> {
    let reports: Vec<FileReport> = args
        .files
        .iter()
        .map(|file| report(file, args.strict))
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
pub(crate) fn diagnostics(file: &Path) -> Vec<Diagnostic> {
    match load_file_with_includes(file).map(|(loaded, _)| loaded) {
        Ok(Loaded {
            config,
            mut diagnostics,
            ..
        }) => {
            if !diagnostics.iter().any(Diagnostic::is_error) {
                let dns = rdock_proxy::upstream::Dns::default();
                let cloudflare = rdock_proxy::forwarded::CloudflareRanges::default();
                let backends = rdock_balancer::Registry::default();
                let compiled = compile(
                    &config,
                    &CompileEnv {
                        mode: Mode::Validate,
                        generation: 0,
                        dns: &dns,
                        client: Arc::new(rdock_middleware::HttpClient::default()),
                        previous: None,
                        cloudflare: &cloudflare,
                        backends: &backends,
                        sticky_key: b"validate",
                    },
                );
                diagnostics.extend(compiled.diagnostics);
            }
            diagnostics
        }
        Err(err) => vec![load_error(&err)],
    }
}

fn report(file: &Path, strict: bool) -> FileReport {
    let mut diagnostics = diagnostics(file);
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
