//! CLI parity with the admin API (ADR-0024, F-MGMT-01): configuration history, diff and
//! rollback, users, tokens, the audit log and backend drain, all through the admin socket
//! (or the listener with `RDOCK_ADMIN_TOKEN`).

use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, bail};
use clap::{Args, Subcommand};
use serde_json::{Value, json};

use crate::ctl::{Answer, Call, call};
use crate::{CtlArgs, print};

#[derive(Subcommand)]
pub(crate) enum ConfigCommand {
    /// List applied configurations, newest first.
    History(CtlArgs),
    /// Show what a document for the API provider would change, without applying it.
    Diff(ConfigFile),
    /// Restore the API provider's objects of a history entry.
    Rollback(Rollback),
}

#[derive(Args)]
pub(crate) struct ConfigFile {
    /// JSON or YAML with `routes`, `services` and `middlewares`.
    file: PathBuf,
    #[command(flatten)]
    ctl: CtlArgs,
}

#[derive(Args)]
pub(crate) struct Rollback {
    /// The `id` from `rdock config history`.
    id: u64,
    #[command(flatten)]
    ctl: CtlArgs,
}

#[derive(Subcommand)]
pub(crate) enum UsersCommand {
    /// List users.
    List(CtlArgs),
    /// Add a user; reads the first password from standard input.
    Add(UserAdd),
    /// Change a user's role or turn them off or on.
    Set(UserSet),
    /// Set a new password, read from standard input.
    Passwd(UserName),
    /// Remove a user's second factor, so they enrol again at the next login.
    ResetMfa(UserName),
    /// Delete a user, their sessions and their tokens.
    Remove(UserName),
}

#[derive(Args)]
pub(crate) struct UserAdd {
    name: String,
    /// `viewer`, `operator` or `admin`.
    #[arg(long, default_value = "viewer")]
    role: String,
    #[command(flatten)]
    ctl: CtlArgs,
}

#[derive(Args)]
pub(crate) struct UserSet {
    name: String,
    #[arg(long)]
    role: Option<String>,
    /// Turn the user off: no login, sessions end, tokens stop working.
    #[arg(long, conflicts_with = "enable")]
    disable: bool,
    #[arg(long)]
    enable: bool,
    #[command(flatten)]
    ctl: CtlArgs,
}

#[derive(Args)]
pub(crate) struct UserName {
    name: String,
    #[command(flatten)]
    ctl: CtlArgs,
}

#[derive(Subcommand)]
pub(crate) enum TokensCommand {
    /// List API tokens.
    List(CtlArgs),
    /// Create a token and print it once.
    Create(TokenCreate),
    /// Revoke a token by its ID.
    Revoke(TokenId),
}

#[derive(Args)]
pub(crate) struct TokenCreate {
    name: String,
    /// `metrics`, `viewer`, `operator` or `admin`.
    #[arg(long, default_value = "viewer")]
    role: String,
    /// Days until it expires; 0 never (only with `admin.tokens.allow_no_expiry`).
    #[arg(long)]
    days: Option<u16>,
    /// A network it may be used from; repeat for more.
    #[arg(long = "allow")]
    allowed_from: Vec<String>,
    #[command(flatten)]
    ctl: CtlArgs,
}

#[derive(Args)]
pub(crate) struct TokenId {
    id: String,
    #[command(flatten)]
    ctl: CtlArgs,
}

#[derive(Subcommand)]
pub(crate) enum BackendsCommand {
    /// List every service's backends and their state.
    List(CtlArgs),
    /// Stop sending new requests to a backend; open ones finish.
    Drain(BackendRef),
    /// Put a drained backend back in rotation.
    Undrain(BackendRef),
}

#[derive(Args)]
pub(crate) struct BackendRef {
    service: String,
    /// The backend's address as `rdock backends list` shows it.
    backend: String,
    #[command(flatten)]
    ctl: CtlArgs,
}

#[derive(Subcommand)]
pub(crate) enum RoutesCommand {
    /// Show how a request would be routed, without sending it: every route with why it
    /// matches or not, the winner and the backends it would use.
    Explain(Explain),
}

#[derive(Args)]
pub(crate) struct Explain {
    /// Host of the request.
    #[arg(long)]
    host: String,
    /// Path, with an optional query.
    #[arg(long, default_value = "/")]
    path: String,
    #[arg(long, default_value = "GET")]
    method: String,
    /// The listener; the first one when omitted.
    #[arg(long)]
    listener: Option<String>,
    /// A request header as `Name: value`; repeat for more.
    #[arg(long = "header")]
    headers: Vec<String>,
    /// The client's address, for `ClientIP` rules.
    #[arg(long)]
    client_ip: Option<std::net::IpAddr>,
    /// Print the raw JSON answer.
    #[arg(long)]
    json: bool,
    #[command(flatten)]
    ctl: CtlArgs,
}

#[derive(Args)]
pub(crate) struct AuditList {
    /// How many records, newest first.
    #[arg(long, default_value_t = 50)]
    limit: usize,
    #[command(flatten)]
    ctl: CtlArgs,
}

/// Fails with the API's error message unless the status is one of `ok`.
fn expect(answer: Answer, ok: &[u16]) -> anyhow::Result<Answer> {
    if ok.contains(&answer.status) {
        return Ok(answer);
    }
    let message = answer.json()["error"]
        .as_str()
        .map_or_else(|| answer.body.trim().to_owned(), str::to_owned);
    bail!("{} ({})", message, answer.status)
}

fn lines(rows: impl IntoIterator<Item = String>) -> anyhow::Result<ExitCode> {
    let mut text: Vec<String> = rows.into_iter().collect();
    text.push(String::new());
    print(&text.join("\n"))?;
    Ok(ExitCode::SUCCESS)
}

fn text(value: &Value) -> String {
    value
        .as_str()
        .map_or_else(|| value.to_string(), str::to_owned)
}

fn read_password() -> anyhow::Result<String> {
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .context("reading the password from standard input")?;
    let password = input.trim_end_matches(['\r', '\n']).to_owned();
    if password.is_empty() {
        bail!(
            "give the password on standard input, for example: read -rs P; echo \"$P\" | rdock users …"
        );
    }
    Ok(password)
}

pub(crate) fn config(command: &ConfigCommand) -> anyhow::Result<ExitCode> {
    match command {
        ConfigCommand::History(ctl) => {
            let answer = expect(
                call(ctl, &Call::new("GET", "/api/v1/config/history"))?,
                &[200],
            )?;
            let rows = answer.json().as_array().cloned().unwrap_or_default();
            lines(rows.iter().map(|e| {
                format!(
                    "{}  gen {:>4}  {}  {}{}",
                    e["id"],
                    e["generation"],
                    text(&e["applied_at"]),
                    text(&e["summary"]),
                    if e["api"] == true { "  [api]" } else { "" }
                )
            }))
        }
        ConfigCommand::Diff(args) => {
            let raw = std::fs::read_to_string(&args.file)
                .with_context(|| format!("reading {}", args.file.display()))?;
            let document: Value = serde_json::from_str(&raw).or_else(|_| {
                serde_saphyr::from_str(&raw).context("the file is neither JSON nor YAML")
            })?;
            let answer = expect(
                call(
                    &args.ctl,
                    &Call::new("POST", "/api/v1/config/validate").json(&document),
                )?,
                &[200],
            )?;
            let result = answer.json();
            let mut out = vec![text(&result["diff"])];
            for d in result["diagnostics"].as_array().into_iter().flatten() {
                out.push(format!(
                    "{}: {}: {}",
                    text(&d["severity"]),
                    text(&d["path"]),
                    text(&d["message"])
                ));
            }
            let valid = result["valid"] == true;
            out.push(if valid {
                "valid".into()
            } else {
                "would be rejected".into()
            });
            lines(out)?;
            Ok(if valid {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            })
        }
        ConfigCommand::Rollback(args) => {
            let current = expect(
                call(&args.ctl, &Call::new("GET", "/api/v1/config/api"))?,
                &[200],
            )?;
            let tag = current
                .header("etag")
                .context("the API sent no ETag")?
                .to_owned();
            let mut request =
                Call::new("POST", "/api/v1/config/rollback").json(&json!({ "id": args.id }));
            request.headers.push(("If-Match", tag));
            let answer = expect(call(&args.ctl, &request)?, &[200])?;
            lines([format!(
                "rolled back; generation {} in use",
                answer.json()["generation"]
            )])
        }
    }
}

pub(crate) fn users(command: &UsersCommand) -> anyhow::Result<ExitCode> {
    match command {
        UsersCommand::List(ctl) => {
            let answer = expect(call(ctl, &Call::new("GET", "/api/v1/users"))?, &[200])?;
            let rows = answer.json().as_array().cloned().unwrap_or_default();
            lines(rows.iter().map(|u| {
                format!(
                    "{:<24} {:<9} {}{}",
                    text(&u["name"]),
                    text(&u["role"]),
                    if u["mfa"] == true { "mfa" } else { "no mfa" },
                    if u["disabled"] == true {
                        "  disabled"
                    } else {
                        ""
                    }
                )
            }))
        }
        UsersCommand::Add(args) => {
            let body =
                json!({ "name": args.name, "role": args.role, "password": read_password()? });
            expect(
                call(&args.ctl, &Call::new("POST", "/api/v1/users").json(&body))?,
                &[201],
            )?;
            lines([format!("added {} ({})", args.name, args.role)])
        }
        UsersCommand::Set(args) => {
            let mut body = json!({});
            if let Some(role) = &args.role {
                body["role"] = json!(role);
            }
            if args.disable || args.enable {
                body["disabled"] = json!(args.disable);
            }
            change_user(&args.ctl, &args.name, &body)
        }
        UsersCommand::Passwd(args) => change_user(
            &args.ctl,
            &args.name,
            &json!({ "password": read_password()? }),
        ),
        UsersCommand::ResetMfa(args) => {
            change_user(&args.ctl, &args.name, &json!({ "reset_mfa": true }))
        }
        UsersCommand::Remove(args) => {
            let path = format!("/api/v1/users/{}", args.name);
            expect(call(&args.ctl, &Call::new("DELETE", &path))?, &[204])?;
            lines([format!("removed {}", args.name)])
        }
    }
}

fn change_user(ctl: &CtlArgs, name: &str, body: &Value) -> anyhow::Result<ExitCode> {
    let path = format!("/api/v1/users/{name}");
    expect(call(ctl, &Call::new("PATCH", &path).json(body))?, &[200])?;
    lines([format!("changed {name}; their sessions ended")])
}

pub(crate) fn tokens(command: &TokensCommand) -> anyhow::Result<ExitCode> {
    match command {
        TokensCommand::List(ctl) => {
            let answer = expect(call(ctl, &Call::new("GET", "/api/v1/tokens"))?, &[200])?;
            let rows = answer.json().as_array().cloned().unwrap_or_default();
            lines(rows.iter().map(|t| {
                format!(
                    "{}  {:<9} {:<24} by {}",
                    text(&t["id"]),
                    text(&t["role"]),
                    text(&t["name"]),
                    text(&t["created_by"])
                )
            }))
        }
        TokensCommand::Create(args) => {
            let mut body =
                json!({ "name": args.name, "role": args.role, "allowed_from": args.allowed_from });
            if let Some(days) = args.days {
                body["expires_in_days"] = json!(days);
            }
            let answer = expect(
                call(&args.ctl, &Call::new("POST", "/api/v1/tokens").json(&body))?,
                &[201],
            )?;
            lines([
                text(&answer.json()["token"]),
                "Store it now: it is shown only once.".to_owned(),
            ])
        }
        TokensCommand::Revoke(args) => {
            let path = format!("/api/v1/tokens/{}", args.id);
            expect(call(&args.ctl, &Call::new("DELETE", &path))?, &[204])?;
            lines([format!("revoked {}", args.id)])
        }
    }
}

pub(crate) fn backends(command: &BackendsCommand) -> anyhow::Result<ExitCode> {
    let (ctl, path, target, drained) = match command {
        BackendsCommand::List(ctl) => {
            let answer = expect(call(ctl, &Call::new("GET", "/api/v1/backends"))?, &[200])?;
            let services = answer.json().as_array().cloned().unwrap_or_default();
            let mut out = Vec::new();
            for service in &services {
                for b in service["backends"].as_array().into_iter().flatten() {
                    out.push(format!(
                        "{:<20} {:<28} {:<6} in flight {}{}",
                        text(&service["service"]),
                        text(&b["address"]),
                        text(&b["state"]),
                        b["in_flight"],
                        if b["drained"] == true {
                            "  drained"
                        } else {
                            ""
                        }
                    ));
                }
            }
            return lines(out);
        }
        BackendsCommand::Drain(target) => (&target.ctl, "/api/v1/backends/drain", target, true),
        BackendsCommand::Undrain(target) => {
            (&target.ctl, "/api/v1/backends/undrain", target, false)
        }
    };
    let body = json!({ "service": target.service, "backend": target.backend });
    expect(call(ctl, &Call::new("POST", path).json(&body))?, &[200])?;
    lines([format!(
        "{} {}/{}",
        if drained {
            "drained"
        } else {
            "back in rotation:"
        },
        target.service,
        target.backend
    )])
}

pub(crate) fn audit_list(args: &AuditList) -> anyhow::Result<ExitCode> {
    let path = format!("/api/v1/audit?limit={}", args.limit);
    let answer = expect(call(&args.ctl, &Call::new("GET", &path))?, &[200])?;
    let rows = answer.json().as_array().cloned().unwrap_or_default();
    lines(rows.iter().map(|r| {
        format!(
            "{} #{:<6} {:<8} {:<24} {:<22} {}{}",
            text(&r["time"]),
            r["seq"],
            text(&r["result"]),
            text(&r["actor"]),
            text(&r["action"]),
            r["resource"].as_str().unwrap_or_default(),
            r["reason"]
                .as_str()
                .map(|s| format!("  ({s})"))
                .unwrap_or_default()
        )
    }))
}

pub(crate) fn routes(command: &RoutesCommand) -> anyhow::Result<ExitCode> {
    let RoutesCommand::Explain(args) = command;
    let mut headers = serde_json::Map::new();
    for header in &args.headers {
        let (name, value) = header
            .split_once(':')
            .with_context(|| format!("write headers as `Name: value`, not `{header}`"))?;
        headers.insert(name.trim().to_owned(), json!(value.trim()));
    }
    let body = json!({
        "listener": args.listener.clone().unwrap_or_default(),
        "host": args.host,
        "path": args.path,
        "method": args.method,
        "headers": headers,
        "client_ip": args.client_ip,
    });
    let answer = expect(
        call(
            &args.ctl,
            &Call::new("POST", "/api/v1/routes/explain").json(&body),
        )?,
        &[200],
    )?;
    let result = answer.json();
    if args.json {
        return lines([serde_json::to_string_pretty(&result).unwrap_or_default()]);
    }
    let mut out = vec![format!(
        "{} {}{} on listener {}",
        text(&result["request"]["method"]),
        text(&result["request"]["host"]),
        text(&result["request"]["path"]),
        text(&result["listener"])
    )];
    for route in result["routes"].as_array().into_iter().flatten() {
        let mark = match route["result"].as_str() {
            Some("matched") => "→",
            Some("shadowed") => "≈",
            _ => "✗",
        };
        out.push(format!(
            "  {mark} {:<28} {}",
            text(&route["name"]),
            route["reason"].as_str().unwrap_or("matches")
        ));
    }
    let outcome = &result["outcome"];
    match outcome["result"].as_str() {
        Some("route") => {
            out.push(format!(
                "route {} → service {}",
                text(&outcome["route"]),
                text(&outcome["service"])
            ));
            let middlewares: Vec<String> = outcome["middlewares"]
                .as_array()
                .into_iter()
                .flatten()
                .map(text)
                .collect();
            if !middlewares.is_empty() {
                out.push(format!("middlewares: {}", middlewares.join(" → ")));
            }
            for b in outcome["backends"].as_array().into_iter().flatten() {
                let state = if b["considered"] == true {
                    "considered".to_owned()
                } else {
                    format!("excluded: {}", b["reason"].as_str().unwrap_or("?"))
                };
                out.push(format!("  backend {:<28} {state}", text(&b["address"])));
            }
        }
        _ => out.push(format!(
            "{}: {}",
            text(&outcome["result"]),
            outcome["reason"].as_str().unwrap_or_default()
        )),
    }
    lines(out)
}
