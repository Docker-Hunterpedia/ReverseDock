//! `rdock reload`, `rdock status` and `rdock healthcheck`: requests to the admin API of the
//! running proxy over plain HTTP/1.1 on its local admin listener.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, bail};
use rdock_model::Diagnostic;

use crate::run::{admin_address, admin_token};
use crate::{CtlArgs, StatusArgs, print};

const TIMEOUT: Duration = Duration::from_secs(30);

/// The admin address: `--admin`, or `admin.listener` from the configuration file.
fn address(args: &CtlArgs) -> SocketAddr {
    if let Some(address) = args.admin {
        return address;
    }
    let configured = rdock_config::load_file(&args.config).map_or_else(
        |_| rdock_model::settings::Admin::default().listener,
        |l| l.config.admin.listener,
    );
    let mut address = admin_address(&configured);
    if address.ip().is_unspecified() {
        address.set_ip(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    }
    address
}

/// Sends one request and returns status and body.
fn request(
    address: SocketAddr,
    method: &str,
    path: &str,
    token: Option<&str>,
) -> anyhow::Result<(u16, String)> {
    let mut stream = TcpStream::connect_timeout(&address, TIMEOUT)
        .with_context(|| format!("cannot reach the admin API at {address} (is rdock running?)"))?;
    stream.set_read_timeout(Some(TIMEOUT))?;
    stream.set_write_timeout(Some(TIMEOUT))?;
    let auth = token
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: {address}\r\n{auth}Content-Length: 0\r\nConnection: close\r\n\r\n"
    )?;
    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .context("reading the admin API response")?;
    let text = String::from_utf8_lossy(&raw);
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .context("invalid response from the admin API")?;
    Ok((status, body.to_owned()))
}

pub(crate) fn reload(args: &CtlArgs) -> anyhow::Result<ExitCode> {
    let token = admin_token(&args.data_dir, false)?;
    let (status, body) = request(address(args), "POST", "/api/v1/config/reload", Some(&token))?;
    if status == 401 {
        bail!("the admin token was refused");
    }
    let report: serde_json::Value = serde_json::from_str(&body).context("invalid reload report")?;
    let diagnostics: Vec<Diagnostic> = report["diagnostics"]
        .as_array()
        .map(|items| items.iter().filter_map(diagnostic).collect())
        .unwrap_or_default();
    let mut lines = crate::validate::render_diagnostics(&diagnostics);
    if status == 200 {
        lines.push(format!("applied generation {}", report["generation"]));
    } else {
        lines.push(format!(
            "rejected: {}; generation {} stays in use",
            report["error"].as_str().unwrap_or("unknown error"),
            report["generation"]
        ));
    }
    lines.push(String::new());
    print(&lines.join("\n"))?;
    Ok(if status == 200 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

fn diagnostic(value: &serde_json::Value) -> Option<Diagnostic> {
    let path = value["path"].as_str()?;
    let message = value["message"].as_str()?;
    let mut d = if value["severity"] == "error" {
        Diagnostic::error(path, message)
    } else {
        Diagnostic::warning(path, message)
    };
    if let Some(hint) = value["hint"].as_str() {
        d = d.with_hint(hint);
    }
    Some(d)
}

pub(crate) fn status(args: &StatusArgs) -> anyhow::Result<ExitCode> {
    let token = admin_token(&args.ctl.data_dir, false)?;
    let (status, body) = request(address(&args.ctl), "GET", "/api/v1/status", Some(&token))?;
    if status != 200 {
        bail!("the admin API answered {status}: {}", body.trim());
    }
    if args.json {
        print(&body)?;
        return Ok(ExitCode::SUCCESS);
    }
    let s: serde_json::Value = serde_json::from_str(&body).context("invalid status document")?;
    let mut lines = vec![
        format!(
            "rdock {} ({})",
            s["version"].as_str().unwrap_or("?"),
            s["commit"].as_str().unwrap_or("?")
        ),
        format!("ready        {}", s["ready"]),
        format!("generation   {}", s["generation"]),
        format!(
            "config       {} ({})",
            s["config_file"].as_str().unwrap_or("?"),
            s["origin"].as_str().unwrap_or("?")
        ),
        format!("started      {}", s["started_at"].as_str().unwrap_or("?")),
    ];
    for listener in s["listeners"].as_array().into_iter().flatten() {
        lines.push(format!(
            "listener     {} {} {} ({} routes)",
            listener["name"].as_str().unwrap_or("?"),
            listener["address"].as_str().unwrap_or("?"),
            listener["tls"]
                .as_str()
                .map_or("http".to_owned(), |p| format!("https/{p}")),
            listener["routes"]
        ));
    }
    if let Some(last) = s["last_reload"].as_object() {
        lines.push(format!(
            "last reload  {} by {} at {}",
            last.get("result").and_then(|v| v.as_str()).unwrap_or("?"),
            last.get("trigger").and_then(|v| v.as_str()).unwrap_or("?"),
            last.get("at").and_then(|v| v.as_str()).unwrap_or("?")
        ));
    }
    lines.push(String::new());
    print(&lines.join("\n"))?;
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn healthcheck(args: &CtlArgs) -> ExitCode {
    match request(address(args), "GET", "/readyz", None) {
        Ok((200, _)) => ExitCode::SUCCESS,
        Ok((status, body)) => {
            eprintln!("not ready ({status}): {}", body.trim());
            ExitCode::FAILURE
        }
        Err(err) => {
            eprintln!("not ready: {err:#}");
            ExitCode::FAILURE
        }
    }
}
