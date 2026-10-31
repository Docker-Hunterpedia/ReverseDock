//! `rdock reload`, `rdock status` and `rdock healthcheck`: requests to the admin API of the
//! running proxy over plain HTTP/1.1, on its local Unix socket (no token needed, ADR-0024) or
//! its admin listener.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, SystemTime};

use anyhow::{Context, bail};
use rdock_model::Diagnostic;
use rdock_model::settings::Admin;

use crate::run::{admin_address, socket_path};
use crate::{CtlArgs, StatusArgs, print};

const TIMEOUT: Duration = Duration::from_secs(30);

/// The `admin` section of the configuration file, or the defaults when it cannot be read.
fn admin_settings(args: &CtlArgs) -> Admin {
    rdock_config::load_file(&args.config).map_or_else(|_| Admin::default(), |l| l.config.admin)
}

/// The admin address: `--admin`, or `admin.listener` from the configuration file.
fn address(args: &CtlArgs) -> SocketAddr {
    if let Some(address) = args.admin {
        return address;
    }
    let mut address = admin_address(&admin_settings(args).listener);
    if address.ip().is_unspecified() {
        address.set_ip(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    }
    address
}

/// Where an authenticated command goes.
enum Target {
    /// The local socket: file permissions are the authentication.
    Socket(PathBuf),
    /// The admin listener, with an API token.
    Tcp(SocketAddr, String),
}

/// The socket when it exists and `--admin` is not given; otherwise the listener and an API
/// token.
fn target(args: &CtlArgs) -> anyhow::Result<Target> {
    if args.admin.is_none() {
        let socket = admin_settings(args)
            .socket
            .unwrap_or_else(|| socket_path(&args.data_dir));
        if socket.exists() {
            return Ok(Target::Socket(socket));
        }
    }
    Ok(Target::Tcp(address(args), api_token()?))
}

/// An API token for the listener: `RDOCK_ADMIN_TOKEN` (ADR-0024; the shared token file of
/// v0.1–v0.4 is gone).
fn api_token() -> anyhow::Result<String> {
    match std::env::var("RDOCK_ADMIN_TOKEN") {
        Ok(token) if !token.trim().is_empty() => Ok(token.trim().to_owned()),
        _ => anyhow::bail!(
            "set RDOCK_ADMIN_TOKEN to an API token to use the admin listener, or run this on the \
             server, where the admin socket needs none (create tokens in the dashboard or with \
             POST /api/v1/tokens)"
        ),
    }
}

/// One request to the admin API: method, path, extra headers and an optional JSON body.
pub(crate) struct Call<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub headers: Vec<(&'a str, String)>,
    pub body: Option<String>,
}

impl<'a> Call<'a> {
    pub(crate) fn new(method: &'a str, path: &'a str) -> Self {
        Self {
            method,
            path,
            headers: Vec::new(),
            body: None,
        }
    }

    /// With a JSON body.
    pub(crate) fn json(mut self, body: &serde_json::Value) -> Self {
        self.headers
            .push(("Content-Type", "application/json".into()));
        self.body = Some(body.to_string());
        self
    }
}

/// The answer: status, response head and body.
pub(crate) struct Answer {
    pub status: u16,
    pub head: String,
    pub body: String,
}

impl Answer {
    /// The body as JSON (`null` when it is not JSON).
    pub(crate) fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body).unwrap_or(serde_json::Value::Null)
    }

    /// A response header, by lower-case name.
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.head.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name).then(|| value.trim())
        })
    }
}

/// Sends `call` to the running proxy (socket, or listener with an API token).
pub(crate) fn call(args: &CtlArgs, call: &Call<'_>) -> anyhow::Result<Answer> {
    send_call(&target(args)?, call)
}

fn send(target: &Target, method: &str, path: &str) -> anyhow::Result<(u16, String)> {
    send_call(target, &Call::new(method, path)).map(|a| (a.status, a.body))
}

fn send_call(target: &Target, call: &Call<'_>) -> anyhow::Result<Answer> {
    match target {
        Target::Socket(socket) => {
            let stream = UnixStream::connect(socket).with_context(|| {
                format!(
                    "cannot reach the admin socket {} (is rdock running?)",
                    socket.display()
                )
            })?;
            stream.set_read_timeout(Some(TIMEOUT))?;
            stream.set_write_timeout(Some(TIMEOUT))?;
            exchange(stream, call, "localhost", None)
        }
        Target::Tcp(address, token) => tcp_request(*address, call, Some(token)),
    }
}

/// Sends one request to the admin listener.
fn tcp_request(
    address: SocketAddr,
    call: &Call<'_>,
    token: Option<&str>,
) -> anyhow::Result<Answer> {
    let stream = TcpStream::connect_timeout(&address, TIMEOUT)
        .with_context(|| format!("cannot reach the admin API at {address} (is rdock running?)"))?;
    stream.set_read_timeout(Some(TIMEOUT))?;
    stream.set_write_timeout(Some(TIMEOUT))?;
    exchange(stream, call, &address.to_string(), token)
}

fn exchange(
    mut stream: impl Read + Write,
    call: &Call<'_>,
    host: &str,
    token: Option<&str>,
) -> anyhow::Result<Answer> {
    use std::fmt::Write as _;
    let mut head = format!("{} {} HTTP/1.1\r\nHost: {host}\r\n", call.method, call.path);
    if let Some(token) = token {
        let _ = write!(head, "Authorization: Bearer {token}\r\n");
    }
    for (name, value) in &call.headers {
        let _ = write!(head, "{name}: {value}\r\n");
    }
    let body = call.body.as_deref().unwrap_or_default();
    let _ = write!(
        head,
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body.as_bytes())?;
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
    Ok(Answer {
        status,
        head: head.to_owned(),
        body: body.to_owned(),
    })
}

pub(crate) fn reload(args: &CtlArgs) -> anyhow::Result<ExitCode> {
    let (status, body) = send(&target(args)?, "POST", "/api/v1/config/reload")?;
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
    let (status, body) = send(&target(&args.ctl)?, "GET", "/api/v1/status")?;
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
    for cert in s["certificates"].as_array().into_iter().flatten() {
        lines.push(certificate_line(cert));
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

/// One automatic certificate: names, expiry and renewal plan, and the last error if failing.
fn certificate_line(cert: &serde_json::Value) -> String {
    let names: Vec<&str> = cert["names"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .collect();
    let when = |key: &str| {
        cert[key]
            .as_i64()
            .and_then(|t| {
                SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(t.try_into().ok()?))
            })
            .map_or_else(|| "-".to_owned(), rdock_observability::rfc3339)
    };
    let failing = cert["last_error"]
        .as_str()
        .map(|error| format!(" — {} failures, last: {error}", cert["failures"]))
        .unwrap_or_default();
    format!(
        "certificate  {} expires {} renews {} ({}){failing}",
        names.join(","),
        when("not_after"),
        when("renew_at"),
        cert["renewal"].as_str().unwrap_or("?")
    )
}

pub(crate) fn healthcheck(args: &CtlArgs) -> ExitCode {
    match tcp_request(address(args), &Call::new("GET", "/readyz"), None).map(|a| (a.status, a.body))
    {
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
