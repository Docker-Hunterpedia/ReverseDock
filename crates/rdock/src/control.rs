//! `rdock control`: the control plane of a cluster (H-HA-01…03, ADR-0031) in the same binary,
//! so it reuses the admin API's users, tokens, audit log and dashboard; and the commands that
//! talk to it over its admin socket.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use std::fmt::Write as _;

use anyhow::{Context, bail};
use async_trait::async_trait;
use clap::{Args, Subcommand};
use rdock_control::ControlPlane;
use rdock_model::Diagnostic;
use rdock_observability::{LogFormat, Metrics, init_logging};
use serde_json::{Value, json};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::watch;

use crate::ctl::{Answer, Call, call};
use crate::{COMMIT, CtlArgs, DEFAULT_DATA_DIR, LogFormatArg, VERSION, print};

/// Default configuration file of the control plane.
const DEFAULT_CONTROL_CONFIG: &str = "/etc/rdock/control.yaml";

/// Sections a control plane's file may hold: everything else is published to data planes.
const CONTROL_SECTIONS: [&str; 5] = ["$schema", "version", "control", "admin", "observability"];

#[derive(Subcommand)]
pub(crate) enum ControlCommand {
    /// Run the control plane: the cluster listener data planes connect to, and the admin API.
    Run(ControlRunArgs),
    /// Validate a configuration file and publish it to the data planes as the next revision.
    Publish(PublishArgs),
    /// List published revisions, newest first, with the instances that refused each.
    Revisions(ControlCtl),
    /// Publish an earlier revision's configuration again, as a new revision.
    Rollback(RollbackArgs),
    /// List enrolled data planes: state, revision served, last report.
    Instances(ControlCtl),
    /// Revoke a data plane: it can no longer fetch bundles or use the store.
    Revoke(RevokeArgs),
    /// The rollout of the newest revision: show it, resume a halted one, or abandon it.
    #[command(subcommand)]
    Rollout(RolloutCommand),
    /// Join tokens for enrolling data planes.
    #[command(subcommand)]
    Token(TokenCommand),
}

/// The admin socket of the control plane (the same flags as the data plane's commands, with
/// the control plane's default file).
#[derive(Args)]
pub(crate) struct ControlCtl {
    /// Admin listener of the control plane. Read from the configuration file when omitted.
    #[arg(long, env = "RDOCK_ADMIN")]
    admin: Option<std::net::SocketAddr>,
    /// The control plane's configuration file, to find the admin listener.
    #[arg(short, long, default_value = DEFAULT_CONTROL_CONFIG)]
    config: PathBuf,
    /// The control plane's data directory, to find the admin socket.
    #[arg(long, env = "RDOCK_DATA_DIR", default_value = DEFAULT_DATA_DIR)]
    data_dir: PathBuf,
}

impl ControlCtl {
    fn ctl(&self) -> CtlArgs {
        CtlArgs {
            admin: self.admin,
            config: self.config.clone(),
            data_dir: self.data_dir.clone(),
        }
    }
}

#[derive(Args)]
pub(crate) struct ControlRunArgs {
    /// The control plane's configuration file (`control` and `admin`).
    #[arg(short, long, default_value = DEFAULT_CONTROL_CONFIG)]
    config: PathBuf,
    /// Directory for the cluster CA, join tokens, instances, revisions and the store. Its
    /// contents include certificate private keys and the ACME account key: protect and back it
    /// up like a data directory.
    #[arg(long, env = "RDOCK_DATA_DIR", default_value = DEFAULT_DATA_DIR)]
    data_dir: PathBuf,
    /// Log filter, e.g. `info`.
    #[arg(long, env = "RDOCK_LOG", default_value = "info")]
    log: String,
    /// Format of the application log.
    #[arg(long, env = "RDOCK_LOG_FORMAT", value_enum, default_value_t = LogFormatArg::Auto)]
    log_format: LogFormatArg,
}

#[derive(Args)]
pub(crate) struct PublishArgs {
    /// The configuration to publish (YAML, or JSON with a .json extension), without `cluster`
    /// and `control`. References such as `${file:…}` are published as written and resolved on
    /// each data plane.
    file: PathBuf,
    #[command(flatten)]
    ctl: ControlCtl,
}

#[derive(Args)]
pub(crate) struct RollbackArgs {
    /// The revision whose configuration to publish again.
    revision: u64,
    #[command(flatten)]
    ctl: ControlCtl,
}

#[derive(Args)]
pub(crate) struct RevokeArgs {
    /// The instance's name, as `rdock control instances` lists it.
    name: String,
    #[command(flatten)]
    ctl: ControlCtl,
}

#[derive(Subcommand)]
pub(crate) enum RolloutCommand {
    /// Show the rollout: phase, canary, stable revision, why it halted.
    Status(ControlCtl),
    /// Let a halted (or soaking) rollout go on: every instance takes the revision now.
    Resume(ControlCtl),
    /// Abandon the rollout: the stable revision is published again and every instance takes
    /// it at once.
    Abandon(ControlCtl),
}

#[derive(Subcommand)]
pub(crate) enum TokenCommand {
    /// Create a single-use join token; prints it once, with the `ca_pin` line for data planes.
    Create(TokenCreateArgs),
}

#[derive(Args)]
pub(crate) struct TokenCreateArgs {
    /// How long the token stays usable, e.g. `30m` or `1d` [default: `control.join_token_ttl`].
    #[arg(long)]
    ttl: Option<String>,
    #[command(flatten)]
    ctl: ControlCtl,
}

fn expect(answer: Answer, ok: &[u16]) -> anyhow::Result<Answer> {
    if ok.contains(&answer.status) {
        return Ok(answer);
    }
    let value = answer.json();
    let mut message = value["error"]
        .as_str()
        .map_or_else(|| answer.body.trim().to_owned(), str::to_owned);
    if let Some(diagnostics) = value["diagnostics"].as_array() {
        for d in diagnostics {
            let _ = write!(
                message,
                "\n  {} {}: {}",
                d["severity"].as_str().unwrap_or("error"),
                d["path"].as_str().unwrap_or(""),
                d["message"].as_str().unwrap_or("")
            );
        }
    }
    bail!("{} ({})", message, answer.status)
}

/// The rollout in a few lines.
fn render_rollout(value: &Value) -> String {
    let mut out = format!(
        "rollout of revision {}: {} (mode {}, stable revision {})\n",
        value["revision"],
        text(&value["phase"]),
        text(&value["mode"]),
        value["stable"]
    );
    if let Some(canary) = value["canary"].as_str() {
        let _ = writeln!(out, "  canary: {canary}");
    }
    if let Some(at) = value["soak_ends_at"].as_str() {
        let _ = writeln!(out, "  the rest follow at {at}");
    }
    if let Some(reason) = value["halt"]["reason"].as_str() {
        let _ = writeln!(
            out,
            "  halted: {reason}\n  resume with `rdock control rollout resume` or abandon with `rdock control rollout abandon`"
        );
    }
    out
}

fn text(value: &Value) -> String {
    value
        .as_str()
        .map_or_else(|| value.to_string(), str::to_owned)
}

/// `rdock control …`.
#[allow(clippy::too_many_lines)] // one arm per command, each a request and its rendering
pub(crate) fn control(
    command: &ControlCommand,
    plugins: &Arc<rdock_plugin_api::Registry>,
) -> anyhow::Result<ExitCode> {
    match command {
        ControlCommand::Run(args) => run(args, plugins),
        ControlCommand::Publish(args) => {
            let text_doc = std::fs::read_to_string(&args.file)
                .with_context(|| format!("reading {}", args.file.display()))?;
            let document = rdock_config::parse_document(
                &text_doc,
                rdock_config::Format::from_path(&args.file),
            )
            .map_err(|e| anyhow::anyhow!("{}: {e}", args.file.display()))?;
            let answer = expect(
                call(
                    &args.ctl.ctl(),
                    &Call::new("POST", "/api/v1/cluster/revisions")
                        .json(&json!({ "document": document })),
                )?,
                &[201],
            )?;
            let value = answer.json();
            let mut out = format!(
                "published revision {} (sha256 {})\n",
                value["revision"],
                text(&value["sha256"])
            );
            for w in value["warnings"].as_array().into_iter().flatten() {
                let _ = writeln!(out, "warning {}: {}", text(&w["path"]), text(&w["message"]));
            }
            print(&out)?;
            Ok(ExitCode::SUCCESS)
        }
        ControlCommand::Rollback(args) => {
            let answer = expect(
                call(
                    &args.ctl.ctl(),
                    &Call::new("POST", "/api/v1/cluster/revisions")
                        .json(&json!({ "rollback_to": args.revision })),
                )?,
                &[201],
            )?;
            let value = answer.json();
            print(&format!(
                "published revision {} with the configuration of revision {}\n",
                value["revision"], args.revision
            ))?;
            Ok(ExitCode::SUCCESS)
        }
        ControlCommand::Revisions(ctl) => {
            let answer = expect(
                call(&ctl.ctl(), &Call::new("GET", "/api/v1/cluster/revisions"))?,
                &[200],
            )?;
            let value = answer.json();
            let mut out = String::new();
            for r in value["revisions"].as_array().into_iter().flatten() {
                let mut rollback = r["rollback_of"]
                    .as_u64()
                    .map(|o| format!(" (rollback of {o})"))
                    .unwrap_or_default();
                if let Some(state) = r["rollout"]["state"].as_str()
                    && state != "complete"
                {
                    let _ = write!(rollback, "  rollout {state}");
                    if let Some(reason) = r["rollout"]["reason"].as_str() {
                        let _ = write!(rollback, ": {reason}");
                    }
                }
                let refused: Vec<String> = r["refused_by"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|x| text(&x["instance"]))
                    .collect();
                let refused = if refused.is_empty() {
                    String::new()
                } else {
                    format!("  refused by {}", refused.join(", "))
                };
                let _ = writeln!(
                    out,
                    "{:>6}  {}  {}{rollback}{refused}",
                    r["revision"],
                    text(&r["published_at"]),
                    &text(&r["sha256"])[..12.min(text(&r["sha256"]).len())]
                );
            }
            if value["rollout"].is_object() {
                out.push_str(&render_rollout(&value["rollout"]));
            }
            print(&out)?;
            Ok(ExitCode::SUCCESS)
        }
        ControlCommand::Rollout(command) => {
            let (ctl, call_spec) = match command {
                RolloutCommand::Status(ctl) => (ctl, Call::new("GET", "/api/v1/cluster/rollout")),
                RolloutCommand::Resume(ctl) => (
                    ctl,
                    Call::new("POST", "/api/v1/cluster/rollout/resume").json(&json!({})),
                ),
                RolloutCommand::Abandon(ctl) => (
                    ctl,
                    Call::new("POST", "/api/v1/cluster/rollout/abandon").json(&json!({})),
                ),
            };
            let value = expect(call(&ctl.ctl(), &call_spec)?, &[200])?.json();
            let out = match command {
                RolloutCommand::Abandon(_) => format!(
                    "abandoned; published revision {} with the configuration of revision {}\n",
                    value["revision"], value["rollback_of"]
                ),
                _ => render_rollout(&value),
            };
            print(&out)?;
            Ok(ExitCode::SUCCESS)
        }
        ControlCommand::Instances(ctl) => {
            let answer = expect(
                call(&ctl.ctl(), &Call::new("GET", "/api/v1/cluster/instances"))?,
                &[200],
            )?;
            let value = answer.json();
            let mut out = String::new();
            for i in value["instances"].as_array().into_iter().flatten() {
                let mut line = format!(
                    "{:<24} {:<8} serving {:<4} target {:<4} {}",
                    text(&i["name"]),
                    text(&i["state"]),
                    i["serving"],
                    i["target"],
                    text(&i["version"])
                );
                if let Some(error) = i["last_error"].as_str() {
                    let _ = write!(line, "  {error}");
                }
                let _ = writeln!(out, "{}", line.trim_end());
            }
            if value["rollout"].is_object() {
                out.push_str(&render_rollout(&value["rollout"]));
            }
            print(&out)?;
            Ok(ExitCode::SUCCESS)
        }
        ControlCommand::Revoke(args) => {
            let path = format!("/api/v1/cluster/instances/{}/revoke", args.name);
            expect(
                call(&args.ctl.ctl(), &Call::new("POST", &path).json(&json!({})))?,
                &[200],
            )?;
            print(&format!("revoked {}\n", args.name))?;
            Ok(ExitCode::SUCCESS)
        }
        ControlCommand::Token(TokenCommand::Create(args)) => {
            let mut body = json!({});
            if let Some(ttl) = &args.ttl {
                let ttl: rdock_model::values::Duration = serde_json::from_value(json!(ttl))
                    .map_err(|e| anyhow::anyhow!("--ttl: {e}"))?;
                body["ttl_seconds"] = json!(ttl.as_std().as_secs());
            }
            let answer = expect(
                call(
                    &args.ctl.ctl(),
                    &Call::new("POST", "/api/v1/cluster/tokens").json(&body),
                )?,
                &[201],
            )?;
            let value = answer.json();
            print(&format!(
                "{}\nStore it now: it is shown only once, works once and expires at {}.\nData planes need:\n  cluster:\n    control:\n      ca_pin: \"{}\"\n",
                text(&value["token"]),
                text(&value["expires_at"]),
                text(&value["ca_pin"])
            ))?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

/// `rdock control run`.
fn run(
    args: &ControlRunArgs,
    plugins: &Arc<rdock_plugin_api::Registry>,
) -> anyhow::Result<ExitCode> {
    let format = match args.log_format {
        LogFormatArg::Auto => LogFormat::Auto,
        LogFormatArg::Json => LogFormat::Json,
        LogFormatArg::Text => LogFormat::Text,
    };
    init_logging(format, &args.log).map_err(anyhow::Error::msg)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("rdock-control")
        .build()
        .context("starting the async runtime")?;
    runtime.block_on(serve(args, plugins.clone()))
}

/// Loads and checks the control plane's file: `control` and `admin` only.
fn load(path: &Path) -> anyhow::Result<rdock_model::Config> {
    let loaded =
        rdock_config::load_file(path).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
    let mut problems: Vec<Diagnostic> = loaded
        .diagnostics
        .iter()
        .filter(|d| d.is_error())
        .cloned()
        .collect();
    if let Some(map) = loaded.source.as_object() {
        for key in map
            .keys()
            .filter(|k| !CONTROL_SECTIONS.contains(&k.as_str()))
        {
            problems.push(
                Diagnostic::error(key.clone(), format!("the control plane does not serve traffic: `{key}` belongs in a configuration you publish"))
                    .with_hint("publish it with `rdock control publish <file>`; this file holds `control` and `admin`"),
            );
        }
    }
    // Settings this version does not implement yet (ADR-0014), for the control plane.
    let mut gated = Vec::new();
    rdock_proxy::gate::check(&loaded.config, rdock_proxy::Mode::Run, &mut gated);
    problems.extend(
        gated
            .into_iter()
            .filter(|d| d.is_error() && d.path.starts_with("control.")),
    );
    if loaded.config.control.is_none() {
        problems.push(Diagnostic::error(
            "control",
            "`rdock control run` needs a `control` section",
        ));
    }
    if !problems.is_empty() {
        let lines = crate::validate::render_diagnostics(&problems).join("\n");
        bail!("{} cannot be used:\n{lines}", path.display());
    }
    Ok(loaded.config)
}

async fn serve(
    args: &ControlRunArgs,
    plugins: Arc<rdock_plugin_api::Registry>,
) -> anyhow::Result<ExitCode> {
    let mut terminate = signal(SignalKind::terminate()).context("installing signal handlers")?;
    let mut interrupt = signal(SignalKind::interrupt()).context("installing signal handlers")?;
    let config = match load(&args.config) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("error: {e:#}");
            return Ok(ExitCode::from(1));
        }
    };
    std::fs::create_dir_all(&args.data_dir)
        .with_context(|| format!("creating the data directory {}", args.data_dir.display()))?;
    let _lock = match crate::datadir::DataDirLock::acquire(&args.data_dir) {
        Ok(lock) => lock,
        Err(err) => {
            eprintln!("error: {err}");
            return Ok(ExitCode::from(1));
        }
    };
    let settings = config.control.clone().map(|c| *c).unwrap_or_default();
    let plane = ControlPlane::open(&args.data_dir, settings.clone())
        .context("opening the control plane's state")?;
    let address = crate::run::admin_address(&settings.listener);
    let listener = std::net::TcpListener::bind(address)
        .with_context(|| format!("cannot listen on the cluster address {address}"))?;
    let (stop, stop_rx) = watch::channel(false);
    let server = tokio::spawn(rdock_control::server::serve(
        plane.clone(),
        listener,
        stop_rx.clone(),
    ));
    let events = plane.events();
    tokio::spawn(plane.clone().drive(stop_rx.clone()));
    let metrics = Metrics::new(VERSION, COMMIT).context("registering metrics")?;
    let admin = ControlAdmin {
        plane: plane.clone(),
        metrics: metrics.clone(),
        prometheus: config.observability.metrics.prometheus,
        plugins,
    };
    tokio::spawn(admin.clone().keep_gauges(stop_rx.clone()));
    let running = if config.admin.enabled {
        let socket = config
            .admin
            .socket
            .clone()
            .unwrap_or_else(|| crate::run::socket_path(&args.data_dir));
        let settings =
            crate::run::admin_settings(config.admin.clone(), &args.data_dir, socket.clone(), None);
        let running = rdock_admin::start_with(
            settings,
            Arc::new(admin),
            stop_rx.clone(),
            rdock_admin::Sockets::default(),
        )?;
        tracing::info!(address = %crate::run::admin_address(&config.admin.listener), socket = %socket.display(), "admin API listening");
        let running = Arc::new(running);
        let auditor = tokio::spawn(audit_rollouts(events, running.clone(), stop_rx.clone()));
        Some((running, auditor))
    } else {
        None
    };
    tracing::info!(
        cluster = %plane.cluster_id(),
        %address,
        ca_pin = %plane.ca().pin(),
        revision = plane.latest_revision().await,
        "control plane ready"
    );
    let _ = sd_notify::notify(&[sd_notify::NotifyState::Ready]);
    tokio::select! {
        _ = terminate.recv() => {}
        _ = interrupt.recv() => {}
    }
    tracing::info!("stopping the control plane");
    let _ = stop.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), server).await;
    if let Some((running, auditor)) = running {
        // The audit task holds the other reference and ends on the stop signal.
        let _ = tokio::time::timeout(Duration::from_secs(5), auditor).await;
        if let Ok(running) = Arc::try_unwrap(running) {
            running.stopped().await;
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Writes the rollout's automatic steps that need an operator's attention (a halt) and its
/// completion to the audit log, as the control plane (actor `rdock-control`).
async fn audit_rollouts(
    mut events: tokio::sync::broadcast::Receiver<rdock_control::rollout::Event>,
    admin: Arc<rdock_admin::Running>,
    mut stop: watch::Receiver<bool>,
) {
    use rdock_admin::audit::{Event, Outcome};
    use rdock_control::rollout::Event as Step;
    loop {
        let received = tokio::select! {
            _ = stop.changed() => return,
            received = events.recv() => received,
        };
        let event = match received {
            Ok(event) => event,
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
            Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
        };
        let record = match event {
            Step::Halted { revision, halt } => Event {
                resource: Some(format!("revision {revision}")),
                outcome: Outcome::Failed,
                reason: Some(halt.reason),
                ..Event::new("rdock-control", "control", "cluster.rollout.halt")
            },
            Step::Completed { revision } => Event {
                resource: Some(format!("revision {revision}")),
                ..Event::new("rdock-control", "control", "cluster.rollout.complete")
            },
            Step::CanaryChosen { .. } | Step::Soaking { .. } => continue,
        };
        admin.audit(record);
    }
}

/// The lookup a publication is validated with. The control plane publishes `${file:…}` and
/// `${env:…}` as written and each data plane resolves them (ADR-0031): files and Vault read as
/// a placeholder long enough for key-length checks; an environment variable the control plane
/// has set reads as its value (so per-instance values such as listener addresses can be
/// checked with a representative value), any other as the placeholder.
struct Unresolved;

const PLACEHOLDER: &str = "rdock-control-placeholder-0123456789abcdef0123456789abcdef";

impl rdock_config::Lookup for Unresolved {
    fn env(&self, name: &str) -> Result<Option<String>, rdock_config::ReferenceError> {
        Ok(Some(
            std::env::var(name).unwrap_or_else(|_| PLACEHOLDER.to_owned()),
        ))
    }

    fn file(&self, _: &Path) -> Result<String, rdock_config::ReferenceError> {
        Ok(PLACEHOLDER.to_owned())
    }

    fn vault(&self, _: &str) -> Result<String, rdock_config::ReferenceError> {
        Ok(PLACEHOLDER.to_owned())
    }
}

/// Checks a document before it is published: what `rdock validate` refuses is refused here
/// (`Err` with the errors); compile findings that depend on files only data planes have come
/// back as warnings, and a data plane that cannot use the bundle refuses it (NACK).
pub(crate) fn check_document(
    document: &Value,
    plugins: &rdock_plugin_api::Registry,
) -> Result<Vec<Diagnostic>, Vec<Diagnostic>> {
    let mut errors = rdock_model::cluster::bundle_diagnostics(document);
    if document.as_object().is_none_or(serde_json::Map::is_empty) {
        errors.push(Diagnostic::error(
            "",
            "an empty configuration is never published",
        ));
    }
    if !errors.is_empty() {
        return Err(errors);
    }
    let loaded = match rdock_config::load_value(document.clone(), &Unresolved) {
        Ok(loaded) => loaded,
        Err(err) => return Err(vec![crate::validate::load_error(&err)]),
    };
    let (errors, mut warnings): (Vec<Diagnostic>, Vec<Diagnostic>) = loaded
        .diagnostics
        .into_iter()
        .partition(Diagnostic::is_error);
    if !errors.is_empty() {
        return Err(errors);
    }
    let compiled = crate::validate::compile_diagnostics(&loaded.config, plugins);
    for d in compiled {
        if d.is_error() {
            warnings.push(Diagnostic::warning(
                d.path,
                format!("compiled on the control plane: {}", d.message),
            ));
        } else {
            warnings.push(d);
        }
    }
    Ok(warnings)
}

/// The admin API's view of the control plane.
#[derive(Clone)]
struct ControlAdmin {
    plane: Arc<ControlPlane>,
    metrics: Metrics,
    prometheus: bool,
    plugins: Arc<rdock_plugin_api::Registry>,
}

impl ControlAdmin {
    /// Keeps `rdock_control_revision` and `rdock_control_instances` current.
    async fn keep_gauges(self, mut stop: watch::Receiver<bool>) {
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        loop {
            tokio::select! {
                _ = stop.changed() => return,
                _ = tick.tick() => {}
            }
            self.metrics
                .control_revision
                .set(i64::try_from(self.plane.latest_revision().await).unwrap_or(i64::MAX));
            for (state, count) in self.plane.census().await {
                self.metrics
                    .control_instances
                    .with_label_values(&[state])
                    .set(count);
            }
        }
    }
}

#[async_trait]
impl rdock_admin::Control for ControlAdmin {
    fn ready(&self) -> bool {
        true
    }

    fn metrics(&self) -> Option<String> {
        self.prometheus.then(|| self.metrics.render())
    }

    async fn status(&self) -> Value {
        json!({
            "role": "control",
            "version": VERSION,
            "cluster": {
                "id": self.plane.cluster_id(),
                "ca_pin": self.plane.ca().pin(),
                "latest": self.plane.latest_revision().await,
                "instances": self.plane.census().await,
            },
        })
    }

    async fn reload(&self) -> (bool, Value) {
        (
            false,
            json!({ "result": "rejected", "error": "the control plane reads its file at start; restart it to apply changes" }),
        )
    }

    async fn effective_config(&self) -> Value {
        let latest = self.plane.latest_revision().await;
        self.plane
            .document(latest)
            .await
            .ok()
            .flatten()
            .unwrap_or_else(|| json!({}))
    }

    async fn api_config(&self) -> (Value, String) {
        (json!({}), "g0-0".to_owned())
    }

    async fn dry_run(&self, _candidate: Value) -> Result<(bool, Value), String> {
        Err("the control plane has no API objects; validate a document by publishing it".to_owned())
    }

    async fn write_api(&self, _candidate: Value, _if_match: String) -> rdock_admin::ApiWrite {
        rdock_admin::ApiWrite::Invalid(
            "the control plane has no API objects; publish with POST /api/v1/cluster/revisions"
                .to_owned(),
        )
    }

    async fn history(&self) -> Value {
        json!({ "entries": [] })
    }

    async fn history_api(&self, _id: u64) -> Option<Value> {
        None
    }

    async fn backends(&self) -> Value {
        json!({ "services": [] })
    }

    async fn set_drained(&self, _service: String, _backend: String, _drained: bool) -> bool {
        false
    }

    async fn renew_certificate(&self, _name: String) -> bool {
        false
    }

    async fn metrics_summary(&self, _window_seconds: u64) -> Value {
        json!({ "routes": [], "services": [] })
    }

    async fn explain(&self, _request: Value) -> Result<Value, String> {
        Err("the control plane routes no traffic".to_owned())
    }

    async fn caches(&self) -> Value {
        json!({ "stores": [] })
    }

    async fn purge_cache(
        &self,
        _store: String,
        _selector: rdock_admin::CachePurge,
    ) -> rdock_admin::PurgeOutcome {
        rdock_admin::PurgeOutcome::NoStore
    }

    async fn cluster_instances(&self) -> Option<Value> {
        Some(self.plane.instances().await)
    }

    async fn cluster_revoke(&self, instance: String) -> Option<Result<bool, String>> {
        Some(
            self.plane
                .revoke(&instance)
                .await
                .map_err(|e| e.to_string()),
        )
    }

    async fn cluster_create_token(
        &self,
        ttl_seconds: Option<u64>,
        actor: String,
    ) -> Option<Result<Value, String>> {
        let ttl = ttl_seconds.map(Duration::from_secs);
        Some(
            self.plane
                .create_token(ttl, Some(actor))
                .await
                .map(|(token, record)| {
                    json!({
                        "token": token.expose(),
                        "id": record.id,
                        "expires_at": rdock_control::rfc3339(record.expires_at),
                        "ca_pin": self.plane.ca().pin(),
                        "cluster_id": self.plane.cluster_id(),
                    })
                })
                .map_err(|e| e.to_string()),
        )
    }

    async fn cluster_rollout(&self) -> Option<Value> {
        Some(self.plane.rollout().await)
    }

    async fn cluster_rollout_resume(&self, actor: String) -> Option<rdock_admin::RolloutAction> {
        use rdock_admin::RolloutAction;
        Some(match self.plane.resume(&actor).await {
            Ok(view) => RolloutAction::Done(view),
            Err(rdock_control::Error::Conflict(message)) => RolloutAction::Conflict(message),
            Err(e) => RolloutAction::Failed(e.to_string()),
        })
    }

    async fn cluster_rollout_abandon(&self, actor: String) -> Option<rdock_admin::RolloutAction> {
        use rdock_admin::RolloutAction;
        Some(match self.plane.abandon(&actor).await {
            Ok(bundle) => RolloutAction::Done(json!({
                "revision": bundle.revision,
                "sha256": bundle.sha256,
                "published_at": bundle.published_at,
                "rollback_of": bundle.rollback_of,
            })),
            Err(rdock_control::Error::Conflict(message)) => RolloutAction::Conflict(message),
            Err(e) => RolloutAction::Failed(e.to_string()),
        })
    }

    async fn cluster_revisions(&self) -> Option<Value> {
        Some(
            self.plane
                .revisions()
                .await
                .unwrap_or_else(|e| json!({ "error": e.to_string() })),
        )
    }

    async fn cluster_publish(
        &self,
        request: Value,
        actor: String,
    ) -> Option<rdock_admin::ClusterPublish> {
        use rdock_admin::ClusterPublish;
        let (document, rollback_of) = if let Some(revision) = request["rollback_to"].as_u64() {
            match self.plane.document(revision).await {
                Ok(Some(document)) => (document, Some(revision)),
                Ok(None) => {
                    return Some(ClusterPublish::Invalid(format!(
                        "revision {revision} is not kept"
                    )));
                }
                Err(e) => return Some(ClusterPublish::Invalid(e.to_string())),
            }
        } else {
            (request["document"].clone(), None)
        };
        let warnings = match check_document(&document, &self.plugins) {
            Ok(warnings) => warnings,
            Err(errors) => {
                return Some(ClusterPublish::Refused(json!({
                    "error": "the configuration does not validate",
                    "diagnostics": errors,
                })));
            }
        };
        Some(
            match self.plane.publish(document, rollback_of, Some(actor)).await {
                Ok(bundle) => ClusterPublish::Published(json!({
                    "revision": bundle.revision,
                    "sha256": bundle.sha256,
                    "published_at": bundle.published_at,
                    "rollback_of": bundle.rollback_of,
                    "warnings": warnings,
                })),
                Err(rdock_control::Error::Refused(message)) => ClusterPublish::Refused(json!({
                    "error": message,
                    "diagnostics": [],
                })),
                Err(e) => ClusterPublish::Invalid(e.to_string()),
            },
        )
    }
}
