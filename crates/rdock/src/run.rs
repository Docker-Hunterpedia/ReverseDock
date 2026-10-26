//! `rdock run`: start, serve, reload, drain.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::Context;
use rdock_observability::{LogFormat, Metrics, init_logging};
use rdock_proxy::{DataPlane, Runtime};
use tokio::signal::unix::{Signal, SignalKind, signal};
use tokio::sync::{mpsc, watch};

use crate::engine::Engine;
use crate::watch::FileWatcher;
use crate::{COMMIT, LogFormatArg, RunArgs, VERSION};

pub(crate) fn run(args: &RunArgs) -> anyhow::Result<ExitCode> {
    let format = match args.log_format {
        LogFormatArg::Auto => LogFormat::Auto,
        LogFormatArg::Json => LogFormat::Json,
        LogFormatArg::Text => LogFormat::Text,
    };
    init_logging(format, &args.log).map_err(anyhow::Error::msg)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("rdock")
        .build()
        .context("starting the async runtime")?;
    runtime.block_on(serve(args))
}

/// The admin token: `RDOCK_ADMIN_TOKEN`, or `$RDOCK_DATA_DIR/admin/token` (created on first
/// start, readable by the owner only).
pub(crate) fn admin_token(data_dir: &Path, create: bool) -> anyhow::Result<String> {
    if let Ok(token) = std::env::var("RDOCK_ADMIN_TOKEN")
        && !token.is_empty()
    {
        return Ok(token);
    }
    let path = token_path(data_dir);
    match std::fs::read_to_string(&path) {
        Ok(token) if !token.trim().is_empty() => Ok(token.trim().to_owned()),
        Err(err) if !create => {
            Err(err).with_context(|| format!("reading the admin token {}", path.display()))
        }
        _ if !create => anyhow::bail!("the admin token {} is empty", path.display()),
        _ => {
            let token = format!(
                "rdk_{}{}",
                uuid::Uuid::new_v4().simple(),
                uuid::Uuid::new_v4().simple()
            );
            rdock_config::state::write_atomic(&path, format!("{token}\n").as_bytes())
                .with_context(|| format!("writing the admin token {}", path.display()))?;
            tracing::info!(file = %path.display(), "created the admin API token");
            Ok(token)
        }
    }
}

pub(crate) fn token_path(data_dir: &Path) -> PathBuf {
    data_dir.join("admin").join("token")
}

/// Signals rdock reacts to.
struct Signals {
    hangup: Signal,
    terminate: Signal,
    interrupt: Signal,
    quit: Signal,
}

impl Signals {
    fn install() -> anyhow::Result<Self> {
        let install = |kind| signal(kind).context("installing signal handlers");
        Ok(Self {
            hangup: install(SignalKind::hangup())?,
            terminate: install(SignalKind::terminate())?,
            interrupt: install(SignalKind::interrupt())?,
            quit: install(SignalKind::quit())?,
        })
    }
}

async fn serve(args: &RunArgs) -> anyhow::Result<ExitCode> {
    // Before anything else: the default action of SIGHUP would end the process.
    let mut signals = Signals::install()?;
    std::fs::create_dir_all(&args.data_dir).with_context(|| {
        format!(
            "creating the data directory {} (set --data-dir or RDOCK_DATA_DIR)",
            args.data_dir.display()
        )
    })?;
    let metrics = Metrics::new(VERSION, COMMIT).context("registering metrics")?;
    let plane = Arc::new(DataPlane::new(metrics, Runtime::empty()));
    let engine = Arc::new(Engine::new(
        args.config.clone(),
        &args.data_dir,
        plane.clone(),
    ));

    tracing::info!(version = VERSION, commit = COMMIT, config = %args.config.display(), "starting rdock");
    let report = match engine.boot().await {
        Ok(report) => report,
        Err(report) => {
            eprintln!(
                "error: {} cannot be used: {}",
                args.config.display(),
                report.error.as_deref().unwrap_or("unknown error")
            );
            for line in crate::validate::render_diagnostics(&report.diagnostics) {
                eprintln!("{line}");
            }
            return Ok(ExitCode::from(1));
        }
    };
    let (stop, stop_rx) = watch::channel(false);
    let admin = start_admin(args, &engine, stop_rx.clone()).await?;
    let dns = {
        let plane = plane.clone();
        tokio::spawn(async move { plane.refresh_dns(stop_rx).await })
    };
    let (on_change, mut changes) = mpsc::channel(1);
    let mut watcher = (!args.no_watch)
        .then(|| start_watcher(&engine, on_change))
        .flatten();

    engine.set_ready(true);
    let _ = sd_notify::notify(&[sd_notify::NotifyState::Ready]);
    tracing::info!(generation = report.generation, origin = ?report.origin, "rdock is ready");
    loop {
        tokio::select! {
            _ = signals.hangup.recv() => {
                engine.reload("SIGHUP").await;
            }
            Some(()) = changes.recv() => {
                engine.reload("file change").await;
            }
            _ = signals.terminate.recv() => break,
            _ = signals.quit.recv() => break,
            _ = signals.interrupt.recv() => break,
        }
        if let Some(w) = watcher.as_mut() {
            w.set_files(&engine.watched_files());
        }
    }
    shut_down(&engine, &plane, &mut signals).await;
    let _ = stop.send(true);
    let _ = dns.await;
    if let Some(admin) = admin {
        let _ = admin.await;
    }
    tracing::info!("rdock stopped");
    Ok(ExitCode::SUCCESS)
}

async fn start_admin(
    args: &RunArgs,
    engine: &Arc<Engine>,
    stop: watch::Receiver<bool>,
) -> anyhow::Result<Option<tokio::task::JoinHandle<()>>> {
    let config = engine.config().await.unwrap_or_default();
    if !config.admin.enabled {
        return Ok(None);
    }
    let token = admin_token(&args.data_dir, true)?;
    let address = admin_address(&config.admin.listener);
    let handle = rdock_admin::serve(address, token, engine.clone(), stop)
        .with_context(|| format!("cannot listen on the admin address {address}"))?;
    tracing::info!(%address, "admin API listening");
    Ok(Some(handle))
}

fn start_watcher(engine: &Engine, changed: mpsc::Sender<()>) -> Option<FileWatcher> {
    match FileWatcher::start(changed) {
        Ok(mut watcher) => {
            watcher.set_files(&engine.watched_files());
            Some(watcher)
        }
        Err(err) => {
            tracing::warn!(error = %err, "cannot watch files; reload with SIGHUP or `rdock reload`");
            None
        }
    }
}

/// Stops accepting, lets open requests finish, and stops at once on a second signal.
async fn shut_down(engine: &Engine, plane: &DataPlane, signals: &mut Signals) {
    engine.set_ready(false);
    let _ = sd_notify::notify(&[sd_notify::NotifyState::Stopping]);
    let drain = engine.drain_timeout().await;
    tracing::info!(
        drain_seconds = drain.as_secs_f64(),
        "shutting down; open requests may finish"
    );
    tokio::select! {
        () = plane.shutdown(drain) => {}
        _ = signals.terminate.recv() => tracing::warn!("second signal, stopping now"),
        _ = signals.interrupt.recv() => tracing::warn!("second signal, stopping now"),
    }
}

/// The address the admin API binds (`:port` is every IPv4 interface).
pub(crate) fn admin_address(listen: &rdock_model::values::ListenAddress) -> std::net::SocketAddr {
    let ip = listen
        .ip()
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
    std::net::SocketAddr::new(ip, listen.port())
}
