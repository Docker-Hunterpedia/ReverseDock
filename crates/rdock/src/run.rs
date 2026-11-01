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
use crate::zero_config::Source;
use crate::{COMMIT, LogFormatArg, RunArgs, VERSION};

/// The socket zero-config mode reads containers from (`providers.docker`'s default).
const DOCKER_SOCKET: &str = "/var/run/docker.sock";

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

/// The key that signs sticky cookies of services without their own secret:
/// `$RDOCK_DATA_DIR/sticky.key` (hex, created on first start, readable by the owner only), so
/// cookies stay valid across restarts.
fn sticky_key(data_dir: &Path) -> anyhow::Result<Vec<u8>> {
    use std::fmt::Write;
    let path = data_dir.join("sticky.key");
    match std::fs::read_to_string(&path) {
        Ok(text) if text.trim().len() >= 32 => Ok(text.trim().as_bytes().to_vec()),
        Ok(_) => anyhow::bail!("the sticky-cookie key {} is too short", path.display()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let key = rdock_proxy::random_key()
                .iter()
                .fold(String::new(), |mut hex, b| {
                    let _ = write!(hex, "{b:02x}");
                    hex
                });
            rdock_config::state::write_atomic(&path, format!("{key}\n").as_bytes())
                .with_context(|| format!("writing the sticky-cookie key {}", path.display()))?;
            Ok(key.into_bytes())
        }
        Err(err) => {
            Err(err).with_context(|| format!("reading the sticky-cookie key {}", path.display()))
        }
    }
}

/// The CLI's Unix socket when `admin.socket` is not set.
pub(crate) fn socket_path(data_dir: &Path) -> PathBuf {
    data_dir.join("admin.sock")
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
    let source = Source::choose(args.config.as_deref(), Path::new(crate::DEFAULT_CONFIG));
    if source == Source::ZeroConfig && !Path::new(DOCKER_SOCKET).exists() {
        eprintln!(
            "error: there is no configuration file at {} and no Docker socket at {DOCKER_SOCKET}\n  \
             hint: write a configuration file (see `rdock validate --help`), pass one with --config, \
             or mount the Docker socket to route labelled containers without one",
            crate::DEFAULT_CONFIG
        );
        return Ok(ExitCode::from(1));
    }
    let metrics = Metrics::new(VERSION, COMMIT).context("registering metrics")?;
    let plane = Arc::new(
        DataPlane::new(metrics, Runtime::empty()).with_sticky_key(sticky_key(&args.data_dir)?),
    );
    let engine = Arc::new(Engine::new(source.clone(), &args.data_dir, plane.clone()));

    tracing::info!(version = VERSION, commit = COMMIT, config = %source.describe(), "starting rdock");
    if source == Source::ZeroConfig {
        tracing::info!(
            "no configuration file: zero-config mode serves labelled Docker containers over HTTPS on :443 \
             with certificates from Let's Encrypt (accepting its terms of service), and redirects :80; \
             write {} to configure more",
            crate::DEFAULT_CONFIG
        );
    }
    engine.restore_snapshots();
    let report = match engine.boot().await {
        Ok(report) => report,
        Err(report) => {
            eprintln!(
                "error: {} cannot be used: {}",
                source.describe(),
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
    let (on_snapshot, mut snapshots) = mpsc::channel(1);
    let boot_config = engine.config().await.unwrap_or_default();
    let provider_tasks =
        crate::providers::start(&engine, &boot_config, &stop.subscribe(), &on_snapshot);
    let mut watcher = (!args.no_watch)
        .then(|| start_watcher(&engine, on_change))
        .flatten();

    engine.set_ready(true);
    let _ = sd_notify::notify(&[sd_notify::NotifyState::Ready]);
    tracing::info!(
        generation = report.generation,
        origin = report.origin.as_str(),
        "rdock is ready"
    );
    loop {
        tokio::select! {
            _ = signals.hangup.recv() => {
                engine.reload("SIGHUP").await;
            }
            Some(()) = changes.recv() => {
                engine.reload_if_changed("file change").await;
                warn_if_providers_changed(&engine, &boot_config).await;
            }
            Some(()) = snapshots.recv() => {
                engine.reload("provider").await;
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
    for task in provider_tasks {
        let _ = task.await;
    }
    if let Some(admin) = admin {
        admin.stopped().await;
    }
    tracing::info!("rdock stopped");
    Ok(ExitCode::SUCCESS)
}

/// Provider settings are read at start; say so when a reload changes them.
async fn warn_if_providers_changed(engine: &Engine, boot: &rdock_model::Config) {
    if let Some(config) = engine.config().await
        && config.providers != boot.providers
    {
        tracing::warn!("`providers` changed; restart rdock to apply the new provider settings");
    }
}

async fn start_admin(
    args: &RunArgs,
    engine: &Arc<Engine>,
    stop: watch::Receiver<bool>,
) -> anyhow::Result<Option<rdock_admin::Running>> {
    let config = engine.config().await.unwrap_or_default();
    let admin = config.admin;
    if !admin.enabled {
        return Ok(None);
    }
    let address = admin_address(&admin.listener);
    let socket = admin
        .socket
        .clone()
        .unwrap_or_else(|| socket_path(&args.data_dir));
    let settings = rdock_admin::Settings {
        address,
        tls: admin.tls.map(|tls| rdock_admin::TlsFiles {
            cert_file: tls.cert_file,
            key_file: tls.key_file,
        }),
        socket: Some(socket.clone()),
        allowed_hosts: admin.allowed_hosts,
        threads: usize::from(admin.threads),
        state_dir: args.data_dir.join("admin"),
        passwords: admin.passwords,
        sessions: admin.sessions,
        mfa: admin.mfa,
        dashboard: admin.dashboard,
        tokens: admin.tokens,
        metrics_unauthenticated_on_loopback: admin.metrics_unauthenticated_on_loopback,
    };
    let running = rdock_admin::start(settings, engine.clone(), stop)?;
    tracing::info!(%address, socket = %socket.display(), "admin API listening");
    Ok(Some(running))
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
