//! `rdock run`: start, serve, reload, drain.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use rdock_observability::{LogFormat, Metrics, init_logging};
use rdock_proxy::{DataPlane, Runtime};
use tokio::signal::unix::{Signal, SignalKind, signal};
use tokio::sync::{mpsc, watch};

use crate::datadir::DataDirLock;
use crate::engine::Engine;
use crate::watch::FileWatcher;
use crate::zero_config::Source;
use crate::{COMMIT, LogFormatArg, RunArgs, VERSION};

/// The socket zero-config mode reads containers from (`providers.docker`'s default).
const DOCKER_SOCKET: &str = "/var/run/docker.sock";

pub(crate) fn run(
    args: &RunArgs,
    plugins: &Arc<rdock_plugin_api::Registry>,
) -> anyhow::Result<ExitCode> {
    let format = match args.log_format {
        LogFormatArg::Auto => LogFormat::Auto,
        LogFormatArg::Json => LogFormat::Json,
        LogFormatArg::Text => LogFormat::Text,
    };
    init_logging(format, &args.log).map_err(anyhow::Error::msg)?;
    let threads = Threads::from_config(args);
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.enable_all().thread_name("rdock");
    if let Some(workers) = threads.settings.worker_threads {
        builder.worker_threads(usize::from(workers));
    }
    if let Some(blocking) = threads.settings.max_blocking_threads {
        builder.max_blocking_threads(usize::from(blocking));
    }
    let runtime = builder.build().context("starting the async runtime")?;
    runtime.block_on(serve(args, plugins, threads))
}

/// The proxy runtime's threads: the `runtime` section as read before the runtime starts, and
/// the values in effect.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Threads {
    /// As configured.
    pub(crate) settings: rdock_model::settings::RuntimeSettings,
    /// Worker threads in effect.
    pub(crate) workers: usize,
    /// Most blocking threads in effect.
    pub(crate) max_blocking: usize,
}

impl Threads {
    /// tokio's default for `max_blocking_threads` (tokio 1.54.1 `Builder` documentation).
    const TOKIO_MAX_BLOCKING: usize = 512;

    /// Reads `runtime` from the configuration file: the runtime is built before the
    /// configuration is applied, so this is the one setting read ahead, and a change needs a
    /// restart. A file that cannot be loaded or has errors leaves the defaults; the start
    /// reports its problems as usual.
    fn from_config(args: &RunArgs) -> Self {
        let source = Source::choose(args.config.as_deref(), Path::new(crate::DEFAULT_CONFIG));
        let settings = match source {
            Source::File(path) => rdock_config::load_file(&path)
                .ok()
                .filter(|loaded| !loaded.has_errors())
                .and_then(|loaded| loaded.config.runtime)
                .unwrap_or_default(),
            Source::ZeroConfig => rdock_model::settings::RuntimeSettings::default(),
        };
        Self::of(settings)
    }

    /// Shows the values in effect as `rdock_runtime_threads`.
    pub(crate) fn record(&self, metrics: &Metrics) {
        for (kind, value) in [
            ("worker", self.workers),
            ("max_blocking", self.max_blocking),
        ] {
            metrics
                .runtime_threads
                .with_label_values(&[kind])
                .set(i64::try_from(value).unwrap_or(i64::MAX));
        }
    }

    fn of(settings: rdock_model::settings::RuntimeSettings) -> Self {
        // tokio's default: `TOKIO_WORKER_THREADS`, else the CPUs the process may use.
        let default_workers = std::env::var("TOKIO_WORKER_THREADS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|&n| n > 0)
            .or_else(|| std::thread::available_parallelism().ok().map(usize::from))
            .unwrap_or(1);
        Self {
            settings,
            workers: settings.worker_threads.map_or(default_workers, usize::from),
            max_blocking: settings
                .max_blocking_threads
                .map_or(Self::TOKIO_MAX_BLOCKING, usize::from),
        }
    }
}

/// Raises the soft open-file limit to the hard one, as Go programs do at start (Go 1.19
/// release notes, August 2022). Every proxied request holds two sockets, and inside a
/// container the soft limit is often 1024 with a hard limit of 524288 (Docker 29.1 with
/// containerd 2.2, measured 2026-11-02), which caps a listener at about 500 requests in
/// flight that the hard limit would allow. macOS refuses more than `OPEN_MAX`.
fn raise_open_file_limit() {
    use nix::sys::resource::{Resource, getrlimit, setrlimit};
    let (soft, hard) = match getrlimit(Resource::RLIMIT_NOFILE) {
        Ok(limits) => limits,
        Err(err) => {
            tracing::warn!(error = %err, "cannot read the open-file limit");
            return;
        }
    };
    let wanted = if cfg!(target_os = "macos") {
        hard.min(10_240)
    } else {
        hard
    };
    if soft >= wanted {
        return;
    }
    match setrlimit(Resource::RLIMIT_NOFILE, wanted, hard) {
        Ok(()) => tracing::info!(from = soft, to = wanted, "raised the open-file limit"),
        Err(err) => {
            tracing::warn!(error = %err, soft, hard, "cannot raise the open-file limit");
        }
    }
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
    /// SIGUSR2: an in-place binary upgrade (the NGINX convention; SIGQUIT keeps meaning stop).
    upgrade: Signal,
}

impl Signals {
    fn install() -> anyhow::Result<Self> {
        let install = |kind| signal(kind).context("installing signal handlers");
        Ok(Self {
            hangup: install(SignalKind::hangup())?,
            terminate: install(SignalKind::terminate())?,
            interrupt: install(SignalKind::interrupt())?,
            quit: install(SignalKind::quit())?,
            upgrade: install(SignalKind::user_defined2())?,
        })
    }
}

/// The data plane with its persistent sticky-cookie key and this process's spool for held
/// request bodies (`spool/<pid>`).
fn data_plane(
    data_dir: &Path,
    metrics: Metrics,
    plugins: &Arc<rdock_plugin_api::Registry>,
) -> anyhow::Result<Arc<DataPlane>> {
    let plane = DataPlane::new(metrics, Runtime::empty())
        .with_sticky_key(sticky_key(data_dir)?)
        .with_plugins(plugins.clone());
    let spool = crate::datadir::spool_dir(data_dir);
    // Disk cache stores without a `path` live under `<data dir>/cache/<name>` (F-WEB-03).
    plane.set_cache_dir(data_dir.join("cache"));
    plane.set_quota_dir(data_dir.join("quota"));
    plane.set_abuse_dir(data_dir.join("abuse"));
    plane
        .open_spool(&spool)
        .with_context(|| format!("opening the spool directory {}", spool.display()))?;
    Ok(Arc::new(plane))
}

/// The tasks that write state other processes could share: the providers (the Kubernetes
/// lease, Secret files), the bind retry, the Vault refresh, and through the engine ACME, the
/// local CA, the Cloudflare range sync and alerts; and the quota counters' files. Stopped while
/// a binary upgrade hands over, so there is always one writer.
pub(crate) struct Writers {
    engine: Arc<Engine>,
    plane: Arc<DataPlane>,
    data_dir: PathBuf,
    on_snapshot: mpsc::Sender<()>,
    stop: Option<watch::Sender<bool>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Writers {
    fn new(
        engine: &Arc<Engine>,
        plane: &Arc<DataPlane>,
        data_dir: &Path,
        on_snapshot: mpsc::Sender<()>,
    ) -> Self {
        Self {
            engine: engine.clone(),
            plane: plane.clone(),
            data_dir: data_dir.to_owned(),
            on_snapshot,
            stop: None,
            tasks: Vec::new(),
        }
    }

    /// Starts them with the applied configuration.
    pub(crate) async fn start(&mut self) {
        if self.stop.is_some() {
            return;
        }
        let config = self.engine.config().await.unwrap_or_default();
        let (stop, stop_rx) = watch::channel(false);
        self.tasks = crate::providers::start(
            &self.engine,
            &config,
            &self.data_dir,
            &stop_rx,
            &self.on_snapshot,
        );
        // Provider listeners left out because their address was in use are retried until they bind.
        self.tasks.push(tokio::spawn(
            self.engine.clone().retry_unbound(stop_rx.clone()),
        ));
        // `${vault:…}` references are read again every `secrets.vault.refresh`.
        self.tasks
            .push(tokio::spawn(self.engine.clone().refresh_vault(stop_rx)));
        self.stop = Some(stop);
        self.plane.pause_quota_writes(false);
        self.engine.resume_background();
    }

    /// Stops them and waits until they have (the Kubernetes provider releases its lease);
    /// writes the quota counters a last time.
    pub(crate) async fn stop(&mut self) {
        self.engine.pause_background();
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(true);
        }
        for task in std::mem::take(&mut self.tasks) {
            let _ = task.await;
        }
        let quotas = self.plane.quotas().clone();
        let _ = tokio::task::spawn_blocking(move || quotas.flush_all()).await;
        let abuse = self.plane.abuse().clone();
        let _ = tokio::task::spawn_blocking(move || abuse.flush_all()).await;
        self.plane.pause_quota_writes(true);
    }
}

/// How the process came to run: started on its own, or handed over by a running one.
enum Start {
    Fresh,
    Inherited(Box<crate::upgrade::inherit::Inherited>),
}

#[allow(clippy::too_many_lines)] // the process's life from start to exit, in order
async fn serve(
    args: &RunArgs,
    plugins: &Arc<rdock_plugin_api::Registry>,
    threads: Threads,
) -> anyhow::Result<ExitCode> {
    // Before anything else: the default action of SIGHUP would end the process.
    let mut signals = Signals::install()?;
    raise_open_file_limit();
    let start = if args.inherit {
        match crate::upgrade::inherit::receive() {
            Ok(inherited) => Start::Inherited(Box::new(inherited)),
            Err(reason) => {
                eprintln!("error: {reason}");
                return Ok(ExitCode::from(1));
            }
        }
    } else {
        Start::Fresh
    };
    std::fs::create_dir_all(&args.data_dir).with_context(|| {
        format!(
            "creating the data directory {} (set --data-dir or RDOCK_DATA_DIR)",
            args.data_dir.display()
        )
    })?;
    // One process per data directory, before anything writes to it (ADR-0031).
    let (lock, mut start) = match start {
        Start::Fresh => match DataDirLock::acquire(&args.data_dir) {
            Ok(lock) => {
                // No live predecessor: what earlier runs left in the spool is nobody's.
                crate::datadir::clean_spool(&args.data_dir);
                (lock, Start::Fresh)
            }
            Err(err) => {
                eprintln!("error: {err}");
                return Ok(ExitCode::from(1));
            }
        },
        Start::Inherited(mut inherited) => {
            let Some(file) = inherited.lock.take() else {
                eprintln!("error: the handover has no data-directory lock");
                return Ok(ExitCode::from(1));
            };
            (
                DataDirLock::adopt(file, &args.data_dir),
                Start::Inherited(inherited),
            )
        }
    };
    if let Err(reason) = crate::datadir::check_format(&args.data_dir) {
        if let Start::Inherited(inherited) = &start {
            let _ = inherited.channel.send(
                &crate::upgrade::wire::Message::Failed {
                    reason: reason.clone(),
                },
                &[],
            );
        }
        eprintln!("error: {reason}");
        return Ok(ExitCode::from(1));
    }
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
    let plane = data_plane(&args.data_dir, metrics, plugins)?;
    let engine = Arc::new(Engine::new(source.clone(), &args.data_dir, plane.clone()));
    engine.set_threads(threads);
    let (upgrade_tx, mut upgrades) = mpsc::channel::<crate::upgrade::Trigger>(1);
    engine.set_upgrades(upgrade_tx.clone());
    tokio::spawn(engine.clone().watch_thresholds());
    if let Start::Inherited(inherited) = &mut start {
        // Built without accepting and without writers until the old process says `go`.
        plane.set_accepting(false);
        engine.pause_background();
        plane.pause_quota_writes(true);
        engine
            .upgrade_generation
            .store(inherited.generation, std::sync::atomic::Ordering::SeqCst);
        plane
            .metrics()
            .upgrade_generation
            .set(i64::try_from(inherited.generation).unwrap_or(i64::MAX));
        if let Err(reason) = inherited.hand_to(&plane) {
            let _ = inherited.channel.send(
                &crate::upgrade::wire::Message::Failed {
                    reason: reason.clone(),
                },
                &[],
            );
            eprintln!("error: {reason}");
            return Ok(ExitCode::from(1));
        }
    }

    log_start(&source, plugins);
    engine.restore_snapshots();
    let report = match engine.boot().await {
        Ok(report) => report,
        Err(report) => {
            let reason = format!(
                "{} cannot be used: {}",
                source.describe(),
                report.error.as_deref().unwrap_or("unknown error")
            );
            if let Start::Inherited(inherited) = &start {
                let _ = inherited.channel.send(
                    &crate::upgrade::wire::Message::Failed {
                        reason: reason.clone(),
                    },
                    &[],
                );
            }
            eprintln!("error: {reason}");
            for line in crate::validate::render_diagnostics(&report.diagnostics) {
                eprintln!("{line}");
            }
            return Ok(ExitCode::from(1));
        }
    };
    let unclaimed = plane.drop_unclaimed();
    if unclaimed > 0 {
        tracing::info!(
            unclaimed,
            "closed handed-over sockets the configuration no longer uses"
        );
    }
    let (stop, stop_rx) = watch::channel(false);
    let (admin_gate, admin_gate_rx) = watch::channel(!matches!(start, Start::Inherited(_)));
    let admin_sockets = match &mut start {
        Start::Inherited(inherited) => rdock_admin::Sockets {
            tcp: inherited.admin_tcp.take(),
            unix: inherited.admin_unix.take(),
            accepting: Some(admin_gate_rx),
        },
        Start::Fresh => rdock_admin::Sockets {
            accepting: Some(admin_gate_rx),
            ..rdock_admin::Sockets::default()
        },
    };
    let admin = start_admin(args, &engine, stop_rx.clone(), admin_sockets).await?;
    let dns = {
        let plane = plane.clone();
        tokio::spawn(async move { plane.refresh_dns(stop_rx).await })
    };
    let (on_change, mut changes) = mpsc::channel(1);
    let (on_snapshot, mut snapshots) = mpsc::channel(1);
    let boot_config = engine.config().await.unwrap_or_default();
    let mut writers = Writers::new(&engine, &plane, &args.data_dir, on_snapshot);
    match start {
        Start::Fresh => writers.start().await,
        Start::Inherited(inherited) => {
            if let Err(reason) = inherited.ready_and_wait().await {
                eprintln!("error: {reason}");
                return Ok(ExitCode::from(1));
            }
            // The old process stopped accepting and its writers: this one takes over.
            for (_, counter) in plane.quotas().counters() {
                counter.reread();
            }
            // Bans the old process wrote up to `go` (it stopped writing then).
            plane.abuse().reread();
            writers.start().await;
            engine.certificates_loaded(Duration::from_secs(5)).await;
            plane.set_accepting(true);
            admin_gate.send_replace(true);
            if let Err(err) = lock.write_pid() {
                tracing::warn!(file = %lock.path().display(), error = %err, "cannot write the pid into the lock file");
            }
            if let Some(admin) = &admin {
                // The old process wrote the audit log until `go`; continue its chain.
                admin.resync_audit();
                admin.audit(rdock_admin::audit::Event {
                    resource: Some(format!(
                        "sha256:{} {}",
                        inherited.binary_sha256,
                        inherited.binary.display()
                    )),
                    reason: Some(format!(
                        "took over from pid {} (generation {})",
                        inherited.previous_pid, inherited.generation
                    )),
                    ..rdock_admin::audit::Event::new(
                        inherited.triggered_by.clone(),
                        if inherited.method == "signal" {
                            "signal"
                        } else {
                            "socket"
                        },
                        "upgrade",
                    )
                });
            }
            let previous = inherited.previous_pid;
            if let Err(reason) = inherited.serving(plane.clone()) {
                tracing::warn!(error = %reason, "cannot follow the old process's drain");
            }
            tracing::info!(
                previous_pid = previous,
                "took over from the previous process"
            );
        }
    }
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
    let mut draining = None;
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
            _ = signals.upgrade.recv() => {
                let trigger = crate::upgrade::Trigger { binary: None, actor: "signal".into(), reply: None };
                let _ = upgrade_tx.try_send(trigger);
            }
            Some(mut trigger) = upgrades.recv() => {
                let outcome = crate::upgrade::perform(
                    crate::upgrade::Context {
                        args,
                        source: &source,
                        engine: &engine,
                        plane: &plane,
                        admin: admin.as_ref(),
                        admin_gate: &admin_gate,
                        lock: &lock,
                        writers: &mut writers,
                    },
                    &trigger,
                )
                .await;
                match trigger.reply.take() {
                    Some(reply) => {
                        let _ = reply.send(outcome.to_admin());
                    }
                    // A signal has no request to record it; this process is still the audit
                    // log's writer when the upgrade did not happen.
                    None => audit_signal_failure(admin.as_ref(), &outcome),
                }
                if let crate::upgrade::Outcome::Serving(handover, _) = outcome {
                    draining = Some(handover);
                    break;
                }
                // Refused requests that queued meanwhile are answered as refused.
                while let Ok(mut queued) = upgrades.try_recv() {
                    if let Some(reply) = queued.reply.take() {
                        let _ = reply.send(rdock_admin::UpgradeOutcome::Refused(
                            serde_json::json!({ "error": "another upgrade was in progress" }),
                        ));
                    }
                }
            }
            _ = signals.terminate.recv() => break,
            _ = signals.quit.recv() => break,
            _ = signals.interrupt.recv() => break,
        }
        if let Some(w) = watcher.as_mut() {
            w.set_files(&engine.watched_files());
        }
    }
    drop(watcher);
    if let Some(handover) = draining {
        // Another process serves now: drain this one's connections and exit. Its writers are
        // stopped; the quota counts it takes while draining go to the new process.
        engine.set_ready(false);
        tokio::select! {
            () = crate::upgrade::drain(&plane, handover) => {}
            _ = signals.terminate.recv() => tracing::warn!("signal while draining; stopping now"),
            _ = signals.interrupt.recv() => tracing::warn!("signal while draining; stopping now"),
        }
    } else {
        shut_down(&engine, &plane, &mut signals).await;
        writers.stop().await;
    }
    let _ = stop.send(true);
    let _ = dns.await;
    if let Some(admin) = admin {
        admin.stopped().await;
    }
    crate::datadir::remove_own_spool(&args.data_dir);
    drop(lock);
    tracing::info!("rdock stopped");
    Ok(ExitCode::SUCCESS)
}

/// Records a refused or failed upgrade asked for by `SIGUSR2` in the audit log.
fn audit_signal_failure(admin: Option<&rdock_admin::Running>, outcome: &crate::upgrade::Outcome) {
    let document = match outcome {
        crate::upgrade::Outcome::Serving(..) => return,
        crate::upgrade::Outcome::Refused(d) | crate::upgrade::Outcome::Failed(d) => d,
    };
    if let Some(admin) = admin {
        admin.audit(rdock_admin::audit::Event {
            outcome: rdock_admin::audit::Outcome::Failed,
            resource: document["sha256"].as_str().map(|h| format!("sha256:{h}")),
            reason: document["error"].as_str().map(str::to_owned),
            ..rdock_admin::audit::Event::new("signal", "signal", "upgrade")
        });
    }
}

fn log_start(source: &Source, plugins: &rdock_plugin_api::Registry) {
    if !plugins.is_empty() {
        let names: Vec<&str> = plugins.names().collect();
        tracing::info!(plugins = %names.join(", "), api = rdock_plugin_api::API_VERSION, "native plugins compiled in");
    }
    tracing::info!(version = VERSION, commit = COMMIT, config = %source.describe(), "starting rdock");
    if *source == Source::ZeroConfig {
        tracing::info!(
            "no configuration file: zero-config mode serves labelled Docker containers over HTTPS on :443 \
             with certificates from Let's Encrypt (accepting its terms of service), and redirects :80; \
             write {} to configure more",
            crate::DEFAULT_CONFIG
        );
    }
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
    sockets: rdock_admin::Sockets,
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
        trust_forwarded_on_loopback: admin.trust_forwarded_on_loopback,
        audit_dir: args.data_dir.join("audit"),
        audit: admin.audit,
        api_writes: admin.api_writes,
        feeds: Some(engine.feeds()),
    };
    let running = rdock_admin::start_with(settings, engine.clone(), stop, sockets)?;
    #[cfg(feature = "fault-injection")]
    if let Some(fault) = rdock_admin::fault::from_env()
        && fault.kind == rdock_admin::fault::Kind::WriteLock
    {
        let engine = engine.clone();
        tokio::spawn(async move { engine.hold_api_writes(fault).await });
    }
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

#[cfg(test)]
mod tests {
    use nix::sys::resource::{Resource, getrlimit};

    #[test]
    fn the_soft_open_file_limit_reaches_the_hard_one() {
        super::raise_open_file_limit();
        let (soft, hard) = getrlimit(Resource::RLIMIT_NOFILE).unwrap();
        let wanted = if cfg!(target_os = "macos") {
            hard.min(10_240)
        } else {
            hard
        };
        assert_eq!(soft, wanted);
    }
}
