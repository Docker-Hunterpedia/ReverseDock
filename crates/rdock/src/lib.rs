//! ReverseDock as a library: the whole `rdock` command-line interface behind one function, so
//! that a binary with native plugins is a few lines (F-EXT-02, ADR-0030).
//!
//! ```no_run
//! use std::process::ExitCode;
//!
//! fn main() -> ExitCode {
//!     let registry = rdock::Registry::new();
//!     // .plugin("header_rewrite", header_rewrite::factory())
//!     rdock::run(registry)
//! }
//! ```
//!
//! Every subcommand (`run`, `validate`, `schema`, `version`…) behaves exactly as in the stock
//! binary, which is this same call with an empty registry; the registry's plugins are
//! available to `type: plugin` middlewares and to validation. Plugins are written against
//! [`plugin_api`] (the `rdock-plugin-api` crate) only.
//!
//! With the default feature `mimalloc` the library also sets mimalloc as the global allocator,
//! as the stock binary does; turn the feature off to choose your own. The `jemalloc` feature
//! (off by default) sets jemalloc instead, for comparisons (H-PERF-06).

use std::ffi::OsString;
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Context;
use clap::{Args, Parser, Subcommand, ValueEnum};

/// musl's malloc took a global lock on every allocation and mapped and unmapped memory for
/// the 64 KiB connection buffers, which was about a quarter of the CPU per request on 2 CPUs
/// (perf, 2026-11-02, #93). mimalloc keeps freed memory per thread and reuses it.
#[cfg(all(
    feature = "mimalloc",
    not(feature = "jemalloc"),
    not(feature = "alloc-count")
))]
#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// The comparison allocator of H-PERF-06, behind the `jemalloc` feature (off by default and in
/// release builds). It wins over mimalloc when both features are on.
#[cfg(all(feature = "jemalloc", not(feature = "alloc-count")))]
#[global_allocator]
static ALLOCATOR: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[cfg(feature = "alloc-count")]
mod alloc_count;

pub use rdock_plugin_api as plugin_api;
pub use rdock_plugin_api::Registry;

mod admin_cli;
mod cluster;
mod control;
mod ctl;
mod datadir;
mod engine;
mod hash;
mod migrate;
mod providers;
mod run;
mod trust;
mod upgrade;
mod validate;
mod watch;
mod zero_config;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const COMMIT: &str = env!("RDOCK_BUILD_COMMIT");
const RUSTC: &str = env!("RDOCK_BUILD_RUSTC");
const TARGET: &str = env!("RDOCK_BUILD_TARGET");

/// Default configuration file.
const DEFAULT_CONFIG: &str = "/etc/rdock/rdock.yaml";
/// Default data directory.
const DEFAULT_DATA_DIR: &str = "/var/lib/rdock";

/// ReverseDock: one reverse proxy for every dock.
#[derive(Parser)]
#[command(name = "rdock", version, about, propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the proxy.
    Run(RunArgs),
    /// Validate configuration files without starting the proxy.
    Validate(ValidateArgs),
    /// Run a cluster's control plane, and publish, list and roll back configurations, enrol and
    /// revoke data planes through it.
    #[command(subcommand)]
    Control(control::ControlCommand),
    /// Ask the running proxy to reload its configuration.
    Reload(CtlArgs),
    /// Show the state of the running proxy.
    Status(StatusArgs),
    /// Exit 0 when the running proxy is ready (for container health checks).
    Healthcheck(CtlArgs),
    /// Replace the running binary without dropping connections (Linux; over the admin Unix
    /// socket only). The running process hands its listeners to the new binary and drains.
    Upgrade(UpgradeArgs),
    /// Create an argon2id password hash for `basic_auth` (reads the password from stdin).
    Hash(HashArgs),
    /// Install the local CA's root (for localhost and private names) into the system trust
    /// stores, or remove it with --uninstall.
    Trust(TrustArgs),
    /// Turn another proxy's configuration into rdock.yaml.
    #[command(subcommand)]
    Migrate(MigrateCommand),
    /// Work with the admin audit log.
    #[command(subcommand)]
    Audit(AuditCommand),
    /// The configuration history, diffs and rollback of the API provider.
    #[command(subcommand)]
    Config(admin_cli::ConfigCommand),
    /// Manage dashboard users.
    #[command(subcommand)]
    Users(admin_cli::UsersCommand),
    /// Manage API tokens.
    #[command(subcommand)]
    Tokens(admin_cli::TokensCommand),
    /// Show backends and drain them.
    #[command(subcommand)]
    Backends(admin_cli::BackendsCommand),
    /// Show HTTP cache stores and purge them (this instance only).
    #[command(subcommand)]
    Cache(admin_cli::CacheCommand),
    /// Manage consumers (API clients) and their quota counters.
    #[command(subcommand)]
    Consumers(admin_cli::ConsumersCommand),
    /// List and lift the bans of `abuse` middlewares on this instance.
    #[command(subcommand)]
    Bans(admin_cli::BansCommand),
    /// Mint, revoke and hash consumers' API keys.
    #[command(subcommand)]
    Keys(admin_cli::KeysCommand),
    /// Explain routing decisions.
    #[command(subcommand)]
    Routes(admin_cli::RoutesCommand),
    /// Print the JSON Schema of rdock.yaml.
    Schema {
        /// Print the OpenAPI 3.1 document of the admin API instead.
        #[arg(long)]
        openapi: bool,
    },
    /// Print version and build information.
    Version {
        /// Print as JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum AuditCommand {
    /// Check that no audit record was changed or removed (the SHA-256 chain).
    Verify(AuditArgs),
    /// Show recent records from the running proxy.
    List(admin_cli::AuditList),
}

#[derive(Args)]
struct AuditArgs {
    /// Data directory holding `audit/`.
    #[arg(long, env = "RDOCK_DATA_DIR", default_value = DEFAULT_DATA_DIR)]
    data_dir: PathBuf,
}

#[derive(Subcommand)]
enum MigrateCommand {
    /// Traefik labels (a Compose file) or a Traefik dynamic configuration → rdock.yaml.
    Traefik(MigrateTraefikArgs),
}

#[derive(Args)]
struct MigrateTraefikArgs {
    /// Compose file or Traefik dynamic configuration; `-` reads standard input.
    input: PathBuf,
    /// Migrate Compose services without `traefik.enable`, as Traefik's `exposedByDefault` does.
    #[arg(long)]
    expose_by_default: bool,
    /// Write the result to this file instead of standard output.
    #[arg(short, long)]
    output: Option<PathBuf>,
}

#[derive(Args)]
struct TrustArgs {
    /// Remove the root from the trust stores instead of installing it.
    #[arg(long)]
    uninstall: bool,
    /// Data directory holding the local CA (`pki/`); the CA is created there when missing.
    #[arg(long, env = "RDOCK_DATA_DIR", default_value = DEFAULT_DATA_DIR)]
    data_dir: PathBuf,
}

#[derive(Args)]
struct HashArgs {
    /// Print a complete `user:hash` entry for `basic_auth.users`.
    #[arg(long)]
    user: Option<String>,
}

#[derive(Args)]
struct RunArgs {
    /// Configuration file [default: /etc/rdock/rdock.yaml]. Without one, rdock runs in
    /// zero-config mode: HTTPS on :443 with automatic certificates, :80 redirecting, routes from
    /// Docker labels.
    #[arg(short, long, env = "RDOCK_CONFIG")]
    config: Option<PathBuf>,
    /// Directory for state (configuration history, last-known-good copy, admin token,
    /// certificates and the local CA).
    #[arg(long, env = "RDOCK_DATA_DIR", default_value = DEFAULT_DATA_DIR)]
    data_dir: PathBuf,
    /// Do not reload when the configuration or referenced files change.
    #[arg(long)]
    no_watch: bool,
    /// Log filter, e.g. `info` or `info,rdock_proxy=debug`.
    #[arg(long, env = "RDOCK_LOG", default_value = "info")]
    log: String,
    /// Format of the application log.
    #[arg(long, env = "RDOCK_LOG_FORMAT", value_enum, default_value_t = LogFormatArg::Auto)]
    log_format: LogFormatArg,
    /// Internal (binary upgrade): take over the listening sockets a running rdock hands over on
    /// standard input. Started by `rdock upgrade`; not for use by hand.
    #[arg(long, hide = true)]
    inherit: bool,
}

#[derive(Clone, Copy, ValueEnum)]
enum LogFormatArg {
    /// JSON unless standard error is a terminal.
    Auto,
    /// JSON lines.
    Json,
    /// Text.
    Text,
}

#[derive(Args)]
struct ValidateArgs {
    /// Configuration files (YAML, or JSON with a .json extension).
    #[arg(required = true)]
    files: Vec<PathBuf>,
    /// Treat warnings as errors.
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

#[derive(Args)]
struct CtlArgs {
    /// Admin listener of the running proxy. Read from the configuration file when omitted.
    #[arg(long, env = "RDOCK_ADMIN")]
    admin: Option<SocketAddr>,
    /// Configuration file, to find the admin listener.
    #[arg(short, long, env = "RDOCK_CONFIG", default_value = DEFAULT_CONFIG)]
    config: PathBuf,
    /// Data directory, to find the admin socket.
    #[arg(long, env = "RDOCK_DATA_DIR", default_value = DEFAULT_DATA_DIR)]
    data_dir: PathBuf,
}

#[derive(Args)]
struct UpgradeArgs {
    /// The new binary [default: `upgrade.binary`, /usr/local/bin/rdock].
    #[arg(long)]
    binary: Option<PathBuf>,
    /// Data directory, to find the admin socket.
    #[arg(long, env = "RDOCK_DATA_DIR", default_value = DEFAULT_DATA_DIR)]
    data_dir: PathBuf,
    /// Configuration file, to find `admin.socket` when it is set.
    #[arg(short, long, env = "RDOCK_CONFIG", default_value = DEFAULT_CONFIG)]
    config: PathBuf,
}

#[derive(Args)]
struct StatusArgs {
    #[command(flatten)]
    ctl: CtlArgs,
    /// Print the raw JSON document.
    #[arg(long)]
    json: bool,
}

/// Runs the `rdock` command line with the process's arguments and `registry`'s plugins, and
/// returns the exit code (`0` success, `1` a failed check such as invalid configuration, `2`
/// an error). An invalid registry (a duplicate or malformed plugin name) is reported and gives
/// `2` before anything else happens.
#[must_use]
pub fn run(registry: Registry) -> ExitCode {
    // clap reads the process's arguments itself.
    run_parsed(registry, Cli::try_parse)
}

/// Like [`run`], with explicit arguments (the first is the program name), e.g. for tests.
#[must_use]
pub fn run_with_args<I, T>(registry: Registry, args: I) -> ExitCode
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    run_parsed(registry, || Cli::try_parse_from(args))
}

/// Checks the registry, parses the command line with `parse` and runs the command.
fn run_parsed(registry: Registry, parse: impl FnOnce() -> Result<Cli, clap::Error>) -> ExitCode {
    if let Err(err) = registry.check() {
        eprintln!("error: the plugin registry is invalid: {err}");
        return ExitCode::from(2);
    }
    let cli = match parse() {
        Ok(cli) => cli,
        Err(err) => {
            // `--help` and `--version` print and succeed; usage errors exit 2.
            let _ = err.print();
            return if err.use_stderr() {
                ExitCode::from(2)
            } else {
                ExitCode::SUCCESS
            };
        }
    };
    let plugins = std::sync::Arc::new(registry);
    #[cfg(feature = "alloc-count")]
    if matches!(cli.command, Command::Run(_)) {
        alloc_count::serve_from_env();
    }
    let result = match cli.command {
        Command::Run(args) => run::run(&args, &plugins),
        Command::Validate(args) => validate::validate(&args, &plugins),
        Command::Control(command) => control::control(&command, &plugins),
        Command::Reload(args) => ctl::reload(&args),
        Command::Status(args) => ctl::status(&args),
        Command::Healthcheck(args) => Ok(ctl::healthcheck(&args)),
        Command::Upgrade(args) => ctl::upgrade(&args),
        Command::Hash(args) => hash::hash(&args),
        Command::Trust(args) => trust::trust(&args),
        Command::Migrate(MigrateCommand::Traefik(args)) => migrate::traefik(&args),
        Command::Audit(AuditCommand::Verify(args)) => audit_verify(&args),
        Command::Audit(AuditCommand::List(args)) => admin_cli::audit_list(&args),
        Command::Config(command) => admin_cli::config(&command),
        Command::Users(command) => admin_cli::users(&command),
        Command::Tokens(command) => admin_cli::tokens(&command),
        Command::Backends(command) => admin_cli::backends(&command),
        Command::Cache(command) => admin_cli::cache(&command),
        Command::Consumers(command) => admin_cli::consumers(&command),
        Command::Bans(command) => admin_cli::bans(&command),
        Command::Keys(command) => admin_cli::keys(&command),
        Command::Routes(command) => admin_cli::routes(&command),
        Command::Schema { openapi: false } => schema().map(|()| ExitCode::SUCCESS),
        Command::Schema { openapi: true } => {
            print(rdock_admin::openapi_json()).map(|()| ExitCode::SUCCESS)
        }
        Command::Version { json } => version(json, &plugins).map(|()| ExitCode::SUCCESS),
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

/// `rdock audit verify`: exit 0 when the chain holds, 1 at the first broken link.
fn audit_verify(args: &AuditArgs) -> anyhow::Result<ExitCode> {
    use rdock_admin::audit::{Verdict, verify};
    let dir = args.data_dir.join("audit");
    match verify(&dir).with_context(|| format!("reading the audit log in {}", dir.display()))? {
        Verdict::Intact { records, files } => {
            println!("audit log intact: {records} records in {files} files");
            Ok(ExitCode::SUCCESS)
        }
        Verdict::Broken { file, line, reason } => {
            eprintln!("audit log broken at {}:{line}: {reason}", file.display());
            Ok(ExitCode::FAILURE)
        }
    }
}

fn schema() -> anyhow::Result<()> {
    print(&rdock_model::json_schema_string().context("serialising the JSON Schema")?)
}

fn version(json: bool, plugins: &Registry) -> anyhow::Result<()> {
    let names: Vec<&str> = plugins.names().collect();
    let api = rdock_plugin_api::API_VERSION;
    // The WASM host ABI, when this build includes it (`wasm` feature, experimental).
    let wasm_abi = rdock_middleware::wasm::ENABLED.then_some(rdock_wasm::ABI_VERSION);
    if json {
        // HTTP/3 ingress, when this build includes it (`http3` feature, experimental).
        let http3 = rdock_proxy::http3::ENABLED;
        let info = serde_json::json!({ "version": VERSION, "commit": COMMIT, "rustc": RUSTC, "target": TARGET, "plugin_api": api, "plugins": names, "wasm_abi": wasm_abi, "http3": http3 });
        print(&format!("{info}\n"))
    } else {
        let plugins = if names.is_empty() {
            "none".to_owned()
        } else {
            names.join(", ")
        };
        let wasm = wasm_abi.map_or_else(
            || "not in this build".to_owned(),
            |abi| format!("ABI {abi} (experimental)"),
        );
        let http3 = if rdock_proxy::http3::ENABLED {
            "quinn and h3 (experimental)"
        } else {
            "not in this build"
        };
        print(&format!(
            "rdock {VERSION}\ncommit  {COMMIT}\nrustc   {RUSTC}\ntarget  {TARGET}\nplugin API {api}; plugins: {plugins}\nWASM plugins: {wasm}\nHTTP/3: {http3}\n"
        ))
    }
}
