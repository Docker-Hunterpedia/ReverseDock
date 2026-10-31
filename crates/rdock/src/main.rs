//! The `rdock` command-line interface.

use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Context;
use clap::{Args, Parser, Subcommand, ValueEnum};

mod admin_cli;
mod ctl;
mod engine;
mod hash;
mod migrate;
mod providers;
mod run;
mod trust;
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
    /// Ask the running proxy to reload its configuration.
    Reload(CtlArgs),
    /// Show the state of the running proxy.
    Status(StatusArgs),
    /// Exit 0 when the running proxy is ready (for container health checks).
    Healthcheck(CtlArgs),
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
    /// Explain routing decisions.
    #[command(subcommand)]
    Routes(admin_cli::RoutesCommand),
    /// Print the JSON Schema of rdock.yaml.
    Schema,
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
struct StatusArgs {
    #[command(flatten)]
    ctl: CtlArgs,
    /// Print the raw JSON document.
    #[arg(long)]
    json: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Run(args) => run::run(&args),
        Command::Validate(args) => validate::validate(&args),
        Command::Reload(args) => ctl::reload(&args),
        Command::Status(args) => ctl::status(&args),
        Command::Healthcheck(args) => Ok(ctl::healthcheck(&args)),
        Command::Hash(args) => hash::hash(&args),
        Command::Trust(args) => trust::trust(&args),
        Command::Migrate(MigrateCommand::Traefik(args)) => migrate::traefik(&args),
        Command::Audit(AuditCommand::Verify(args)) => audit_verify(&args),
        Command::Audit(AuditCommand::List(args)) => admin_cli::audit_list(&args),
        Command::Config(command) => admin_cli::config(&command),
        Command::Users(command) => admin_cli::users(&command),
        Command::Tokens(command) => admin_cli::tokens(&command),
        Command::Backends(command) => admin_cli::backends(&command),
        Command::Routes(command) => admin_cli::routes(&command),
        Command::Schema => schema().map(|()| ExitCode::SUCCESS),
        Command::Version { json } => version(json).map(|()| ExitCode::SUCCESS),
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

fn version(json: bool) -> anyhow::Result<()> {
    if json {
        let info = serde_json::json!({ "version": VERSION, "commit": COMMIT, "rustc": RUSTC, "target": TARGET });
        print(&format!("{info}\n"))
    } else {
        print(&format!(
            "rdock {VERSION}\ncommit  {COMMIT}\nrustc   {RUSTC}\ntarget  {TARGET}\n"
        ))
    }
}
