//! The `rdock` command-line interface.

use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Context;
use clap::{Args, Parser, Subcommand, ValueEnum};

mod ctl;
mod engine;
mod hash;
mod providers;
mod run;
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
    /// Print the JSON Schema of rdock.yaml.
    Schema,
    /// Print version and build information.
    Version {
        /// Print as JSON.
        #[arg(long)]
        json: bool,
    },
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
    /// zero-config mode: HTTP on :80, routes from Docker labels.
    #[arg(short, long, env = "RDOCK_CONFIG")]
    config: Option<PathBuf>,
    /// Directory for state (configuration history, last-known-good copy, admin token).
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
    /// Data directory, to find the admin token.
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
