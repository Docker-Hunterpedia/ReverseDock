//! Per-request cost of one proxied HTTP/1.1 request through a locally built `rdock`.
//!
//! `rdock-perreq measure` starts the binary given with `--rdock` on a generated configuration
//! (no Docker), in front of a backend in this process that answers every request with 1 KiB.
//! After a warm-up it sends N and then 2N requests over the same kept-alive connections and
//! reports the difference divided by N, so start-up and anything that does not grow with the
//! request count cancel out:
//!
//! - `--measure allocs`: allocations per request, read from a binary built with the bench-only
//!   `alloc-count` feature (`RDOCK_ALLOC_COUNT_SOCKET`). Exact.
//! - `--measure syscalls`: system calls per request, from `strace -c -f` attached to the
//!   process for each phase. Exact for the traced window; timers that fire by time, not by
//!   request, are included in both phases and mostly cancel.
//! - `--measure cpu`: CPU time per request, the sum of `/proc/<pid>/task/*/schedstat` (time on
//!   a CPU, in nanoseconds) over all threads. Relative: compare builds on the same machine,
//!   interleaved (see `run.sh`).
//!
//! `rdock-perreq tail` is the TLS-tail experiment of issue 181 step 4: a few established
//! connections send requests at a steady rate while a burst of new TLS connections arrives,
//! all at once or ramped; it reports the latency of the established connections' requests.
//!
//! `rdock-perreq scale` is the CPU-scaling measurement (ADR-0031 step 9): peak throughput and
//! CPU time per request of an `rdock` pinned to a number of CPUs, by closed-loop saturation.
//!
//! See `benchmarks/README.md`, "Per-request cost without Docker" and "CPU scaling".

// A measurement tool: counts and times become ratios and averages in floating point, where
// precision far beyond what is measured does not matter.
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::many_single_char_names,
    clippy::too_many_lines,
    clippy::format_push_string
)]

mod scale;
mod tail;

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Per-request cost of ReverseDock.
#[derive(Parser)]
#[command(name = "rdock-perreq")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Allocations, system calls or CPU time per request.
    Measure(MeasureArgs),
    /// Latency of established connections during a burst of TLS handshakes.
    Tail(tail::TailArgs),
    /// The burst of new TLS connections for `tail` (started by it).
    Burst(tail::BurstArgs),
    /// Peak throughput and CPU per request of rdock pinned to a number of CPUs.
    Scale(scale::ScaleArgs),
}

/// What `measure` reads.
#[derive(Clone, Copy, ValueEnum, PartialEq, Eq)]
enum Measure {
    Allocs,
    Syscalls,
    Cpu,
}

/// The setup shared by `measure` and `tail`.
#[derive(Args, Clone)]
pub(crate) struct LabArgs {
    /// The `rdock` binary to run.
    #[arg(long)]
    rdock: PathBuf,
    /// Number of routes, one host each (`site<i>.test`), all to the same service.
    #[arg(long, default_value_t = 1)]
    routes: usize,
    /// Serve HTTPS (a P-256 certificate from a throw-away CA).
    #[arg(long)]
    tls: bool,
    /// Turn the admin API on (on a loopback port); off as in the benchmark configurations.
    #[arg(long)]
    admin: bool,
    /// CPUs for rdock, as `taskset -c` takes them (e.g. `0,1`).
    #[arg(long)]
    cpus: Option<String>,
    /// Bound on concurrent TLS handshakes on the listener (`tls.max_handshakes`); unset by default.
    #[arg(long)]
    max_handshakes: Option<u32>,
    /// YAML mapping entries added to the listener, e.g. `socket: { backlog: 128 }`.
    #[arg(long)]
    listener_extra: Option<String>,
    /// YAML added at the top level of the configuration, e.g. `runtime: { worker_threads: 2 }`.
    #[arg(long)]
    config_extra: Option<String>,
}

#[derive(Args)]
struct MeasureArgs {
    #[command(flatten)]
    lab: LabArgs,
    /// Request headers: 3 (`Host`, `User-Agent`, `Accept`, as k6 sends) or 20 (a browser's).
    #[arg(long, default_value_t = 3)]
    headers: usize,
    /// Requests in the first phase; the second sends twice as many.
    #[arg(long, default_value_t = 2000)]
    n: usize,
    /// Kept-alive client connections.
    #[arg(long, default_value_t = 4)]
    conns: usize,
    #[arg(long, value_enum)]
    measure: Measure,
    /// A name for the variant, copied into the output.
    #[arg(long, default_value = "")]
    label: String,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    // The tool's own threads: two, except for `scale`, which sizes them to the CPUs it may use.
    let threads = match &cli.command {
        Cmd::Scale(args) => args.tool_threads,
        _ => 2,
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(threads)
        .enable_all()
        .build()?;
    match cli.command {
        Cmd::Measure(args) => runtime.block_on(measure(args)),
        Cmd::Tail(args) => runtime.block_on(tail::run(args)),
        Cmd::Burst(args) => runtime.block_on(tail::burst(args)),
        Cmd::Scale(args) => runtime.block_on(scale::run(args)),
    }
}

/// A running rdock in front of the in-process backend.
pub(crate) struct Lab {
    child: Child,
    dir: tempfile::TempDir,
    pub(crate) proxy: SocketAddr,
    pub(crate) tls: Option<Arc<rustls::ClientConfig>>,
    alloc_socket: PathBuf,
    pub(crate) routes: usize,
}

impl Drop for Lab {
    fn drop(&mut self) {
        let _ = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status();
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

const BODY_LEN: usize = 1024;

/// Answers every request with 1 KiB, keeping the connection alive.
async fn backend() -> anyhow::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {BODY_LEN}\r\n\r\n"
    )
    .into_bytes();
    response.extend(std::iter::repeat_n(b'x', BODY_LEN));
    let response: Arc<[u8]> = response.into();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let _ = stream.set_nodelay(true);
            let response = response.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16 * 1024];
                let mut filled = 0;
                loop {
                    let Ok(read) = stream.read(&mut buf[filled..]).await else {
                        return;
                    };
                    if read == 0 {
                        return;
                    }
                    filled += read;
                    // Requests carry no body; answer each complete head.
                    while let Some(end) = find(&buf[..filled], b"\r\n\r\n") {
                        if stream.write_all(&response).await.is_err() {
                            return;
                        }
                        buf.copy_within(end + 4..filled, 0);
                        filled -= end + 4;
                    }
                    if filled == buf.len() {
                        return;
                    }
                }
            });
        }
    });
    Ok(addr)
}

pub(crate) fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// A free loopback port (bound and released; nothing else on this machine races for it in a
/// measurement).
fn free_port() -> anyhow::Result<u16> {
    Ok(std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port())
}

impl Lab {
    pub(crate) async fn start(args: &LabArgs) -> anyhow::Result<Self> {
        let backend = backend().await?;
        let dir = tempfile::tempdir()?;
        let port = free_port()?;
        let proxy: SocketAddr = format!("127.0.0.1:{port}").parse()?;
        let mut config = String::new();
        let extra = args
            .listener_extra
            .as_deref()
            .map(|e| format!(", {e}"))
            .unwrap_or_default();
        let tls = if args.tls {
            let ca = rdock_testkit::certs::TestCa::new();
            let issued = ca.issue(dir.path(), "bench", &["site0.test"]);
            let limit = args
                .max_handshakes
                .map(|n| format!(" max_handshakes: {n} "))
                .unwrap_or_default();
            config.push_str(&format!(
                "listeners:\n  web: {{ address: \"{proxy}\", tls: {{{limit}}}{extra} }}\n\
                 certificates:\n  bench: {{ cert_file: \"{}\", key_file: \"{}\" }}\n",
                issued.cert.display(),
                issued.key.display()
            ));
            Some(ca.client_config(&[b"http/1.1"]))
        } else {
            config.push_str(&format!(
                "listeners:\n  web: {{ address: \"{proxy}\"{extra} }}\n"
            ));
            None
        };
        config.push_str("defaults: { listeners: [web], tls: off }\nroutes:\n");
        let route_tls = if args.tls {
            ", tls: { certificate: bench }"
        } else {
            ""
        };
        for i in 0..args.routes {
            config.push_str(&format!(
                "  r{i}: {{ match: \"Host(`site{i}.test`)\", service: app{route_tls} }}\n"
            ));
        }
        config.push_str(&format!(
            "services:\n  app:\n    backends: [{{ address: \"{backend}\" }}]\n\
             observability:\n  access_log: {{ format: off }}\n"
        ));
        if args.admin {
            let admin = free_port()?;
            config.push_str(&format!("admin: {{ listener: \"127.0.0.1:{admin}\" }}\n"));
        } else {
            config.push_str("admin: { enabled: false }\n");
        }
        if let Some(extra) = &args.config_extra {
            config.push_str(extra);
            config.push('\n');
        }
        let config_path = dir.path().join("rdock.yaml");
        std::fs::write(&config_path, config)?;
        let alloc_socket = dir.path().join("alloc.sock");
        let mut command = match &args.cpus {
            Some(cpus) => {
                let mut c = Command::new("taskset");
                c.args(["-c", cpus]).arg(&args.rdock);
                c
            }
            None => Command::new(&args.rdock),
        };
        command
            .args(["run", "--log-format", "json", "--log", "warn", "-c"])
            .arg(&config_path)
            .arg("--data-dir")
            .arg(dir.path().join("data"))
            .env("RDOCK_ALLOC_COUNT_SOCKET", &alloc_socket)
            .stdin(Stdio::null())
            .stdout(std::fs::File::create(dir.path().join("access.log"))?)
            .stderr(std::fs::File::create(dir.path().join("rdock.log"))?);
        let child = command
            .spawn()
            .with_context(|| format!("starting {}", args.rdock.display()))?;
        let mut lab = Self {
            child,
            dir,
            proxy,
            tls,
            alloc_socket,
            routes: args.routes,
        };
        lab.wait_ready().await?;
        Ok(lab)
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("rdock.log")).unwrap_or_default()
    }

    async fn wait_ready(&mut self) -> anyhow::Result<()> {
        let started = Instant::now();
        let request = request_bytes("site0.test", 3);
        let mut last = String::new();
        while started.elapsed() < Duration::from_secs(300) {
            if let Ok(Some(status)) = self.child.try_wait() {
                bail!("rdock exited with {status}:\n{}", self.log());
            }
            let attempt = async {
                let mut conn = self.connect("site0.test").await?;
                conn.send(&request).await
            };
            match tokio::time::timeout(Duration::from_secs(5), attempt).await {
                Ok(Ok(200)) => return Ok(()),
                Ok(Ok(status)) => last = format!("status {status}"),
                Ok(Err(err)) => last = format!("{err:#}"),
                Err(_) => last = "timed out".into(),
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        bail!(
            "rdock did not answer in time (last: {last}):\n{}",
            self.log()
        )
    }

    pub(crate) fn pid(&self) -> u32 {
        self.child.id()
    }

    /// A new client connection, through TLS when the lab serves HTTPS.
    pub(crate) async fn connect(&self, server_name: &str) -> anyhow::Result<Conn> {
        let tcp = TcpStream::connect(self.proxy).await?;
        tcp.set_nodelay(true)?;
        let io: Box<dyn Io> = match &self.tls {
            Some(config) => {
                let name = rustls_pki_types::ServerName::try_from(server_name.to_owned())?;
                let stream = tokio_rustls::TlsConnector::from(config.clone())
                    .connect(name, tcp)
                    .await?;
                Box::new(stream)
            }
            None => Box::new(tcp),
        };
        Ok(Conn {
            io,
            buf: Vec::with_capacity(8 * 1024),
        })
    }

    /// The allocation counters of an `alloc-count` build.
    fn allocs(&self) -> anyhow::Result<[u64; 4]> {
        let mut stream = std::os::unix::net::UnixStream::connect(&self.alloc_socket)
            .context("the binary was not built with the `alloc-count` feature")?;
        let mut line = String::new();
        stream.read_to_string(&mut line)?;
        let mut out = [0u64; 4];
        for (slot, field) in out.iter_mut().zip(line.split_whitespace()) {
            *slot = field.parse()?;
        }
        Ok(out)
    }

    /// Nanoseconds on a CPU, summed over the process's threads.
    pub(crate) fn cpu_ns(&self) -> anyhow::Result<u64> {
        let mut total = 0;
        for task in std::fs::read_dir(format!("/proc/{}/task", self.pid()))? {
            let path = task?.path().join("schedstat");
            // A thread can exit between the listing and the read.
            if let Ok(text) = std::fs::read_to_string(path)
                && let Some(ns) = text.split_whitespace().next()
            {
                total += ns.parse::<u64>()?;
            }
        }
        Ok(total)
    }
}

/// A byte stream: plain TCP or TLS.
pub(crate) trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

/// One kept-alive client connection.
pub(crate) struct Conn {
    io: Box<dyn Io>,
    buf: Vec<u8>,
}

impl Conn {
    /// Sends one request and reads the whole response; returns its status.
    pub(crate) async fn send(&mut self, request: &[u8]) -> anyhow::Result<u16> {
        self.io.write_all(request).await?;
        self.io.flush().await?;
        self.buf.clear();
        let mut chunk = [0u8; 8 * 1024];
        let head_end = loop {
            if let Some(end) = find(&self.buf, b"\r\n\r\n") {
                break end + 4;
            }
            let read = self.io.read(&mut chunk).await?;
            if read == 0 {
                bail!("connection closed");
            }
            self.buf.extend_from_slice(&chunk[..read]);
        };
        let head = std::str::from_utf8(&self.buf[..head_end])?;
        let status: u16 = head
            .split_whitespace()
            .nth(1)
            .context("no status")?
            .parse()?;
        let length: usize = head
            .lines()
            .find_map(|l| {
                let (name, value) = l.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse().ok())?
            })
            .context("no content-length")?;
        while self.buf.len() < head_end + length {
            let read = self.io.read(&mut chunk).await?;
            if read == 0 {
                bail!("connection closed in the body");
            }
            self.buf.extend_from_slice(&chunk[..read]);
        }
        Ok(status)
    }
}

/// A GET for `host` with 3 (k6-like) or 20 (browser-like) header fields.
pub(crate) fn request_bytes(host: &str, headers: usize) -> Vec<u8> {
    let mut r = format!("GET / HTTP/1.1\r\nHost: {host}\r\n");
    if headers >= 20 {
        r.push_str(
            "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36\r\n\
             Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n\
             Accept-Language: en-GB,en;q=0.9,de;q=0.8\r\n\
             Accept-Encoding: gzip, deflate, br, zstd\r\n\
             Cache-Control: max-age=0\r\n\
             Connection: keep-alive\r\n\
             Upgrade-Insecure-Requests: 1\r\n\
             Sec-Fetch-Dest: document\r\n\
             Sec-Fetch-Mode: navigate\r\n\
             Sec-Fetch-Site: same-origin\r\n\
             Sec-Fetch-User: ?1\r\n\
             Sec-CH-UA: \"Chromium\";v=\"141\", \"Not?A_Brand\";v=\"8\"\r\n\
             Sec-CH-UA-Mobile: ?0\r\n\
             Sec-CH-UA-Platform: \"Linux\"\r\n\
             Cookie: session=4f2a9c1e7b3d5a8f; theme=dark; consent=1\r\n\
             Referer: https://site0.test/index.html\r\n\
             DNT: 1\r\n\
             Priority: u=0, i\r\n\
             Pragma: no-cache\r\n",
        );
    } else {
        r.push_str("User-Agent: k6/1.3.0 (https://k6.io/)\r\nAccept: */*\r\n");
    }
    r.push_str("\r\n");
    r.into_bytes()
}

/// The host of the `seq`-th request: spread over all routes, the same sequence for every build.
fn host_index(seq: usize, routes: usize) -> usize {
    (seq.wrapping_mul(7919).wrapping_add(13)) % routes
}

/// Sends `total` requests spread over `conns`, then gives the connections back.
async fn phase(
    conns: Vec<Conn>,
    requests: &Arc<Vec<Vec<u8>>>,
    first_seq: usize,
    total: usize,
) -> anyhow::Result<Vec<Conn>> {
    let count = conns.len();
    let mut tasks = Vec::with_capacity(count);
    for (i, mut conn) in conns.into_iter().enumerate() {
        let requests = requests.clone();
        tasks.push(tokio::spawn(async move {
            let mut seq = first_seq + i;
            while seq < first_seq + total {
                let request = &requests[host_index(seq, requests.len())];
                let status = conn.send(request).await?;
                if status != 200 {
                    bail!("status {status} for request {seq}");
                }
                seq += count;
            }
            anyhow::Ok(conn)
        }));
    }
    let mut back = Vec::with_capacity(count);
    for task in tasks {
        back.push(task.await??);
    }
    Ok(back)
}

/// `strace -c -f` attached to the process until [`Strace::finish`].
struct Strace {
    child: Child,
    out: PathBuf,
}

impl Strace {
    fn attach(pid: u32, out: &Path) -> anyhow::Result<Self> {
        let mut child = Command::new("strace")
            .args(["-c", "-f", "-o"])
            .arg(out)
            .args(["-p", &pid.to_string()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .context("starting strace")?;
        // strace says "Process <pid> attached with <n> threads" once every thread is traced.
        let stderr = child.stderr.take().context("strace stderr")?;
        let mut lines = BufReader::new(stderr).lines();
        loop {
            let line = lines.next().context("strace exited")??;
            if line.contains("attached") {
                break;
            }
        }
        std::thread::spawn(move || for _ in lines {});
        Ok(Self {
            child,
            out: out.to_owned(),
        })
    }

    fn finish(mut self) -> anyhow::Result<BTreeMap<String, u64>> {
        Command::new("kill")
            .args(["-INT", &self.child.id().to_string()])
            .status()?;
        self.child.wait()?;
        let text = std::fs::read_to_string(&self.out)?;
        let mut calls = BTreeMap::new();
        for line in text.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            // % time, seconds, usecs/call, calls, [errors], syscall
            if fields.len() < 5 || fields[0].parse::<f64>().is_err() {
                continue;
            }
            let Some(name) = fields.last() else { continue };
            if *name == "total" {
                continue;
            }
            if let Ok(n) = fields[3].parse::<u64>() {
                calls.insert((*name).to_owned(), n);
            }
        }
        Ok(calls)
    }
}

async fn measure(args: MeasureArgs) -> anyhow::Result<()> {
    let lab = Lab::start(&args.lab).await?;
    let requests: Arc<Vec<Vec<u8>>> = Arc::new(
        (0..lab.routes)
            .map(|i| request_bytes(&format!("site{i}.test"), args.headers))
            .collect(),
    );
    let mut conns = Vec::with_capacity(args.conns);
    for _ in 0..args.conns {
        conns.push(lab.connect("site0.test").await?);
    }
    if args.lab.tls && lab.routes > 1 {
        bail!("--tls is measured with one route (the connection's name stays the route's)");
    }
    // The warm-up reaches every route once (the host sequence visits each route once per
    // `routes` requests), so first-use costs such as a metric's label child stay out of the
    // phases.
    let warmup = (args.n / 2).max(500).max(lab.routes + 500);
    conns = phase(conns, &requests, 0, warmup).await?;
    let n = args.n;
    let mut seq = warmup;
    let started = Instant::now();
    let out = match args.measure {
        Measure::Allocs => {
            let a0 = lab.allocs()?;
            conns = phase(conns, &requests, seq, n).await?;
            seq += n;
            let a1 = lab.allocs()?;
            conns = phase(conns, &requests, seq, 2 * n).await?;
            let a2 = lab.allocs()?;
            let per = |k: usize| ((a2[k] - a1[k]) as f64 - (a1[k] - a0[k]) as f64) / n as f64;
            serde_json::json!({
                "allocations": per(0),
                "deallocations": per(1),
                "reallocations": per(2),
                "bytes_allocated": per(3),
                "phase_n": [a1[0] - a0[0]],
                "phase_2n": [a2[0] - a1[0]],
            })
        }
        Measure::Syscalls => {
            let dir = tempfile::tempdir()?;
            let s = Strace::attach(lab.pid(), &dir.path().join("n.txt"))?;
            conns = phase(conns, &requests, seq, n).await?;
            seq += n;
            let c1 = s.finish()?;
            let s = Strace::attach(lab.pid(), &dir.path().join("2n.txt"))?;
            conns = phase(conns, &requests, seq, 2 * n).await?;
            let c2 = s.finish()?;
            let mut per = BTreeMap::new();
            let mut total = 0.0;
            for name in c1.keys().chain(c2.keys()) {
                let a = c1.get(name).copied().unwrap_or(0) as f64;
                let b = c2.get(name).copied().unwrap_or(0) as f64;
                let v = (b - a) / n as f64;
                per.insert(name.clone(), (v * 1000.0).round() / 1000.0);
            }
            for v in per.values() {
                total += v;
            }
            serde_json::json!({ "syscalls": (total * 1000.0_f64).round() / 1000.0, "by_name": per })
        }
        Measure::Cpu => {
            let t0 = lab.cpu_ns()?;
            let w0 = Instant::now();
            conns = phase(conns, &requests, seq, n).await?;
            seq += n;
            let t1 = lab.cpu_ns()?;
            let w1 = Instant::now();
            conns = phase(conns, &requests, seq, 2 * n).await?;
            let t2 = lab.cpu_ns()?;
            let w2 = Instant::now();
            let per = ((t2 - t1) as f64 - (t1 - t0) as f64) / n as f64 / 1000.0;
            serde_json::json!({
                "cpu_us": per,
                "cpu_us_2n_only": (t2 - t1) as f64 / (2 * n) as f64 / 1000.0,
                "req_per_s_2n": (2 * n) as f64 / (w2 - w1).as_secs_f64(),
                "req_per_s_n": n as f64 / (w1 - w0).as_secs_f64(),
            })
        }
    };
    drop(conns);
    let mut line = serde_json::json!({
        "label": args.label,
        "routes": args.lab.routes,
        "headers": args.headers,
        "tls": args.lab.tls,
        "n": n,
        "conns": args.conns,
        "seconds": started.elapsed().as_secs_f64(),
    });
    if let (Some(line), Some(out)) = (line.as_object_mut(), out.as_object()) {
        line.extend(out.clone());
    }
    println!("{line}");
    Ok(())
}
