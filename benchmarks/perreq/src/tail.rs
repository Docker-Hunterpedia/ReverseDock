//! The TLS-tail experiment of issue 181 step 4.
//!
//! A handful of established TLS connections send requests on a fixed schedule (an open model:
//! latency counts from the time a request was due, so a stalled proxy cannot slow the schedule
//! down). After `--burst-at`, `--burst` new TLS connections arrive, either all at once (as k6
//! opens its preallocated virtual users' connections in the first 50 ms of a run) or spread
//! evenly over `--ramp`. Each new connection completes its handshake, sends one request and stays
//! open until the end. The output is the latency of the established connections' requests
//! during the burst and outside it, and how long the burst's handshakes took.
//!
//! The burst comes from a second process (`rdock-perreq burst`, on `--burst-cpus`), so the
//! client side of 500 handshakes does not delay the measuring client's own requests.

use std::net::SocketAddr;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::Args;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

use crate::{Lab, LabArgs, request_bytes};

/// When a request was due (seconds from the start) and its latency (milliseconds).
type Sample = (f64, f64);

#[derive(Args)]
pub(crate) struct TailArgs {
    #[command(flatten)]
    lab: LabArgs,
    /// Established connections that keep sending.
    #[arg(long, default_value_t = 8)]
    established: usize,
    /// Requests per second over all established connections.
    #[arg(long, default_value_t = 2000)]
    rate: u64,
    /// How long the established connections send, in seconds.
    #[arg(long, default_value_t = 8)]
    duration: u64,
    /// New TLS connections in the burst.
    #[arg(long, default_value_t = 500)]
    burst: usize,
    /// When the burst starts, in seconds after the established connections start.
    #[arg(long, default_value_t = 3)]
    burst_at: u64,
    /// Spread the burst over this many milliseconds; 0 opens all at once.
    #[arg(long, default_value_t = 0)]
    ramp: u64,
    /// CPUs for the burst process, as `taskset -c` takes them.
    #[arg(long)]
    burst_cpus: Option<String>,
    /// A name for the variant, copied into the output.
    #[arg(long, default_value = "")]
    label: String,
}

/// The burst process.
#[derive(Args)]
pub(crate) struct BurstArgs {
    /// The proxy.
    #[arg(long)]
    addr: SocketAddr,
    /// Server name for SNI and `Host`.
    #[arg(long, default_value = "site0.test")]
    name: String,
    /// New connections.
    #[arg(long)]
    count: usize,
    /// Milliseconds to wait before the first one.
    #[arg(long)]
    delay: u64,
    /// Spread over this many milliseconds; 0 opens all at once.
    #[arg(long, default_value_t = 0)]
    ramp: u64,
    /// Milliseconds after the start to keep the connections open.
    #[arg(long)]
    hold: u64,
}

/// Percentiles of a set of durations, in milliseconds.
fn summary(mut values: Vec<f64>) -> serde_json::Value {
    if values.is_empty() {
        return serde_json::json!({ "count": 0 });
    }
    values.sort_by(f64::total_cmp);
    let at = |q: f64| {
        let rank = ((q * values.len() as f64).ceil() as usize).clamp(1, values.len());
        (values[rank - 1] * 1000.0).round() / 1000.0
    };
    serde_json::json!({
        "count": values.len(),
        "p50": at(0.50),
        "p99": at(0.99),
        "p999": at(0.999),
        "max": at(1.0),
    })
}

pub(crate) async fn run(args: TailArgs) -> anyhow::Result<()> {
    if !args.lab.tls {
        anyhow::bail!("the tail experiment needs --tls");
    }
    let lab = Lab::start(&args.lab).await?;
    let request: Arc<[u8]> = request_bytes("site0.test", 3).into();
    let mut conns = Vec::with_capacity(args.established);
    for _ in 0..args.established {
        let mut conn = lab.connect("site0.test").await?;
        conn.send(&request).await?;
        conns.push(conn);
    }
    let cpu_before = lab.cpu_ns()?;
    let lead = Duration::from_millis(300);
    let start = Instant::now() + lead;
    let end = start + Duration::from_secs(args.duration);
    // The burst process, told when to start relative to its own start.
    // nosemgrep: rust.lang.security.current-exe.current-exe -- a benchmark tool starting a second copy of itself as the load source; no security decision depends on the path
    let exe = std::env::current_exe()?;
    let mut burst = match &args.burst_cpus {
        Some(cpus) => {
            let mut c = Command::new("taskset");
            c.args(["-c", cpus]).arg(exe);
            c
        }
        None => Command::new(exe),
    };
    let delay = lead + Duration::from_secs(args.burst_at);
    let child = burst
        .arg("burst")
        .args(["--addr", &lab.proxy.to_string()])
        .args(["--count", &args.burst.to_string()])
        .args(["--delay", &delay.as_millis().to_string()])
        .args(["--ramp", &args.ramp.to_string()])
        .args([
            "--hold",
            &(lead + Duration::from_secs(args.duration))
                .as_millis()
                .to_string(),
        ])
        .stdout(Stdio::piped())
        .spawn()?;
    // Requests are due every `interval` on each connection, the connections offset evenly.
    let interval = Duration::from_secs_f64(args.established as f64 / args.rate as f64);
    let samples: Arc<Mutex<Vec<Sample>>> = Arc::new(Mutex::new(Vec::new()));
    let mut tasks = Vec::new();
    for (i, mut conn) in conns.into_iter().enumerate() {
        let request = request.clone();
        let samples = samples.clone();
        let offset = interval.mul_f64(i as f64 / args.established as f64);
        tasks.push(tokio::spawn(async move {
            let mut due = start + offset;
            let mut local = Vec::new();
            while due < end {
                tokio::time::sleep_until(due.into()).await;
                let status = conn.send(&request).await?;
                if status != 200 {
                    anyhow::bail!("status {status}");
                }
                let done = Instant::now();
                local.push((
                    due.duration_since(start).as_secs_f64(),
                    done.duration_since(due).as_secs_f64() * 1000.0,
                ));
                due += interval;
            }
            samples.lock().await.extend(local);
            anyhow::Ok(())
        }));
    }
    for task in tasks {
        task.await??;
    }
    let cpu_after = lab.cpu_ns()?;
    let output = tokio::task::spawn_blocking(move || child.wait_with_output()).await??;
    let burst: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap_or_default();
    let samples = samples.lock().await.clone();
    let burst_from = args.burst_at as f64;
    // The burst window: from its start until 1 s after its last connection was due.
    let burst_to = burst_from + args.ramp as f64 / 1000.0 + 1.0;
    let (during, outside): (Vec<&Sample>, Vec<&Sample>) = samples
        .iter()
        .partition(|(t, _)| *t >= burst_from && *t < burst_to);
    let line = serde_json::json!({
        "label": args.label,
        "burst": args.burst,
        "ramp_ms": args.ramp,
        "rate": args.rate,
        "established": args.established,
        "max_handshakes": args.lab.max_handshakes,
        "during_burst_ms": summary(during.iter().map(|s| s.1).collect()),
        "outside_burst_ms": summary(outside.iter().map(|s| s.1).collect()),
        "all_ms": summary(samples.iter().map(|s| s.1).collect()),
        "handshake_ms": burst["handshake_ms"],
        "burst_failures": burst["failures"],
        "rdock_cpu_s": (cpu_after - cpu_before) as f64 / 1e9,
    });
    println!("{line}");
    Ok(())
}

/// Accepts any certificate: the burst measures the server's handshakes, and skipping the
/// client's signature check keeps the client side cheap enough to arrive at the burst rate.
#[derive(Debug)]
struct AnyCert(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

pub(crate) async fn burst(args: BurstArgs) -> anyhow::Result<()> {
    let began = Instant::now();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCert(provider)))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let config = Arc::new(config);
    let first = began + Duration::from_millis(args.delay);
    let hold = began + Duration::from_millis(args.hold);
    let request: Arc<[u8]> = request_bytes(&args.name, 3).into();
    let handshakes: Arc<Mutex<Vec<f64>>> = Arc::new(Mutex::new(Vec::new()));
    let failures = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut tasks = Vec::with_capacity(args.count);
    for i in 0..args.count {
        let config = config.clone();
        let request = request.clone();
        let handshakes = handshakes.clone();
        let failures = failures.clone();
        let name = rustls_pki_types::ServerName::try_from(args.name.clone())?;
        let at = first + Duration::from_millis(args.ramp).mul_f64(i as f64 / args.count as f64);
        tasks.push(tokio::spawn(async move {
            tokio::time::sleep_until(at.into()).await;
            let started = Instant::now();
            let connected = async {
                let tcp = tokio::net::TcpStream::connect(args.addr).await?;
                tcp.set_nodelay(true)?;
                tokio_rustls::TlsConnector::from(config)
                    .connect(name, tcp)
                    .await
            }
            .await;
            let Ok(mut tls) = connected else {
                failures.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return;
            };
            handshakes
                .lock()
                .await
                .push(started.elapsed().as_secs_f64() * 1000.0);
            let mut buf = vec![0u8; 4096];
            let answered = async {
                tls.write_all(&request).await?;
                // The head and the 1 KiB body arrive in one or two reads; one is enough to
                // know the request was served.
                tls.read(&mut buf).await
            }
            .await;
            if !matches!(answered, Ok(n) if n > 0) {
                failures.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            // Stay open, as a virtual user's connection does.
            tokio::time::sleep_until(hold.into()).await;
            drop(tls);
        }));
    }
    for task in tasks {
        task.await?;
    }
    let line = serde_json::json!({
        "handshake_ms": summary(handshakes.lock().await.clone()),
        "failures": failures.load(std::sync::atomic::Ordering::Relaxed),
    });
    println!("{line}");
    Ok(())
}
