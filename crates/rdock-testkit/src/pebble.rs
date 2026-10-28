//! Pebble, Let's Encrypt's test CA, with `pebble-challtestsrv` as its DNS server, in Docker.
//! Every name resolves to the Docker host, where the `rdock` under test listens.

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use tempfile::TempDir;

const PEBBLE: &str = "ghcr.io/letsencrypt/pebble:2.10.1";
const CHALLTESTSRV: &str = "ghcr.io/letsencrypt/pebble-challtestsrv:2.10.1";
const BUSYBOX: &str = "busybox:1.37";

/// A running Pebble.
pub struct Pebble {
    names: Vec<String>,
    network: String,
    dir: TempDir,
    /// ACME directory URL, reachable from the host.
    pub directory: String,
    management: u16,
}

impl Drop for Pebble {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f"])
            .args(&self.names)
            .output();
        let _ = Command::new("docker")
            .args(["network", "rm", &self.network])
            .output();
    }
}

fn docker(args: &[&str]) -> String {
    let out = Command::new("docker").args(args).output().unwrap();
    assert!(
        out.status.success(),
        "docker {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

/// The address containers reach the Docker host at.
fn host_address() -> String {
    let line = docker(&[
        "run",
        "--rm",
        "--add-host",
        "rdock-host:host-gateway",
        BUSYBOX,
        "grep",
        "-w",
        "rdock-host",
        "/etc/hosts",
    ]);
    line.split_whitespace().next().unwrap().to_owned()
}

impl Pebble {
    /// Starts Pebble validating HTTP-01 on the host's `http_port`.
    pub fn start(http_port: u16) -> Self {
        let id = std::process::id();
        let network = format!("rdock-pebble-{id}");
        let dns = format!("rdock-challtestsrv-{id}");
        let ca = format!("rdock-pebble-ca-{id}");
        let acme = crate::free_port();
        let management = crate::free_port();
        let dir = tempfile::tempdir().unwrap();
        let config = serde_json::json!({ "pebble": {
            "listenAddress": "0.0.0.0:14000",
            "managementListenAddress": "0.0.0.0:15000",
            "certificate": "test/certs/localhost/cert.pem",
            "privateKey": "test/certs/localhost/key.pem",
            "httpPort": http_port,
            "tlsPort": 5001,
            "ocspResponderURL": "",
            "externalAccountBindingRequired": false,
            "keyAlgorithm": "ecdsa",
            "profiles": {
                "default": { "description": "90 days", "validityPeriod": 7_776_000 },
                "shortlived": { "description": "6 days", "validityPeriod": 518_400 }
            }
        }});
        std::fs::write(dir.path().join("pebble.json"), config.to_string()).unwrap();
        let host = host_address();
        docker(&["network", "create", &network]);
        let mut pebble = Self {
            names: vec![dns.clone(), ca.clone()],
            network: network.clone(),
            dir,
            directory: format!("https://localhost:{acme}/dir"),
            management,
        };
        docker(&[
            "run",
            "-d",
            "--name",
            &dns,
            "--network",
            &network,
            CHALLTESTSRV,
            "-defaultIPv4",
            &host,
            "-defaultIPv6",
            "",
            "-http01",
            "",
            "-https01",
            "",
            "-tlsalpn01",
            "",
            "-doh",
            "",
        ]);
        let mount = format!("{}:/cfg:ro", pebble.dir.path().display());
        docker(&[
            "run",
            "-d",
            "--name",
            &ca,
            "--network",
            &network,
            "-e",
            "PEBBLE_VA_NOSLEEP=1",
            "-e",
            "PEBBLE_WFE_NONCEREJECT=0",
            "-p",
            &format!("{acme}:14000"),
            "-p",
            &format!("{management}:15000"),
            "-v",
            &mount,
            PEBBLE,
            "-config",
            "/cfg/pebble.json",
            "-dnsserver",
            &format!("{dns}:8053"),
        ]);
        pebble.wait_ready();
        pebble
    }

    fn wait_ready(&mut self) {
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(30) {
            if curl(&self.directory).is_some() {
                return;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        panic!("Pebble did not start");
    }

    /// The root that signs Pebble's HTTPS endpoint (`acme.ca_root`).
    pub fn endpoint_root(&self) -> PathBuf {
        let path = self.dir.path().join("pebble.minica.pem");
        if !path.exists() {
            let container = &self.names[1];
            docker(&[
                "cp",
                &format!("{container}:/test/certs/pebble.minica.pem"),
                &path.display().to_string(),
            ]);
        }
        path
    }

    /// The root of the certificates Pebble issues, as PEM. It changes with every start.
    pub fn issuing_root(&self) -> String {
        curl(&format!("https://localhost:{}/roots/0", self.management)).unwrap()
    }

    /// Stops the CA (the DNS server keeps running), to test a CA outage.
    pub fn stop_ca(&self) {
        docker(&["stop", &self.names[1]]);
    }
}

/// GET over HTTPS without verification (Pebble's endpoints use its own test root).
fn curl(url: &str) -> Option<String> {
    let out = Command::new("curl")
        .args(["-sfk", "--max-time", "5", url])
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}
