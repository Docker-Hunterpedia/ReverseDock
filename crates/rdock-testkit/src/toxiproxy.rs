//! Toxiproxy (<https://github.com/Shopify/toxiproxy>) in Docker, for fault injection between
//! the `rdock` under test and its backends: latency, resets, outages and flapping.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

const IMAGE: &str = "ghcr.io/shopify/toxiproxy:2.13.0";

/// A running Toxiproxy whose proxies listen on host ports.
pub struct Toxiproxy {
    name: String,
    api: u16,
}

impl Drop for Toxiproxy {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.name])
            .output();
    }
}

impl Toxiproxy {
    /// Starts Toxiproxy with `ports` published on 127.0.0.1 for its proxies.
    pub fn start(ports: &[u16]) -> Self {
        static STARTED: AtomicU32 = AtomicU32::new(0);
        let name = format!(
            "rdock-toxiproxy-{}-{}",
            std::process::id(),
            STARTED.fetch_add(1, Ordering::SeqCst)
        );
        let api = crate::free_port();
        let mut args = vec![
            "run".to_owned(),
            "-d".to_owned(),
            "--name".to_owned(),
            name.clone(),
            "--add-host".to_owned(),
            "rdock-host:host-gateway".to_owned(),
            "-p".to_owned(),
            format!("127.0.0.1:{api}:8474"),
        ];
        for port in ports {
            args.push("-p".to_owned());
            args.push(format!("127.0.0.1:{port}:{port}"));
        }
        args.push(IMAGE.to_owned());
        args.extend(["-host".to_owned(), "0.0.0.0".to_owned()]);
        let out = Command::new("docker").args(&args).output().unwrap();
        assert!(
            out.status.success(),
            "docker run: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let proxy = Self { name, api };
        let deadline = Instant::now() + Duration::from_secs(30);
        while proxy.call("GET", "/version", "").is_err() {
            assert!(Instant::now() < deadline, "Toxiproxy did not start");
            std::thread::sleep(Duration::from_millis(100));
        }
        proxy
    }

    /// A proxy `name` on `listen` (one of the published ports) to `upstream` on the host.
    pub fn proxy(&self, name: &str, listen: u16, upstream: u16) {
        let body = serde_json::json!({
            "name": name,
            "listen": format!("0.0.0.0:{listen}"),
            "upstream": format!("rdock-host:{upstream}"),
            "enabled": true
        });
        self.call("POST", "/proxies", &body.to_string()).unwrap();
    }

    /// Adds a toxic, e.g. `{"type": "latency", "attributes": {"latency": 1000}}`.
    pub fn toxic(&self, proxy: &str, name: &str, toxic: &serde_json::Value) {
        let mut body = toxic.clone();
        body["name"] = serde_json::json!(name);
        self.call(
            "POST",
            &format!("/proxies/{proxy}/toxics"),
            &body.to_string(),
        )
        .unwrap();
    }

    /// Removes a toxic.
    pub fn remove_toxic(&self, proxy: &str, name: &str) {
        self.call("DELETE", &format!("/proxies/{proxy}/toxics/{name}"), "")
            .unwrap();
    }

    /// Turns a proxy on or off; off refuses and closes every connection (an outage).
    pub fn set_enabled(&self, proxy: &str, enabled: bool) {
        let body = serde_json::json!({ "enabled": enabled });
        self.call("POST", &format!("/proxies/{proxy}"), &body.to_string())
            .unwrap();
    }

    fn call(&self, method: &str, path: &str, body: &str) -> std::io::Result<String> {
        let mut stream = TcpStream::connect(("127.0.0.1", self.api))?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        write!(
            stream,
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )?;
        let mut reply = String::new();
        stream.read_to_string(&mut reply)?;
        let ok = reply.starts_with("HTTP/1.1 2");
        if ok {
            Ok(reply)
        } else {
            Err(std::io::Error::other(reply))
        }
    }
}
