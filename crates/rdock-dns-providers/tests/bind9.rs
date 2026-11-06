//! The RFC 2136 adapter against BIND 9 in Docker, with an `update-policy` that allows the key
//! to change only one `_acme-challenge` TXT record. Needs Docker and `RDOCK_DOCKER_TESTS=1`
//! (CI sets it); skipped otherwise.

#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::panic)]

use std::net::SocketAddr;
use std::process::Command;
use std::time::{Duration, Instant};

use rdock_acme::dns::{DnsSolver, Lookup, wait_until_visible};
use rdock_dns_providers::Rfc2136Dns;
use rdock_model::acme::{DnsTransport, Rfc2136Provider, TsigAlgorithm};

const BIND: &str = "internetsystemsconsortium/bind9:9.20";
/// A fixed test key (32 bytes, base64), as `tsig-keygen -a hmac-sha256` prints one.
const SECRET: &str = "mY0Jbz4mrjbLI1MUJBQLi4nfiCNbYHgBBk2yW2CeoGU=";
const FQDN: &str = "_acme-challenge.app.example.com";

const NAMED_CONF: &str = r#"
key "rdock-acme." { algorithm hmac-sha256; secret "SECRET"; };
options {
    directory "/var/cache/bind";
    listen-on { any; };
    listen-on-v6 { none; };
    recursion no;
};
zone "example.com" {
    type primary;
    file "/zones/example.com.zone";
    update-policy { grant rdock-acme. name _acme-challenge.app.example.com. txt; };
};
"#;

const ZONE: &str = "$TTL 60
@   IN SOA ns1.example.com. hostmaster.example.com. 1 3600 600 86400 60
@   IN NS  ns1.example.com.
ns1 IN A   127.0.0.1
";

struct Container(String);

impl Drop for Container {
    fn drop(&mut self) {
        let _ = Command::new("docker").args(["rm", "-f", &self.0]).output();
    }
}

/// BIND serving `example.com` on a loopback port (UDP and TCP).
fn start_bind(dir: &std::path::Path) -> (Container, SocketAddr) {
    std::fs::write(dir.join("named.conf"), NAMED_CONF.replace("SECRET", SECRET)).unwrap();
    let zones = dir.join("zones");
    std::fs::create_dir(&zones).unwrap();
    std::fs::write(zones.join("example.com.zone"), ZONE).unwrap();
    // BIND writes its journal next to the zone file, as the unprivileged `bind` user.
    std::fs::set_permissions(&zones, std::os::unix::fs::PermissionsExt::from_mode(0o777)).unwrap();
    let port = rdock_testkit::free_port();
    let name = format!("rdock-bind9-{}-{port}", std::process::id());
    let output = Command::new("docker")
        .args([
            "run",
            "-d",
            "--rm",
            "--platform",
            "linux/amd64",
            "--name",
            &name,
        ])
        .args(["-p", &format!("127.0.0.1:{port}:53/tcp")])
        .args(["-p", &format!("127.0.0.1:{port}:53/udp")])
        .args(["-v", &format!("{}:/etc/bind-test:ro", dir.display())])
        .args(["-v", &format!("{}:/zones", zones.display())])
        .args([BIND, "-g", "-c", "/etc/bind-test/named.conf", "-u", "bind"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "docker run: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    (Container(name), SocketAddr::from(([127, 0, 0, 1], port)))
}

fn provider(server: SocketAddr, transport: DnsTransport) -> Rfc2136Dns {
    Rfc2136Dns::new(&Rfc2136Provider {
        nameserver: server.to_string(),
        zone: None,
        tsig_key_name: Some("rdock-acme".into()),
        tsig_secret: Some(SECRET.into()),
        tsig_algorithm: TsigAlgorithm::HmacSha256,
        transport,
        insecure_unsigned: false,
    })
    .unwrap()
}

async fn visible(server: SocketAddr, value: &str, within: Duration) -> bool {
    wait_until_visible(FQDN, value, &Lookup::Resolvers(vec![server]), within).await
}

#[tokio::test]
async fn updates_bind_within_its_update_policy() {
    if std::env::var("RDOCK_DOCKER_TESTS").is_ok_and(|v| v == "1") {
        run().await;
    } else {
        eprintln!("skipped: set RDOCK_DOCKER_TESTS=1 to run against BIND 9 in Docker");
    }
}

async fn run() {
    let dir = tempfile::tempdir().unwrap();
    let (_bind, server) = start_bind(dir.path());
    let dns = provider(server, DnsTransport::Tcp);

    // BIND needs a moment to load the zone; the first update is retried until it does.
    let started = Instant::now();
    while let Err(error) = dns.present(FQDN, "apex-value").await {
        assert!(
            started.elapsed() < Duration::from_secs(90),
            "BIND never accepted: {error}"
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    provider(server, DnsTransport::Udp)
        .present(FQDN, "wildcard-value")
        .await
        .unwrap();
    assert!(visible(server, "apex-value", Duration::from_secs(10)).await);
    assert!(visible(server, "wildcard-value", Duration::from_secs(10)).await);

    dns.cleanup(FQDN, "apex-value").await.unwrap();
    assert!(visible(server, "wildcard-value", Duration::from_secs(10)).await);
    assert!(!visible(server, "apex-value", Duration::from_secs(3)).await);

    let refused = dns
        .present("_acme-challenge.other.example.com", "x")
        .await
        .unwrap_err();
    assert!(
        refused.0.contains("REFUSED") || refused.0.contains("Refused"),
        "{refused}"
    );
}
