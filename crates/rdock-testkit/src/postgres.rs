//! PostgreSQL 17 in Docker with TLS on, as a TCP-route backend, and `psql` from the same image
//! as the client. Like Traefik's integration fixture
//! (<https://raw.githubusercontent.com/traefik/traefik/master/integration/resources/compose/tcp.yml>,
//! checked 2026-11-06), one container started with `-c` options; the image has no `openssl`,
//! so the certificate comes in environment variables and is written at start with the key at
//! mode 0600, as PostgreSQL requires (<https://www.postgresql.org/docs/17/ssl-tcp.html>).

use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

const IMAGE: &str = "postgres:17.11-alpine";

/// A running PostgreSQL server, published on `127.0.0.1:<port>`.
pub struct Postgres {
    name: String,
    pub port: u16,
}

impl Drop for Postgres {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.name])
            .output();
    }
}

impl Postgres {
    /// Starts PostgreSQL with `ssl=on`, the certificate `cert` and trust authentication, and
    /// waits until it accepts TCP connections.
    pub fn start(cert: &crate::certs::Issued) -> Self {
        static STARTED: AtomicU32 = AtomicU32::new(0);
        let name = format!(
            "rdock-postgres-{}-{}",
            std::process::id(),
            STARTED.fetch_add(1, Ordering::SeqCst)
        );
        let port = crate::free_port();
        let script = "printf '%s' \"$TLS_CERT\" > /tmp/server.crt \
             && printf '%s' \"$TLS_KEY\" > /tmp/server.key \
             && chown 70:70 /tmp/server.key /tmp/server.crt && chmod 0600 /tmp/server.key \
             && exec docker-entrypoint.sh postgres -c ssl=on \
             -c ssl_cert_file=/tmp/server.crt -c ssl_key_file=/tmp/server.key";
        let out = Command::new("docker")
            .args(["run", "-d", "--name", &name, "-p"])
            .arg(format!("127.0.0.1:{port}:5432"))
            .args(["-e", "POSTGRES_HOST_AUTH_METHOD=trust", "-e"])
            .arg(format!("TLS_CERT={}", cert.cert_pem))
            .arg("-e")
            .arg(format!("TLS_KEY={}", cert.key_pem))
            .args(["--entrypoint", "sh", IMAGE, "-c", script])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "docker run: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let postgres = Self { name, port };
        let deadline = Instant::now() + Duration::from_secs(60);
        // The server that initdb starts first listens on the Unix socket only, so a TCP answer
        // comes from the final server.
        while !postgres.ready() {
            assert!(Instant::now() < deadline, "PostgreSQL did not start");
            std::thread::sleep(Duration::from_millis(200));
        }
        postgres
    }

    fn ready(&self) -> bool {
        Command::new("docker")
            .args(["exec", &self.name, "pg_isready", "-h", "127.0.0.1", "-q"])
            .output()
            .is_ok_and(|out| out.status.success())
    }
}

/// Runs `psql <conninfo> -tAc <sql>` in a throw-away container of the same image, where
/// `host_alias` resolves to the Docker host.
pub fn psql(host_alias: &str, conninfo: &str, sql: &str) -> Output {
    Command::new("docker")
        .args(["run", "--rm", "--add-host"])
        .arg(format!("{host_alias}:host-gateway"))
        .args([IMAGE, "psql", conninfo, "-tAc", sql])
        .output()
        .unwrap()
}
