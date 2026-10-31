//! Runs the real `rdock` binary with a generated configuration.

use std::io::Read;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use tempfile::TempDir;

/// A running `rdock run`.
pub struct Rdock {
    child: Option<Child>,
    pub dir: TempDir,
    pub admin: SocketAddr,
    binary: PathBuf,
}

impl Drop for Rdock {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Rdock {
    /// Starts `binary` with `config` (the `admin` section is added) and waits until it is ready.
    pub fn start(binary: &str, config: &str) -> Self {
        Self::try_start(binary, config)
            .unwrap_or_else(|log| panic!("rdock did not become ready:\n{log}"))
    }

    /// Like [`Self::start`]; the error is the process output.
    pub fn try_start(binary: &str, config: &str) -> Result<Self, String> {
        let dir = tempfile::tempdir().unwrap();
        let admin_port = crate::free_port();
        let admin: SocketAddr = format!("127.0.0.1:{admin_port}").parse().unwrap();
        let mut rdock = Self {
            child: None,
            dir,
            admin,
            binary: PathBuf::from(binary),
        };
        rdock.write_config(config);
        rdock.spawn();
        rdock.wait_ready(Duration::from_secs(15))?;
        Ok(rdock)
    }

    pub fn config_path(&self) -> PathBuf {
        self.dir.path().join("rdock.yaml")
    }

    pub fn data_dir(&self) -> PathBuf {
        self.dir.path().join("data")
    }

    /// Replaces the configuration file (the admin section is added again).
    pub fn write_config(&self, config: &str) {
        let full = format!("{config}\nadmin: {{ listener: \"{}\" }}\n", self.admin);
        let tmp = self.dir.path().join(".rdock.yaml.tmp");
        std::fs::write(&tmp, full).unwrap();
        std::fs::rename(tmp, self.config_path()).unwrap();
    }

    fn spawn(&mut self) {
        let child = Command::new(&self.binary)
            .args(["run", "--log-format", "json", "--log", "info", "-c"])
            .arg(self.config_path())
            .arg("--data-dir")
            .arg(self.data_dir())
            .env_remove("RDOCK_ADMIN_TOKEN")
            .stdout(std::fs::File::create(self.dir.path().join("access.log")).unwrap())
            .stderr(std::fs::File::create(self.dir.path().join("rdock.log")).unwrap())
            .stdin(Stdio::null())
            .spawn()
            .unwrap();
        self.child = Some(child);
    }

    fn wait_ready(&mut self, limit: Duration) -> Result<(), String> {
        let started = Instant::now();
        while started.elapsed() < limit {
            if let Some(status) = self
                .child
                .as_mut()
                .and_then(|c| c.try_wait().ok().flatten())
            {
                return Err(format!("exited with {status}\n{}", self.log()));
            }
            if self.get_admin("/readyz").is_some_and(|(s, _)| s == 200) {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        Err(format!("timed out\n{}", self.log()))
    }

    /// The application log so far.
    pub fn log(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("rdock.log")).unwrap_or_default()
    }

    /// Access-log lines so far.
    pub fn access_log(&self) -> Vec<serde_json::Value> {
        std::fs::read_to_string(self.dir.path().join("access.log"))
            .unwrap_or_default()
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    }

    pub fn pid(&self) -> u32 {
        self.child.as_ref().unwrap().id()
    }

    pub fn signal(&self, signal: &str) {
        let status = Command::new("kill")
            .args([&format!("-{signal}"), &self.pid().to_string()])
            .status()
            .unwrap();
        assert!(status.success());
    }

    /// Sends SIGTERM and waits for the exit.
    pub fn stop(&mut self, limit: Duration) -> ExitStatus {
        self.signal("TERM");
        let started = Instant::now();
        loop {
            if let Some(status) = self
                .child
                .as_mut()
                .and_then(|c| c.try_wait().ok().flatten())
            {
                self.child = None;
                return status;
            }
            assert!(
                started.elapsed() < limit,
                "rdock did not stop in time\n{}",
                self.log()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// A blocking request to the admin API over its Unix socket, as the CLI makes it.
    pub fn get_admin(&self, path: &str) -> Option<(u16, String)> {
        self.admin_request("GET", path)
    }

    pub fn admin_request(&self, method: &str, path: &str) -> Option<(u16, String)> {
        use std::io::Write;
        let mut stream =
            std::os::unix::net::UnixStream::connect(self.data_dir().join("admin.sock")).ok()?;
        stream
            .set_read_timeout(Some(Duration::from_secs(20)))
            .ok()?;
        write!(
            stream,
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .ok()?;
        let mut raw = String::new();
        stream.read_to_string(&mut raw).ok()?;
        let (head, body) = raw.split_once("\r\n\r\n")?;
        let status = head.split_whitespace().nth(1)?.parse().ok()?;
        Some((status, body.to_owned()))
    }

    /// Asks the running process to reload, as `rdock reload` does.
    pub fn reload(&self) -> (u16, serde_json::Value) {
        let (status, body) = self.admin_request("POST", "/api/v1/config/reload").unwrap();
        (
            status,
            serde_json::from_str(&body).unwrap_or(serde_json::Value::Null),
        )
    }

    /// Runs the binary with `args` and returns exit status and output.
    pub fn command(&self, args: &[&str]) -> std::process::Output {
        Command::new(&self.binary)
            .args(args)
            .env("RDOCK_CONFIG", self.config_path())
            .env("RDOCK_DATA_DIR", self.data_dir())
            .output()
            .unwrap()
    }

    /// Path of a file in the test directory.
    pub fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// Restarts the process with the current configuration file.
    pub fn restart(&mut self) -> Result<(), String> {
        if self.child.is_some() {
            self.stop(Duration::from_secs(15));
        }
        self.spawn();
        self.wait_ready(Duration::from_secs(15))
    }
}

/// Writes `contents` to `dir/name` and returns the path.
pub fn write(dir: &Path, name: &str, contents: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, contents).unwrap();
    path
}
