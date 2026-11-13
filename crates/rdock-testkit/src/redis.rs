//! An in-process stand-in for a Redis-compatible server: the RESP2 commands rdock's
//! cluster-scoped limits use (`AUTH`, `SELECT`, `PING`, `GET`, `INCRBY`, `DECRBY`,
//! `PEXPIREAT`, `ZADD`, `ZREMRANGEBYSCORE`, `ZCARD`, `TIME`), optionally behind TLS and a password. It
//! can be stopped and started again on the same port with its data kept, to test a store that
//! goes away and returns. Expiry is recorded, not enforced.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

#[derive(Default)]
struct Data {
    strings: HashMap<Vec<u8>, i64>,
    sets: HashMap<Vec<u8>, BTreeMap<Vec<u8>, f64>>,
    expiries: HashMap<Vec<u8>, i64>,
}

/// The fake server.
pub struct FakeRedis {
    pub addr: SocketAddr,
    password: Option<String>,
    tls: Option<Arc<rustls::ServerConfig>>,
    data: Arc<Mutex<Data>>,
    commands: Arc<AtomicU64>,
    task: Option<JoinHandle<()>>,
}

impl FakeRedis {
    /// A server on a free port, without TLS; `password` makes `AUTH` required.
    pub async fn start(password: Option<&str>) -> Self {
        Self::start_with(password, None).await
    }

    /// A server behind TLS with `cert_pem`/`key_pem`.
    pub async fn start_tls(password: Option<&str>, cert_pem: &str, key_pem: &str) -> Self {
        use rustls_pki_types::pem::PemObject;
        let certs = rustls_pki_types::CertificateDer::pem_slice_iter(cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let key = rustls_pki_types::PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).unwrap();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
        Self::start_with(password, Some(Arc::new(config))).await
    }

    async fn start_with(password: Option<&str>, tls: Option<Arc<rustls::ServerConfig>>) -> Self {
        let addr: SocketAddr = format!("127.0.0.1:{}", crate::free_port()).parse().unwrap();
        let mut fake = Self {
            addr,
            password: password.map(str::to_owned),
            tls,
            data: Arc::default(),
            commands: Arc::default(),
            task: None,
        };
        fake.resume().await;
        fake
    }

    /// Stops answering: the listener closes and open connections are dropped.
    pub fn stop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }

    /// Answers again on the same port, with the data it had.
    pub async fn resume(&mut self) {
        self.stop();
        let listener = loop {
            match TcpListener::bind(self.addr).await {
                Ok(listener) => break listener,
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(50)).await,
            }
        };
        let (data, password, tls, commands) = (
            self.data.clone(),
            self.password.clone(),
            self.tls.clone(),
            self.commands.clone(),
        );
        self.task = Some(tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    continue;
                };
                let (data, password, tls, commands) = (
                    data.clone(),
                    password.clone(),
                    tls.clone(),
                    commands.clone(),
                );
                connections.spawn(async move {
                    match tls {
                        Some(config) => {
                            let acceptor = tokio_rustls::TlsAcceptor::from(config);
                            if let Ok(stream) = acceptor.accept(stream).await {
                                serve(stream, &data, password.as_deref(), &commands).await;
                            }
                        }
                        None => serve(stream, &data, password.as_deref(), &commands).await,
                    }
                });
            }
        }));
    }

    /// The integer stored under `key`.
    pub fn get(&self, key: &str) -> Option<i64> {
        self.data
            .lock()
            .unwrap()
            .strings
            .get(key.as_bytes())
            .copied()
    }

    /// Keys holding integers that start with `prefix`.
    pub fn keys(&self, prefix: &str) -> Vec<String> {
        let data = self.data.lock().unwrap();
        let mut out: Vec<String> = data
            .strings
            .keys()
            .filter(|k| k.starts_with(prefix.as_bytes()))
            .map(|k| String::from_utf8_lossy(k).into_owned())
            .collect();
        out.sort();
        out
    }

    /// The expiry recorded for `key` (Unix milliseconds).
    pub fn expiry(&self, key: &str) -> Option<i64> {
        self.data
            .lock()
            .unwrap()
            .expiries
            .get(key.as_bytes())
            .copied()
    }

    /// Commands answered so far.
    pub fn commands(&self) -> u64 {
        self.commands.load(Ordering::SeqCst)
    }
}

impl Drop for FakeRedis {
    fn drop(&mut self) {
        self.stop();
    }
}

async fn read_command<R: AsyncRead + Unpin>(reader: &mut BufReader<R>) -> Option<Vec<Vec<u8>>> {
    let mut line = String::new();
    reader.read_line(&mut line).await.ok()?;
    let count: usize = line.trim_end().strip_prefix('*')?.parse().ok()?;
    let mut args = Vec::with_capacity(count);
    for _ in 0..count {
        line.clear();
        reader.read_line(&mut line).await.ok()?;
        let len: usize = line.trim_end().strip_prefix('$')?.parse().ok()?;
        let mut arg = vec![0u8; len + 2];
        reader.read_exact(&mut arg).await.ok()?;
        arg.truncate(len);
        args.push(arg);
    }
    Some(args)
}

fn integer(text: &[u8]) -> Option<i64> {
    std::str::from_utf8(text).ok()?.parse().ok()
}

fn score(text: &[u8]) -> Option<f64> {
    let text = std::str::from_utf8(text).ok()?;
    match text {
        "-inf" => Some(f64::NEG_INFINITY),
        "+inf" | "inf" => Some(f64::INFINITY),
        _ => text.parse().ok(),
    }
}

async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    data: &Mutex<Data>,
    password: Option<&str>,
    commands: &AtomicU64,
) {
    let mut reader = BufReader::new(stream);
    let mut authenticated = password.is_none();
    while let Some(args) = read_command(&mut reader).await {
        commands.fetch_add(1, Ordering::SeqCst);
        let name = String::from_utf8_lossy(args.first().map_or(&[][..], Vec::as_slice))
            .to_ascii_uppercase();
        let reply = if name == "AUTH" {
            let given = args.last().map(|p| String::from_utf8_lossy(p).into_owned());
            if password.is_some() && given.as_deref() == password {
                authenticated = true;
                "+OK\r\n".to_owned()
            } else {
                "-WRONGPASS invalid username-password pair or user is disabled.\r\n".to_owned()
            }
        } else if !authenticated {
            "-NOAUTH Authentication required.\r\n".to_owned()
        } else {
            execute(&name, &args, data)
        };
        if reader.get_mut().write_all(reply.as_bytes()).await.is_err() {
            return;
        }
    }
}

fn execute(name: &str, args: &[Vec<u8>], data: &Mutex<Data>) -> String {
    let mut data = data.lock().unwrap();
    let arg = |i: usize| args.get(i).cloned().unwrap_or_default();
    match name {
        "PING" => "+PONG\r\n".to_owned(),
        "TIME" => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            let (secs, micros) = (now.as_secs().to_string(), now.subsec_micros().to_string());
            format!(
                "*2\r\n${}\r\n{secs}\r\n${}\r\n{micros}\r\n",
                secs.len(),
                micros.len()
            )
        }
        "SELECT" => "+OK\r\n".to_owned(),
        "GET" => match data.strings.get(&arg(1)) {
            Some(n) => {
                let text = n.to_string();
                format!("${}\r\n{text}\r\n", text.len())
            }
            None => "$-1\r\n".to_owned(),
        },
        "INCRBY" | "DECRBY" => {
            let Some(by) = integer(&arg(2)) else {
                return "-ERR value is not an integer or out of range\r\n".to_owned();
            };
            let value = data.strings.entry(arg(1)).or_default();
            *value += if name == "INCRBY" { by } else { -by };
            format!(":{value}\r\n")
        }
        "PEXPIREAT" => {
            let Some(at) = integer(&arg(2)) else {
                return "-ERR value is not an integer or out of range\r\n".to_owned();
            };
            let exists = data.strings.contains_key(&arg(1)) || data.sets.contains_key(&arg(1));
            if exists {
                data.expiries.insert(arg(1), at);
            }
            format!(":{}\r\n", i32::from(exists))
        }
        "ZADD" => {
            let Some(s) = score(&arg(2)) else {
                return "-ERR value is not a valid float\r\n".to_owned();
            };
            let added = data
                .sets
                .entry(arg(1))
                .or_default()
                .insert(arg(3), s)
                .is_none();
            format!(":{}\r\n", i32::from(added))
        }
        "ZREMRANGEBYSCORE" => {
            let bound = |text: Vec<u8>| -> Option<(f64, bool)> {
                match text.strip_prefix(b"(") {
                    Some(rest) => score(rest).map(|s| (s, true)),
                    None => score(&text).map(|s| (s, false)),
                }
            };
            let (Some((min, min_open)), Some((max, max_open))) = (bound(arg(2)), bound(arg(3)))
            else {
                return "-ERR min or max is not a float\r\n".to_owned();
            };
            let set = data.sets.entry(arg(1)).or_default();
            let before = set.len();
            set.retain(|_, s| {
                let above = if min_open { *s > min } else { *s >= min };
                let below = if max_open { *s < max } else { *s <= max };
                !(above && below)
            });
            format!(":{}\r\n", before - set.len())
        }
        "ZCARD" => format!(":{}\r\n", data.sets.get(&arg(1)).map_or(0, BTreeMap::len)),
        other => format!("-ERR unknown command '{other}'\r\n"),
    }
}
