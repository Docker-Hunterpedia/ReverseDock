//! A small client for Redis-compatible servers (RESP2), enough for cluster-scoped limits:
//! one connection, one command at a time, every step under a timeout, TLS through rustls and
//! `AUTH` with the password from a secret reference. It never logs the password or a reply.
//!
//! RESP2 is described in the Redis documentation, "Redis serialization protocol specification"
//! (<https://redis.io/docs/latest/develop/reference/protocol-spec/>, read 2026-11-13): commands
//! are arrays of bulk strings; replies are simple strings (`+`), errors (`-`), integers (`:`),
//! bulk strings (`$`, `-1` for nil) and arrays (`*`).

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

/// The longest bulk string or array accepted in a reply.
const MAX_REPLY: usize = 1 << 20;

/// A reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    /// `+OK`.
    Simple(String),
    /// `:42`.
    Integer(i64),
    /// `$…`, `None` for nil.
    Bulk(Option<Vec<u8>>),
    /// `*…`, `None` for nil.
    Array(Option<Vec<Reply>>),
}

/// Why a command failed.
#[derive(Debug, thiserror::Error)]
pub enum RespError {
    /// The server could not be reached, the connection broke or a step timed out.
    #[error("redis unreachable: {0}")]
    Unreachable(String),
    /// The server answered with an error (`-ERR …`).
    #[error("redis refused: {0}")]
    Refused(String),
    /// The reply was not what the command returns.
    #[error("redis protocol: {0}")]
    Protocol(String),
}

/// How to reach the server.
#[derive(Clone)]
pub struct RespSettings {
    /// Host name or IP address.
    pub host: String,
    /// Port.
    pub port: u16,
    /// The database to `SELECT` (0 is not selected explicitly).
    pub database: u32,
    /// TLS, verified against `tls` roots.
    pub tls: Option<Arc<rustls::ClientConfig>>,
    /// The ACL user, sent with the password.
    pub username: Option<String>,
    /// The password (never logged).
    pub password: Option<String>,
    /// Limit of each connect, handshake and command.
    pub timeout: Duration,
}

impl fmt::Debug for RespSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RespSettings")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("database", &self.database)
            .field("tls", &self.tls.is_some())
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "<secret>"))
            .field("timeout", &self.timeout)
            .finish()
    }
}

trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

/// A client with one lazily opened connection, reopened after any failure.
pub struct RespClient {
    settings: RespSettings,
    connection: Mutex<Option<BufReader<Box<dyn Stream>>>>,
}

impl fmt::Debug for RespClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RespClient")
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

/// A command as RESP: an array of bulk strings.
#[must_use]
pub fn encode(args: &[&[u8]]) -> Vec<u8> {
    let mut out = format!("*{}\r\n", args.len()).into_bytes();
    for arg in args {
        out.extend_from_slice(format!("${}\r\n", arg.len()).as_bytes());
        out.extend_from_slice(arg);
        out.extend_from_slice(b"\r\n");
    }
    out
}

/// Reads one reply.
pub async fn read_reply<R: AsyncBufReadExt + Unpin + Send>(
    reader: &mut R,
) -> Result<Reply, RespError> {
    Box::pin(read_reply_inner(reader, 0)).await
}

async fn read_line<R: AsyncBufReadExt + Unpin + Send>(reader: &mut R) -> Result<String, RespError> {
    let mut line = Vec::new();
    let read = reader
        .take(MAX_REPLY as u64)
        .read_until(b'\n', &mut line)
        .await
        .map_err(|e| RespError::Unreachable(e.to_string()))?;
    if read == 0 {
        return Err(RespError::Unreachable("the connection closed".to_owned()));
    }
    if !line.ends_with(b"\r\n") {
        return Err(RespError::Protocol("a line without CRLF".to_owned()));
    }
    line.truncate(line.len() - 2);
    String::from_utf8(line).map_err(|_| RespError::Protocol("a line that is not UTF-8".to_owned()))
}

fn length(text: &str) -> Result<Option<usize>, RespError> {
    if text == "-1" {
        return Ok(None);
    }
    let n: usize = text
        .parse()
        .map_err(|_| RespError::Protocol(format!("a bad length `{text}`")))?;
    if n > MAX_REPLY {
        return Err(RespError::Protocol("a reply too large".to_owned()));
    }
    Ok(Some(n))
}

async fn read_reply_inner<R: AsyncBufReadExt + Unpin + Send>(
    reader: &mut R,
    depth: usize,
) -> Result<Reply, RespError> {
    if depth > 4 {
        return Err(RespError::Protocol("arrays nested too deeply".to_owned()));
    }
    let line = read_line(reader).await?;
    let (kind, rest) = line.split_at(line.len().min(1));
    match kind {
        "+" => Ok(Reply::Simple(rest.to_owned())),
        // An error inside an array leaves the rest of the array unread: the connection is out
        // of step and must not be used again (review finding L7).
        "-" if depth > 0 => Err(RespError::Protocol(
            "an error inside an array reply".to_owned(),
        )),
        "-" => Err(RespError::Refused(rest.to_owned())),
        ":" => rest
            .parse()
            .map(Reply::Integer)
            .map_err(|_| RespError::Protocol(format!("a bad integer `{rest}`"))),
        "$" => match length(rest)? {
            None => Ok(Reply::Bulk(None)),
            Some(n) => {
                let mut data = vec![0u8; n + 2];
                reader
                    .read_exact(&mut data)
                    .await
                    .map_err(|e| RespError::Unreachable(e.to_string()))?;
                if !data.ends_with(b"\r\n") {
                    return Err(RespError::Protocol("a bulk string without CRLF".to_owned()));
                }
                data.truncate(n);
                Ok(Reply::Bulk(Some(data)))
            }
        },
        "*" => match length(rest)? {
            None => Ok(Reply::Array(None)),
            Some(n) => {
                let mut items = Vec::with_capacity(n.min(64));
                for _ in 0..n {
                    items.push(Box::pin(read_reply_inner(reader, depth + 1)).await?);
                }
                Ok(Reply::Array(Some(items)))
            }
        },
        _ => Err(RespError::Protocol("an unknown reply type".to_owned())),
    }
}

impl Reply {
    /// The reply to `TIME` as milliseconds since the Unix epoch, by the server's clock.
    pub fn time_ms(&self) -> Result<u64, RespError> {
        let bad = || RespError::Protocol(format!("expected the reply to TIME, got {self:?}"));
        let Self::Array(Some(items)) = self else {
            return Err(bad());
        };
        let number = |i: usize| -> Option<u64> {
            match items.get(i)? {
                Self::Bulk(Some(text)) => std::str::from_utf8(text).ok()?.parse().ok(),
                _ => None,
            }
        };
        let (secs, micros) = (number(0).ok_or_else(bad)?, number(1).ok_or_else(bad)?);
        Ok(secs.saturating_mul(1000).saturating_add(micros / 1000))
    }

    /// The integer of an integer reply.
    pub fn integer(&self) -> Result<i64, RespError> {
        match self {
            Self::Integer(n) => Ok(*n),
            other => Err(RespError::Protocol(format!(
                "expected an integer, got {other:?}"
            ))),
        }
    }
}

impl RespClient {
    /// A client; nothing is connected until the first command.
    #[must_use]
    pub fn new(settings: RespSettings) -> Self {
        Self {
            settings,
            connection: Mutex::new(None),
        }
    }

    async fn open(&self) -> Result<BufReader<Box<dyn Stream>>, RespError> {
        let s = &self.settings;
        let tcp = tokio::time::timeout(s.timeout, TcpStream::connect((s.host.as_str(), s.port)))
            .await
            .map_err(|_| RespError::Unreachable("connecting timed out".to_owned()))?
            .map_err(|e| RespError::Unreachable(e.to_string()))?;
        let _ = tcp.set_nodelay(true);
        let stream: Box<dyn Stream> = match &s.tls {
            Some(config) => {
                let name = rustls_pki_types::ServerName::try_from(s.host.clone())
                    .map_err(|e| RespError::Unreachable(format!("server name: {e}")))?;
                let connector = tokio_rustls::TlsConnector::from(config.clone());
                let tls = tokio::time::timeout(s.timeout, connector.connect(name, tcp))
                    .await
                    .map_err(|_| RespError::Unreachable("the TLS handshake timed out".to_owned()))?
                    .map_err(|e| RespError::Unreachable(format!("TLS: {e}")))?;
                Box::new(tls)
            }
            None => Box::new(tcp),
        };
        let mut connection = BufReader::new(stream);
        if let Some(password) = &s.password {
            let reply = match &s.username {
                Some(user) => {
                    roundtrip(
                        &mut connection,
                        &[b"AUTH", user.as_bytes(), password.as_bytes()],
                        s.timeout,
                    )
                    .await
                }
                None => {
                    roundtrip(&mut connection, &[b"AUTH", password.as_bytes()], s.timeout).await
                }
            };
            // The server's message, never the command (it holds the password).
            reply.map_err(|e| match e {
                RespError::Refused(m) => RespError::Refused(format!("AUTH: {m}")),
                other => other,
            })?;
        }
        if s.database != 0 {
            let db = s.database.to_string();
            roundtrip(&mut connection, &[b"SELECT", db.as_bytes()], s.timeout).await?;
        }
        Ok(connection)
    }

    /// Sends one command and reads its reply. After any error (a refusal, a timeout, a broken
    /// or malformed reply) the connection is dropped and opened again on the next command, so
    /// a reply left half read is never taken for the next command's (review finding L7).
    pub async fn command(&self, args: &[&[u8]]) -> Result<Reply, RespError> {
        let mut guard = self.connection.lock().await;
        if guard.is_none() {
            *guard = Some(self.open().await?);
        }
        let Some(connection) = guard.as_mut() else {
            return Err(RespError::Unreachable("no connection".to_owned()));
        };
        let result = roundtrip(connection, args, self.settings.timeout).await;
        if result.is_err() {
            *guard = None;
        }
        result
    }
}

async fn roundtrip(
    connection: &mut BufReader<Box<dyn Stream>>,
    args: &[&[u8]],
    timeout: Duration,
) -> Result<Reply, RespError> {
    let work = async {
        connection
            .get_mut()
            .write_all(&encode(args))
            .await
            .map_err(|e| RespError::Unreachable(e.to_string()))?;
        connection
            .get_mut()
            .flush()
            .await
            .map_err(|e| RespError::Unreachable(e.to_string()))?;
        read_reply(connection).await
    };
    tokio::time::timeout(timeout, work)
        .await
        .map_err(|_| RespError::Unreachable("the command timed out".to_owned()))?
}

/// The TLS client configuration for `rediss://`: `ca_pem` (PEM certificates) as the only
/// roots, or the system's roots.
pub fn tls_config(ca_pem: Option<&str>) -> Result<Arc<rustls::ClientConfig>, String> {
    use rustls_pki_types::pem::PemObject;
    use rustls_platform_verifier::BuilderVerifierExt;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?;
    let verified = match ca_pem {
        Some(pem) => {
            let mut roots = rustls::RootCertStore::empty();
            for certificate in rustls_pki_types::CertificateDer::pem_slice_iter(pem.as_bytes()) {
                roots
                    .add(certificate.map_err(|e| e.to_string())?)
                    .map_err(|e| e.to_string())?;
            }
            if roots.is_empty() {
                return Err("no certificate in the CA file".to_owned());
            }
            builder.with_root_certificates(roots)
        }
        None => builder
            .with_platform_verifier()
            .map_err(|e| e.to_string())?,
    };
    Ok(Arc::new(verified.with_no_client_auth()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands_are_arrays_of_bulk_strings() {
        assert_eq!(
            encode(&[b"INCRBY", b"k", b"5"]),
            b"*3\r\n$6\r\nINCRBY\r\n$1\r\nk\r\n$1\r\n5\r\n"
        );
    }

    #[tokio::test]
    async fn replies_are_parsed() {
        let input: &[u8] = b"+OK\r\n:42\r\n$3\r\nabc\r\n$-1\r\n*2\r\n:1\r\n$1\r\nx\r\n-ERR no\r\n";
        let mut reader = BufReader::new(input);
        assert_eq!(
            read_reply(&mut reader).await.unwrap(),
            Reply::Simple("OK".into())
        );
        assert_eq!(read_reply(&mut reader).await.unwrap(), Reply::Integer(42));
        assert_eq!(
            read_reply(&mut reader).await.unwrap(),
            Reply::Bulk(Some(b"abc".to_vec()))
        );
        assert_eq!(read_reply(&mut reader).await.unwrap(), Reply::Bulk(None));
        assert_eq!(
            read_reply(&mut reader).await.unwrap(),
            Reply::Array(Some(vec![
                Reply::Integer(1),
                Reply::Bulk(Some(b"x".to_vec()))
            ]))
        );
        assert!(matches!(
            read_reply(&mut reader).await,
            Err(RespError::Refused(m)) if m == "ERR no"
        ));
        // An error inside an array is a protocol error (the connection is dropped).
        let mut nested = BufReader::new(&b"*2\r\n-ERR inner\r\n:1\r\n"[..]);
        assert!(matches!(
            read_reply(&mut nested).await,
            Err(RespError::Protocol(_))
        ));
        let mut bad = BufReader::new(&b"$99999999\r\n"[..]);
        assert!(matches!(
            read_reply(&mut bad).await,
            Err(RespError::Protocol(_))
        ));
    }

    #[test]
    fn the_password_is_not_in_debug_output() {
        let settings = RespSettings {
            host: "localhost".into(),
            port: 6379,
            database: 0,
            tls: None,
            username: None,
            password: Some("hunter2-secret".into()),
            timeout: Duration::from_secs(1),
        };
        assert!(!format!("{settings:?}").contains("hunter2"));
    }
}
