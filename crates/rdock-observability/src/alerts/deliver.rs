//! Delivery to each channel type. HTTP channels go through a resolver that refuses private,
//! loopback and link-local addresses unless the channel allows them, so the address checked is
//! the address connected to; redirects are not followed and every request has 5 seconds.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use http::{Request, header};
use http_body_util::Full;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::connect::dns::Name;
use hyper_util::rt::TokioExecutor;
use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use rdock_model::settings::{AlertChannel, AlertRule, Alerts, SmtpTls};
use serde_json::{Value, json};

use super::{Alert, State};

const TIMEOUT: Duration = Duration::from_secs(5);
const ATTEMPTS: u32 = 3;

/// Whether an address is one a public alert service never has.
fn private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1])
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|v4| private(IpAddr::V4(v4)))
        }
    }
}

/// Whether `url` names its host by a private IP address. The connector skips the resolver
/// for IP literals, so `Guarded` never sees them and they are checked here instead.
fn private_literal(url: &str) -> bool {
    url.parse::<http::Uri>()
        .ok()
        .and_then(|uri| {
            let host = uri.host()?;
            let bare = host.strip_prefix('[').and_then(|h| h.strip_suffix(']'));
            bare.unwrap_or(host).parse::<IpAddr>().ok()
        })
        .is_some_and(private)
}

/// Resolves names and drops private addresses unless allowed.
#[derive(Clone)]
struct Guarded {
    allow_private: bool,
}

impl tower_service::Service<Name> for Guarded {
    type Response = std::vec::IntoIter<SocketAddr>;
    type Error = std::io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, name: Name) -> Self::Future {
        let allow_private = self.allow_private;
        Box::pin(async move {
            let found: Vec<SocketAddr> =
                tokio::net::lookup_host((name.as_str(), 0)).await?.collect();
            let allowed: Vec<SocketAddr> = found
                .iter()
                .copied()
                .filter(|a| allow_private || !private(a.ip()))
                .collect();
            if allowed.is_empty() {
                return Err(std::io::Error::other(format!(
                    "{} resolves only to private addresses; set allow_private_targets: true to allow it",
                    name.as_str()
                )));
            }
            Ok(allowed.into_iter())
        })
    }
}

type Http = Client<HttpsConnector<HttpConnector<Guarded>>, Full<Bytes>>;

/// HTTP clients for public and for private targets.
#[derive(Clone)]
pub(super) struct Clients {
    public: Http,
    private: Http,
}

fn client(allow_private: bool) -> Result<Http, String> {
    let mut http = HttpConnector::new_with_resolver(Guarded { allow_private });
    http.enforce_http(false);
    http.set_connect_timeout(Some(TIMEOUT));
    let connector = HttpsConnectorBuilder::new()
        .try_with_platform_verifier()
        .map_err(|e| e.to_string())?
        .https_or_http()
        .enable_http1()
        .wrap_connector(http);
    Ok(Client::builder(TokioExecutor::new()).build(connector))
}

impl Clients {
    pub(super) fn new() -> Result<Self, String> {
        Ok(Self {
            public: client(false)?,
            private: client(true)?,
        })
    }
}

/// Every channel, with `alerts.webhook` (v0.3) as one named `webhook`.
pub(super) fn channels(settings: &Alerts) -> Vec<(String, AlertChannel)> {
    let mut out: Vec<(String, AlertChannel)> = settings
        .channels
        .iter()
        .map(|(n, c)| (n.clone(), c.clone()))
        .collect();
    if let Some(webhook) = &settings.webhook {
        let loopback = webhook
            .url
            .as_url()
            .host_str()
            .and_then(|h| h.trim_matches(['[', ']']).parse::<IpAddr>().ok())
            .is_some_and(|ip| ip.is_loopback())
            || webhook.url.as_url().host_str() == Some("localhost");
        out.push((
            "webhook".to_owned(),
            AlertChannel::Webhook {
                url: webhook.url.as_url().to_string(),
                secret: None,
                token: webhook.token.clone(),
                rules: Vec::new(),
                allow_private_targets: loopback,
            },
        ));
    }
    out
}

/// Whether `channel` takes alerts of `rule`.
pub(super) fn wants(channel: &AlertChannel, rule: AlertRule) -> bool {
    let rules = match channel {
        AlertChannel::Slack { rules, .. }
        | AlertChannel::Discord { rules, .. }
        | AlertChannel::SlackCompatible { rules, .. }
        | AlertChannel::Webhook { rules, .. }
        | AlertChannel::Smtp { rules, .. } => rules,
    };
    rules.is_empty() || rules.contains(&rule)
}

fn secret(value: &str) -> Result<String, String> {
    rdock_config::interpolate::expand(value, &rdock_config::System)
        .map(|v| v.trim().to_owned())
        .map_err(|e| e.to_string())
}

/// `[FIRING] summary` or `[RESOLVED] summary`.
pub(super) fn line(alert: &Alert) -> String {
    let state = match alert.state {
        State::Firing => "FIRING",
        State::Resolved => "RESOLVED",
    };
    format!("[{state}] {}", alert.summary)
}

/// The JSON a `webhook` channel receives: the alert, plus its details at the top level so
/// v0.3 receivers keep their fields (`event`, `names`, …).
pub(super) fn webhook_body(alert: &Alert) -> Value {
    let mut body = match &alert.details {
        Value::Object(map) => Value::Object(map.clone()),
        _ => json!({}),
    };
    body["type"] = json!(match alert.state {
        State::Firing => "rdock.alert.firing",
        State::Resolved => "rdock.alert.resolved",
    });
    body["timestamp"] = json!(crate::rfc3339(std::time::SystemTime::now()));
    body["alert"] = json!(alert);
    body
}

/// `webhook-signature` of Standard Webhooks: `v1,` and the base64 HMAC-SHA256 of
/// `id.timestamp.body` with the decoded `whsec_` secret.
pub(super) fn sign(secret: &str, id: &str, timestamp: u64, body: &str) -> Result<String, String> {
    let key = STANDARD
        .decode(secret.strip_prefix("whsec_").unwrap_or(secret))
        .map_err(|_| "the webhook secret is not whsec_ followed by base64".to_owned())?;
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key);
    let tag = ring::hmac::sign(&key, format!("{id}.{timestamp}.{body}").as_bytes());
    Ok(format!("v1,{}", STANDARD.encode(tag.as_ref())))
}

async fn post(
    clients: &Clients,
    allow_private: bool,
    url: &str,
    body: &Value,
    headers: Vec<(&'static str, String)>,
) -> Result<(), String> {
    if !allow_private && private_literal(url) {
        return Err(
            "the URL names a private address; set allow_private_targets: true to allow it"
                .to_owned(),
        );
    }
    let mut request = Request::post(url)
        .header(header::CONTENT_TYPE, "application/json")
        .header(
            header::USER_AGENT,
            concat!("rdock/", env!("CARGO_PKG_VERSION")),
        );
    for (name, value) in headers {
        request = request.header(name, value);
    }
    let request = request
        .body(Full::new(Bytes::from(body.to_string())))
        .map_err(|e| e.to_string())?;
    let client = if allow_private {
        &clients.private
    } else {
        &clients.public
    };
    let response = tokio::time::timeout(TIMEOUT, client.request(request))
        .await
        .map_err(|_| "no answer within 5 s".to_owned())?
        .map_err(|e| {
            format!(
                "{e}: {}",
                std::error::Error::source(&e)
                    .map(ToString::to_string)
                    .unwrap_or_default()
            )
        })?;
    let status = response.status();
    if status.is_success() {
        Ok(())
    } else {
        Err(format!(
            "answered {status}{}",
            if status.is_redirection() {
                " (redirects are not followed)"
            } else {
                ""
            }
        ))
    }
}

async fn send(clients: &Clients, channel: &AlertChannel, alert: &Alert) -> Result<(), String> {
    match channel {
        AlertChannel::Slack {
            url,
            allow_private_targets,
            ..
        }
        | AlertChannel::SlackCompatible {
            url,
            allow_private_targets,
            ..
        } => {
            post(
                clients,
                *allow_private_targets,
                &secret(url)?,
                &json!({ "text": line(alert) }),
                Vec::new(),
            )
            .await
        }
        AlertChannel::Discord {
            url,
            allow_private_targets,
            ..
        } => {
            let body = json!({ "content": line(alert), "allowed_mentions": { "parse": [] } });
            post(
                clients,
                *allow_private_targets,
                &secret(url)?,
                &body,
                Vec::new(),
            )
            .await
        }
        AlertChannel::Webhook {
            url,
            secret: signing,
            token,
            allow_private_targets,
            ..
        } => {
            let body = webhook_body(alert);
            let text = body.to_string();
            let mut headers = Vec::new();
            if let Some(signing) = signing {
                let id = format!("msg_{:016x}", fastrand::u64(..));
                let timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs());
                headers.push((
                    "webhook-signature",
                    sign(&secret(signing)?, &id, timestamp, &text)?,
                ));
                headers.push(("webhook-id", id));
                headers.push(("webhook-timestamp", timestamp.to_string()));
            }
            if let Some(token) = token {
                headers.push(("authorization", format!("Bearer {}", secret(token)?)));
            }
            post(
                clients,
                *allow_private_targets,
                &secret(url)?,
                &body,
                headers,
            )
            .await
        }
        AlertChannel::Smtp {
            host,
            port,
            tls,
            username,
            password,
            from,
            to,
            ..
        } => {
            smtp(
                host,
                *port,
                *tls,
                (username.as_deref(), password.as_deref()),
                from,
                to,
                alert,
            )
            .await
        }
    }
}

async fn smtp(
    host: &str,
    port: u16,
    tls: SmtpTls,
    login: (Option<&str>, Option<&str>),
    from: &str,
    to: &[String],
    alert: &Alert,
) -> Result<(), String> {
    let builder = match tls {
        SmtpTls::Starttls => {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host).map_err(|e| e.to_string())?
        }
        SmtpTls::Implicit => {
            AsyncSmtpTransport::<Tokio1Executor>::relay(host).map_err(|e| e.to_string())?
        }
        SmtpTls::None => {
            let loopback =
                host == "localhost" || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback());
            if !loopback {
                return Err("plain SMTP is only allowed to a loopback relay".to_owned());
            }
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host)
        }
    };
    let mut builder = builder.port(port).timeout(Some(TIMEOUT));
    if let (Some(user), Some(password)) = login {
        builder = builder.credentials(Credentials::new(secret(user)?, secret(password)?));
    }
    let mut message = Message::builder()
        .from(from.parse::<Mailbox>().map_err(|e| format!("from: {e}"))?)
        .subject(format!("rdock {}", line(alert)));
    for recipient in to {
        message = message.to(recipient
            .parse::<Mailbox>()
            .map_err(|e| format!("to {recipient}: {e}"))?);
    }
    let details = serde_json::to_string_pretty(&alert.details).unwrap_or_default();
    let body = format!(
        "{}\n\nRule: {:?}\nKey: {}\n\n{details}\n",
        line(alert),
        alert.rule,
        alert.key
    );
    let message = message.body(body).map_err(|e| e.to_string())?;
    builder
        .build()
        .send(message)
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Sends with up to three attempts, waiting about 1 s and 3 s (plus jitter) between them.
pub(super) async fn with_retries(
    clients: &Clients,
    name: &str,
    channel: &AlertChannel,
    alert: &Alert,
) -> Result<(), String> {
    let mut last = String::new();
    for attempt in 0..ATTEMPTS {
        if attempt > 0 {
            let wait = Duration::from_millis(1000 * 3u64.pow(attempt - 1) + fastrand::u64(0..500));
            tokio::time::sleep(wait).await;
        }
        match send(clients, channel, alert).await {
            Ok(()) => return Ok(()),
            Err(err) => {
                tracing::debug!(channel = name, attempt, error = %err, "alert delivery failed");
                last = err;
            }
        }
    }
    Err(last)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_ip_literals_in_urls_are_recognised() {
        for url in [
            "https://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1:8080/hook",
            "https://10.1.2.3/",
            "https://[::1]/hook",
            "https://[fd00::1]:8443/",
        ] {
            assert!(private_literal(url), "{url}");
        }
        for url in [
            "https://hooks.slack.com/services/x",
            "https://1.1.1.1/",
            "https://[2606:4700::1111]/",
            "not a url",
        ] {
            assert!(!private_literal(url), "{url}");
        }
    }

    #[test]
    fn private_addresses_are_recognised() {
        for ip in [
            "10.1.2.3",
            "192.168.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:10.0.0.1",
        ] {
            assert!(private(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["1.1.1.1", "2606:4700::1111"] {
            assert!(!private(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn standard_webhooks_signature_matches_the_reference() {
        // The example from the Standard Webhooks specification.
        let secret = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
        let id = "msg_p5jXN8AQM9LWM0D4loKWxJek";
        let body = r#"{"test": 2432232314}"#;
        let signature = sign(secret, id, 1_614_265_330, body).unwrap();
        assert_eq!(signature, "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=");
    }

    #[test]
    fn webhook_bodies_keep_the_v0_3_fields() {
        let alert = Alert::firing(
            AlertRule::Certificates,
            "cert:a.example",
            "renewal failing",
            json!({ "event": "certificate_renewal_failing", "names": ["a.example"] }),
        );
        let body = webhook_body(&alert);
        assert_eq!(body["event"], "certificate_renewal_failing");
        assert_eq!(body["type"], "rdock.alert.firing");
        assert_eq!(body["alert"]["key"], "cert:a.example");
        assert_eq!(line(&alert), "[FIRING] renewal failing");
    }
}
