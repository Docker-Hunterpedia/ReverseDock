//! DNS-01 (ADR-0020): a [`DnsSolver`] publishes and removes the `_acme-challenge` TXT record,
//! and [`wait_until_visible`] checks the record at the zone's nameservers before the CA is
//! asked to validate.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::{RData, RecordType};
use rdock_model::acme::{DnsProvider, Webhook};
use tracing::debug;

use crate::http::WebhookClient;

/// How often the record is looked up while waiting for it.
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Why a DNS provider failed.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct DnsError(pub String);

/// Publishes and removes TXT records for DNS-01. Each call adds or removes one value, so two
/// challenges for the same name (a wildcard and its base name) can coexist.
#[async_trait]
pub trait DnsSolver: Send + Sync + fmt::Debug {
    /// Adds the TXT record `fqdn` = `value`.
    async fn present(&self, fqdn: &str, value: &str) -> Result<(), DnsError>;
    /// Removes the TXT record `fqdn` = `value`.
    async fn cleanup(&self, fqdn: &str, value: &str) -> Result<(), DnsError>;
}

/// Turns `acme.dns_providers` entries into solvers. The binary supplies one that also knows the
/// providers living in other crates (Cloudflare).
pub trait DnsProviders: Send + Sync + fmt::Debug {
    /// The solver for `config`.
    fn build(&self, config: &DnsProvider) -> Result<Arc<dyn DnsSolver>, DnsError>;
}

/// The providers built into this crate: `exec` and `webhook`.
#[derive(Debug, Default)]
pub struct BuiltinProviders;

impl DnsProviders for BuiltinProviders {
    fn build(&self, config: &DnsProvider) -> Result<Arc<dyn DnsSolver>, DnsError> {
        match config {
            DnsProvider::Exec {
                command,
                args,
                timeout,
            } => Ok(Arc::new(ExecSolver {
                command: command.clone(),
                args: args.clone(),
                timeout: timeout.as_std(),
            })),
            DnsProvider::Webhook(webhook) => Ok(Arc::new(WebhookSolver {
                webhook: webhook.clone(),
                client: WebhookClient::new().map_err(|e| DnsError(e.to_string()))?,
            })),
            DnsProvider::Cloudflare { .. }
            | DnsProvider::DigitalOcean(_)
            | DnsProvider::Hetzner(_)
            | DnsProvider::Rfc2136(_)
            | DnsProvider::Desec(_)
            | DnsProvider::Route53(_)
            | DnsProvider::GoogleCloudDns(_)
            | DnsProvider::AzureDns(_) => Err(DnsError(format!(
                "the {} DNS provider is not available in this build",
                provider_type(config)
            ))),
        }
    }
}

/// The `type` of a provider, as written in the configuration.
fn provider_type(config: &DnsProvider) -> &'static str {
    match config {
        DnsProvider::Cloudflare { .. } => "cloudflare",
        DnsProvider::Exec { .. } => "exec",
        DnsProvider::Webhook(_) => "webhook",
        DnsProvider::DigitalOcean(_) => "digitalocean",
        DnsProvider::Hetzner(_) => "hetzner",
        DnsProvider::Rfc2136(_) => "rfc2136",
        DnsProvider::Desec(_) => "desec",
        DnsProvider::Route53(_) => "route53",
        DnsProvider::GoogleCloudDns(_) => "google_cloud_dns",
        DnsProvider::AzureDns(_) => "azure_dns",
    }
}

/// Characters of an `exec` solver's standard error kept in its error message.
const STDERR_SHOWN: usize = 512;

/// Runs `<command> <args…> present|cleanup <fqdn> <value>` without a shell.
#[derive(Debug)]
struct ExecSolver {
    command: std::path::PathBuf,
    args: Vec<String>,
    timeout: Duration,
}

impl ExecSolver {
    async fn run(&self, action: &str, fqdn: &str, value: &str) -> Result<(), DnsError> {
        let mut command = tokio::process::Command::new(&self.command);
        command
            .args(&self.args)
            .args([action, fqdn, value])
            .stdin(std::process::Stdio::null())
            // Nothing reads standard output; buffering it would cost memory only.
            .stdout(std::process::Stdio::null())
            .kill_on_drop(true);
        let output = tokio::time::timeout(self.timeout, command.output())
            .await
            .map_err(|_| {
                DnsError(format!(
                    "`{}` did not finish within {:?}",
                    self.command.display(),
                    self.timeout
                ))
            })?
            .map_err(|e| DnsError(format!("cannot run `{}`: {e}", self.command.display())))?;
        if output.status.success() {
            return Ok(());
        }
        // The message reaches logs, the certificate status viewers read and alerts: the end of
        // standard error, where the reason usually is, and no more.
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr = stderr.trim();
        let tail = stderr
            .char_indices()
            .rev()
            .nth(STDERR_SHOWN.saturating_sub(1))
            .map_or(stderr, |(i, _)| &stderr[i..]);
        let cut = if tail.len() < stderr.len() { "…" } else { "" };
        Err(DnsError(format!(
            "`{}` {action} failed ({}): {cut}{tail}",
            self.command.display(),
            output.status,
        )))
    }
}

#[async_trait]
impl DnsSolver for ExecSolver {
    async fn present(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
        self.run("present", fqdn, value).await
    }

    async fn cleanup(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
        self.run("cleanup", fqdn, value).await
    }
}

/// POSTs `{"action", "name", "value"}` to an HTTPS endpoint.
#[derive(Debug)]
struct WebhookSolver {
    webhook: Webhook,
    client: WebhookClient,
}

impl WebhookSolver {
    async fn send(&self, action: &str, fqdn: &str, value: &str) -> Result<(), DnsError> {
        let body = serde_json::json!({ "action": action, "name": fqdn, "value": value });
        self.client
            .post(&self.webhook, &body)
            .await
            .map(|_| ())
            .map_err(|e| DnsError(format!("DNS webhook {action}: {e}")))
    }
}

#[async_trait]
impl DnsSolver for WebhookSolver {
    async fn present(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
        self.send("present", fqdn, value).await
    }

    async fn cleanup(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
        self.send("cleanup", fqdn, value).await
    }
}

/// Where the propagation check looks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup {
    /// These resolvers (`acme.dns_resolvers`).
    Resolvers(Vec<SocketAddr>),
    /// The authoritative nameservers of the record's zone, found through the system resolver.
    Authoritative,
}

/// Waits until `fqdn` has the TXT value `value`, or `timeout` passes. Returns whether it was
/// seen; the CA validates either way, so a slow or unreachable nameserver only costs time.
pub async fn wait_until_visible(
    fqdn: &str,
    value: &str,
    lookup: &Lookup,
    timeout: Duration,
) -> bool {
    let started = Instant::now();
    while started.elapsed() < timeout {
        let servers = match lookup {
            Lookup::Resolvers(servers) => servers.clone(),
            Lookup::Authoritative => authoritative_servers(fqdn).await,
        };
        if !servers.is_empty() && txt_values(fqdn, &servers).await.iter().any(|v| v == value) {
            return true;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    debug!(
        fqdn,
        "TXT record not visible in time; asking the CA to validate anyway"
    );
    false
}

/// A resolver asking only `servers`, without a cache, so every poll sees fresh answers.
fn resolver_for(servers: &[SocketAddr]) -> Option<TokioResolver> {
    let configs = servers
        .iter()
        .map(|addr| {
            let mut udp = ConnectionConfig::udp();
            udp.port = addr.port();
            let mut tcp = ConnectionConfig::tcp();
            tcp.port = addr.port();
            let mut config = NameServerConfig::udp_and_tcp(addr.ip());
            config.connections = vec![udp, tcp];
            config
        })
        .collect();
    let mut builder = hickory_resolver::Resolver::builder_with_config(
        ResolverConfig::from_name_servers(configs),
        TokioRuntimeProvider::default(),
    );
    builder.options_mut().cache_size = 0;
    builder.build().ok()
}

async fn txt_values(fqdn: &str, servers: &[SocketAddr]) -> Vec<String> {
    let Some(resolver) = resolver_for(servers) else {
        return Vec::new();
    };
    let Ok(answer) = resolver.lookup(format!("{fqdn}."), RecordType::TXT).await else {
        return Vec::new();
    };
    answer
        .answers()
        .iter()
        .filter_map(|record| match &record.data {
            RData::TXT(txt) => Some(
                txt.txt_data
                    .iter()
                    .map(|part| String::from_utf8_lossy(part).into_owned())
                    .collect(),
            ),
            _ => None,
        })
        .collect()
}

/// The addresses of the nameservers of the closest zone above `fqdn`.
async fn authoritative_servers(fqdn: &str) -> Vec<SocketAddr> {
    let Ok(system) = hickory_resolver::Resolver::builder_tokio()
        .and_then(hickory_resolver::ResolverBuilder::build)
    else {
        return Vec::new();
    };
    let mut zone = fqdn.trim_end_matches('.');
    while let Some((_, parent)) = zone.split_once('.') {
        zone = parent;
        let Ok(answer) = system.lookup(format!("{zone}."), RecordType::NS).await else {
            continue;
        };
        let hosts: Vec<String> = answer
            .answers()
            .iter()
            .filter_map(|r| match &r.data {
                RData::NS(ns) => Some(ns.0.to_string()),
                _ => None,
            })
            .collect();
        if hosts.is_empty() {
            continue;
        }
        let mut servers = Vec::new();
        for host in hosts {
            if let Ok(ips) = system.lookup_ip(host).await {
                servers.extend(ips.iter().map(|ip: IpAddr| SocketAddr::new(ip, 53)));
            }
        }
        return servers;
    }
    Vec::new()
}

/// `_acme-challenge.<name>`, without a wildcard label.
#[must_use]
pub fn challenge_name(name: &str) -> String {
    format!("_acme-challenge.{}", name.trim_start_matches("*."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_names_drop_the_wildcard() {
        assert_eq!(
            challenge_name("*.example.com"),
            "_acme-challenge.example.com"
        );
        assert_eq!(
            challenge_name("app.example.com"),
            "_acme-challenge.app.example.com"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn exec_runs_without_a_shell_and_reports_failures() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("calls");
        let script = dir.path().join("hook.sh");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\necho \"$@\" >> {}\n[ \"$3\" != fail ]\n",
                log.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        let solver = ExecSolver {
            command: script,
            args: vec!["--zone".into()],
            timeout: Duration::from_secs(5),
        };
        solver
            .present("_acme-challenge.a.example.com", "v; rm -rf /")
            .await
            .unwrap();
        assert!(solver.cleanup("fail", "x").await.is_err());
        let calls = std::fs::read_to_string(&log).unwrap();
        assert_eq!(
            calls,
            "--zone present _acme-challenge.a.example.com v; rm -rf /\n--zone cleanup fail x\n"
        );
        // A failure reports only the end of standard error (it reaches logs, the status
        // viewers read and alerts). In this test, not one of its own: scripts written while
        // another test spawns one can fail with `ETXTBSY`.
        let script = dir.path().join("noisy.sh");
        std::fs::write(
            &script,
            "#!/bin/sh\ni=0\nwhile [ $i -lt 2000 ]; do echo secret-line-$i >&2; i=$((i+1)); done\necho the-reason >&2\nexit 1\n",
        )
        .unwrap();
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        let solver = ExecSolver {
            command: script,
            args: Vec::new(),
            timeout: Duration::from_secs(10),
        };
        let err = solver.present("x", "y").await.unwrap_err().0;
        assert!(err.ends_with("the-reason"), "{err}");
        assert!(!err.contains("secret-line-0\n"), "{err}");
        assert!(err.len() < STDERR_SHOWN + 200, "{}", err.len());
    }
}
