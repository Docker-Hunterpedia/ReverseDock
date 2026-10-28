//! One certificate order: identifiers, challenges, CSR, download.

use std::net::IpAddr;
use std::time::Duration;

use instant_acme::{
    Account, AuthorizationStatus, CertificateIdentifier, ChallengeType, Identifier, NewOrder,
    Order, OrderStatus, RetryPolicy,
};
use std::sync::Arc;

use rcgen::{CertificateParams, CustomExtension, DistinguishedName, DnType, KeyPair};
use rdock_tls::Challenges;
use tracing::warn;

use crate::dns::{DnsError, DnsSolver, Lookup, challenge_name, wait_until_visible};
use rustls::sign::CertifiedKey;
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

/// How long the CA may take to validate the challenges.
const VALIDATION_TIMEOUT: Duration = Duration::from_secs(120);
/// How long the CA may take to sign after finalization.
const SIGNING_TIMEOUT: Duration = Duration::from_secs(60);

/// A freshly issued certificate.
#[derive(Debug)]
pub struct Issued {
    /// The chain, leaf first, as PEM.
    pub chain_pem: String,
    /// The new private key (ECDSA P-256), as PKCS#8 PEM.
    pub key_pem: String,
}

/// Why an order failed.
#[derive(Debug, thiserror::Error)]
pub enum IssueError {
    /// The CA or the network failed.
    #[error(transparent)]
    Acme(#[from] instant_acme::Error),
    /// The CA offers no challenge this server can answer.
    #[error("the CA offers no usable challenge for `{0}`")]
    NoChallenge(String),
    /// Validation failed.
    #[error("validation failed: {0}")]
    Invalid(String),
    /// Key or CSR generation failed.
    #[error("cannot create the key or signing request: {0}")]
    Csr(#[from] rcgen::Error),
    /// The DNS provider failed.
    #[error("DNS provider: {0}")]
    Dns(#[from] DnsError),
    /// The TLS-ALPN-01 validation certificate could not be built.
    #[error("cannot build the TLS-ALPN-01 certificate: {0}")]
    ValidationCert(String),
}

/// What to order.
#[derive(Debug, Clone, Copy)]
pub struct OrderSpec<'a> {
    /// Names on the certificate.
    pub names: &'a [String],
    /// Profile to ask for.
    pub profile: Option<&'a str>,
    /// Challenge types this server can answer, most preferred first.
    pub challenge_types: &'a [ChallengeType],
    /// The certificate this order replaces (RFC 9773 `replaces`).
    pub replaces: Option<&'a CertificateIdentifier<'static>>,
    /// How to answer DNS-01, when the request names a DNS provider.
    pub dns: Option<&'a DnsChallenge>,
}

/// A DNS provider and how to check that its records are visible.
#[derive(Debug, Clone)]
pub struct DnsChallenge {
    /// Publishes and removes the TXT records.
    pub solver: Arc<dyn DnsSolver>,
    /// Where to look for the record before validation.
    pub lookup: Lookup,
    /// How long to wait for the record to appear.
    pub timeout: Duration,
}

/// Removes the challenge answers when the order ends, whatever the outcome. DNS records need
/// an async call and are removed by [`Answers::remove_dns`].
struct Answers<'a> {
    challenges: &'a Challenges,
    tokens: Vec<String>,
    names: Vec<String>,
    /// `(fqdn, value)` of published TXT records.
    dns: Vec<(String, String)>,
    /// Names whose authorization uses DNS-01.
    dns_names: Vec<String>,
}

impl Answers<'_> {
    async fn remove_dns(&mut self, dns: Option<&DnsChallenge>) {
        let Some(dns) = dns else { return };
        for (fqdn, value) in self.dns.drain(..) {
            if let Err(e) = dns.solver.cleanup(&fqdn, &value).await {
                warn!(fqdn = %fqdn, error = %e, "cannot remove the DNS-01 record");
            }
        }
    }
}

impl Drop for Answers<'_> {
    fn drop(&mut self) {
        for token in &self.tokens {
            self.challenges.remove_http01(token);
        }
        for name in &self.names {
            self.challenges.remove_tls_alpn01(name);
        }
    }
}

/// Orders a certificate from `account`, answering challenges through `challenges`. Each
/// certificate gets a new private key.
pub async fn issue(
    account: &Account,
    spec: OrderSpec<'_>,
    challenges: &Challenges,
) -> Result<Issued, IssueError> {
    let mut order = new_order(account, spec).await?;
    let mut answers = Answers {
        challenges,
        tokens: Vec::new(),
        names: Vec::new(),
        dns: Vec::new(),
        dns_names: Vec::new(),
    };
    let validated = validate(&mut order, spec, &mut answers).await;
    answers.remove_dns(spec.dns).await;
    drop(answers);
    validated?;
    let key = KeyPair::generate()?;
    let csr = csr_params(spec.names)?.serialize_request(&key)?;
    order.finalize_csr(csr.der()).await?;
    let chain_pem = order
        .poll_certificate(&RetryPolicy::new().timeout(SIGNING_TIMEOUT))
        .await?;
    Ok(Issued {
        chain_pem,
        key_pem: key.serialize_pem(),
    })
}

/// Publishes an answer for every pending authorization, tells the CA to validate, and waits.
async fn validate(
    order: &mut Order,
    spec: OrderSpec<'_>,
    answers: &mut Answers<'_>,
) -> Result<(), IssueError> {
    let mut authorizations = order.authorizations();
    while let Some(authorization) = authorizations.next().await {
        let mut authorization = authorization?;
        if authorization.status == AuthorizationStatus::Valid {
            continue;
        }
        let name = authorization.identifier().to_string();
        let is_ip = matches!(authorization.identifier().identifier, Identifier::Ip(_));
        let offered = spec
            .challenge_types
            .iter()
            .filter(|t| !(is_ip && **t != ChallengeType::Http01))
            .find(|t| authorization.challenges.iter().any(|c| c.r#type == **t))
            .cloned()
            .ok_or_else(|| IssueError::NoChallenge(name.clone()))?;
        let mut challenge = authorization
            .challenge(offered.clone())
            .ok_or_else(|| IssueError::NoChallenge(name.clone()))?;
        let key_authorization = challenge.key_authorization();
        match offered {
            ChallengeType::Dns01 => {
                let dns = spec
                    .dns
                    .ok_or_else(|| IssueError::NoChallenge(name.clone()))?;
                let (fqdn, value) = (challenge_name(&name), key_authorization.dns_value());
                dns.solver.present(&fqdn, &value).await?;
                answers.dns.push((fqdn, value));
                answers.dns_names.push(name);
                // Validation is requested once the record is visible, below.
                continue;
            }
            ChallengeType::TlsAlpn01 => {
                let certificate =
                    validation_certificate(&name, key_authorization.digest().as_ref())?;
                answers.challenges.add_tls_alpn01(&name, &certificate);
                answers.names.push(name);
            }
            _ => {
                let token = challenge.token.clone();
                answers
                    .challenges
                    .add_http01(&token, key_authorization.as_str());
                answers.tokens.push(token);
            }
        }
        challenge.set_ready().await?;
    }
    if let Some(dns) = spec.dns.filter(|_| !answers.dns.is_empty()) {
        for (fqdn, value) in &answers.dns {
            wait_until_visible(fqdn, value, &dns.lookup, dns.timeout).await;
        }
        let mut authorizations = order.authorizations();
        while let Some(authorization) = authorizations.next().await {
            let mut authorization = authorization?;
            let name = authorization.identifier().to_string();
            if authorization.status == AuthorizationStatus::Valid
                || !answers.dns_names.contains(&name)
            {
                continue;
            }
            if let Some(mut challenge) = authorization.challenge(ChallengeType::Dns01) {
                challenge.set_ready().await?;
            }
        }
    }
    let status = order
        .poll_ready(&RetryPolicy::new().timeout(VALIDATION_TIMEOUT))
        .await?;
    if status == OrderStatus::Ready {
        Ok(())
    } else {
        Err(IssueError::Invalid(failure_detail(order).await))
    }
}

/// Creates the order. `replaces` (RFC 9773) only earns a renewal its rate-limit exemption, so
/// when the CA refuses an order because of it (`alreadyReplaced`, or a CA that cannot match the
/// replaced certificate), the order is created again without it. Rate limits are not retried.
async fn new_order(account: &Account, spec: OrderSpec<'_>) -> Result<Order, IssueError> {
    let identifiers: Vec<Identifier> = spec.names.iter().map(|n| identifier(n)).collect();
    let plain = || {
        let order = NewOrder::new(&identifiers);
        match spec.profile {
            Some(profile) => order.profile(profile),
            None => order,
        }
    };
    let Some(replaces) = spec.replaces else {
        return Ok(account.new_order(&plain()).await?);
    };
    match account.new_order(&plain().replaces(replaces.clone())).await {
        Err(instant_acme::Error::Api(problem)) if !is_rate_limit(&problem) => {
            warn!(problem = %problem, "the CA refused the renewal order with `replaces`; ordering without it");
            Ok(account.new_order(&plain()).await?)
        }
        other => Ok(other?),
    }
}

fn is_rate_limit(problem: &instant_acme::Problem) -> bool {
    problem
        .r#type
        .as_deref()
        .is_some_and(|t| t.ends_with(":rateLimited"))
}

/// The signing request for `names`. rcgen fills the subject with a placeholder common name,
/// which Let's Encrypt refuses ("rejectedIdentifier"); the subject names the first name
/// instead, or stays empty when that name is longer than a common name may be (64 bytes).
fn csr_params(names: &[String]) -> Result<CertificateParams, IssueError> {
    let mut params = CertificateParams::new(names.to_vec())?;
    params.distinguished_name = DistinguishedName::new();
    if let Some(first) = names.first().filter(|n| n.len() <= 64) {
        params
            .distinguished_name
            .push(DnType::CommonName, first.clone());
    }
    Ok(params)
}

/// The self-signed TLS-ALPN-01 certificate for `name` (RFC 8737): one name and the critical
/// acmeIdentifier extension holding the SHA-256 digest of the key authorization.
fn validation_certificate(name: &str, digest: &[u8]) -> Result<Arc<CertifiedKey>, IssueError> {
    if digest.len() != 32 {
        return Err(IssueError::ValidationCert(format!(
            "the key authorization digest has {} bytes, not 32",
            digest.len()
        )));
    }
    let key = KeyPair::generate()?;
    let mut params = CertificateParams::new(vec![name.to_owned()])?;
    params.custom_extensions = vec![CustomExtension::new_acme_identifier(digest)];
    let cert = params.self_signed(&key)?;
    let der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    let signing = rustls::crypto::ring::sign::any_supported_type(&der)
        .map_err(|e| IssueError::ValidationCert(e.to_string()))?;
    Ok(Arc::new(CertifiedKey::new(
        vec![cert.der().clone()],
        signing,
    )))
}

fn identifier(name: &str) -> Identifier {
    let literal = name
        .strip_prefix('[')
        .and_then(|n| n.strip_suffix(']'))
        .unwrap_or(name);
    match literal.parse::<IpAddr>() {
        Ok(ip) => Identifier::Ip(ip),
        Err(_) => Identifier::Dns(name.to_owned()),
    }
}

/// The CA's explanation of why the order is not ready.
async fn failure_detail(order: &mut instant_acme::Order) -> String {
    let mut details = Vec::new();
    let mut authorizations = order.authorizations();
    while let Some(Ok(authorization)) = authorizations.next().await {
        if authorization.status == AuthorizationStatus::Valid {
            continue;
        }
        let name = authorization.identifier().to_string();
        let problem = authorization
            .challenges
            .iter()
            .find_map(|c| c.error.as_ref())
            .map_or_else(
                || format!("{:?}", authorization.status),
                ToString::to_string,
            );
        details.push(format!("{name}: {problem}"));
    }
    if details.is_empty() {
        "the order did not become ready".to_owned()
    } else {
        details.join("; ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signing_requests_name_the_certificate_not_a_placeholder() {
        let names = vec!["app.example.com".to_owned(), "*.example.com".to_owned()];
        let params = csr_params(&names).unwrap();
        let subject: Vec<_> = params.distinguished_name.iter().collect();
        assert_eq!(subject.len(), 1);
        assert_eq!(
            params.distinguished_name.get(&DnType::CommonName),
            Some(&rcgen::DnValue::Utf8String("app.example.com".to_owned()))
        );
        let long = vec![format!("{}.example.com", "a".repeat(60))];
        assert_eq!(
            csr_params(&long).unwrap().distinguished_name.iter().count(),
            0
        );
    }

    #[test]
    fn identifiers_distinguish_addresses() {
        assert_eq!(
            identifier("203.0.113.7"),
            Identifier::Ip("203.0.113.7".parse().unwrap())
        );
        assert_eq!(
            identifier("[2001:db8::1]"),
            Identifier::Ip("2001:db8::1".parse().unwrap())
        );
        assert_eq!(
            identifier("app.example.com"),
            Identifier::Dns("app.example.com".into())
        );
    }
}
