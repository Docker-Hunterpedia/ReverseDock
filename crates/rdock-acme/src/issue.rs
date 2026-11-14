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
    /// The cluster store could not take a challenge answer.
    #[error("cluster: {0}")]
    Cluster(String),
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

/// Where HTTP-01 and TLS-ALPN-01 answers go: this instance's maps only, or (in a cluster)
/// every member's, with a barrier before the CA is told to validate (ADR-0031).
#[async_trait::async_trait]
pub trait AnswerSink: Send + Sync {
    /// Publishes the answer to an HTTP-01 challenge.
    async fn add_http01(&self, token: &str, key_authorization: &str) -> Result<(), IssueError>;
    /// Publishes the answer to a TLS-ALPN-01 challenge for `name`: the SHA-256 digest of the
    /// key authorization (each instance builds its own validation certificate from it).
    async fn add_tls_alpn01(&self, name: &str, digest: &[u8]) -> Result<(), IssueError>;
    /// Returns once the answers published so far can be served where the CA may ask.
    async fn ready(&self) -> Result<(), IssueError>;
    /// Withdraws every answer this sink published.
    async fn clear(&self);
}

/// This instance's answer maps (the data plane reads them on the request path).
pub struct LocalAnswers {
    challenges: Arc<Challenges>,
    published: std::sync::Mutex<(Vec<String>, Vec<String>)>,
}

impl LocalAnswers {
    /// A sink into `challenges`.
    #[must_use]
    pub fn new(challenges: Arc<Challenges>) -> Self {
        Self {
            challenges,
            published: std::sync::Mutex::new((Vec::new(), Vec::new())),
        }
    }

    fn take(&self) -> (Vec<String>, Vec<String>) {
        std::mem::take(
            &mut *self
                .published
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }
}

impl Drop for LocalAnswers {
    fn drop(&mut self) {
        let (tokens, names) = self.take();
        for token in &tokens {
            self.challenges.remove_http01(token);
        }
        for name in &names {
            self.challenges.remove_tls_alpn01(name);
        }
    }
}

#[async_trait::async_trait]
impl AnswerSink for LocalAnswers {
    async fn add_http01(&self, token: &str, key_authorization: &str) -> Result<(), IssueError> {
        self.challenges.add_http01(token, key_authorization);
        self.published
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .0
            .push(token.to_owned());
        Ok(())
    }

    async fn add_tls_alpn01(&self, name: &str, digest: &[u8]) -> Result<(), IssueError> {
        let certificate = validation_certificate(name, digest)?;
        self.challenges.add_tls_alpn01(name, &certificate);
        self.published
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .1
            .push(name.to_owned());
        Ok(())
    }

    async fn ready(&self) -> Result<(), IssueError> {
        Ok(())
    }

    async fn clear(&self) {
        let (tokens, names) = self.take();
        for token in &tokens {
            self.challenges.remove_http01(token);
        }
        for name in &names {
            self.challenges.remove_tls_alpn01(name);
        }
    }
}

/// Orders a certificate from `account`, answering challenges through `challenges`. Each
/// certificate gets a new private key.
pub async fn issue(
    account: &Account,
    spec: OrderSpec<'_>,
    challenges: &Arc<Challenges>,
) -> Result<Issued, IssueError> {
    let answers = LocalAnswers::new(challenges.clone());
    let key = KeyPair::generate()?;
    let mut order = new_order(account, spec).await?;
    let chain_pem = complete(&mut order, spec, &answers, &key).await?;
    Ok(Issued {
        chain_pem,
        key_pem: key.serialize_pem(),
    })
}

/// Takes `order` from whatever state it is in to a certificate: answers and validates while it
/// is pending, finalizes with `key` when ready, downloads when processing or valid. An order an
/// earlier holder of the lease started is finished the same way (ADR-0031).
pub async fn complete(
    order: &mut Order,
    spec: OrderSpec<'_>,
    answers: &dyn AnswerSink,
    key: &KeyPair,
) -> Result<String, IssueError> {
    for _ in 0..4 {
        let status = order.refresh().await?.status;
        match status {
            OrderStatus::Pending => {
                let validated = validate(order, spec, answers).await;
                answers.clear().await;
                validated?;
            }
            OrderStatus::Ready => {
                let csr = csr_params(spec.names)?.serialize_request(key)?;
                order.finalize_csr(csr.der()).await?;
            }
            OrderStatus::Processing | OrderStatus::Valid => {
                return Ok(order
                    .poll_certificate(&RetryPolicy::new().timeout(SIGNING_TIMEOUT))
                    .await?);
            }
            OrderStatus::Invalid => return Err(IssueError::Invalid(failure_detail(order).await)),
        }
    }
    Err(IssueError::Invalid(
        "the order did not reach a certificate".to_owned(),
    ))
}

/// Publishes an answer for every pending authorization, waits until they can be served (DNS
/// records visible; in a cluster, every member holding the HTTP and TLS answers), tells the CA
/// to validate, and waits for the order to become ready.
async fn validate(
    order: &mut Order,
    spec: OrderSpec<'_>,
    answers: &dyn AnswerSink,
) -> Result<(), IssueError> {
    let mut chosen: Vec<(String, ChallengeType)> = Vec::new();
    let mut dns_records: Vec<(String, String)> = Vec::new();
    let mut authorizations = order.authorizations();
    while let Some(authorization) = authorizations.next().await {
        let mut authorization = authorization?;
        if authorization.status != AuthorizationStatus::Pending {
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
        let challenge = authorization
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
                dns_records.push((fqdn, value));
            }
            ChallengeType::TlsAlpn01 => {
                answers
                    .add_tls_alpn01(&name, key_authorization.digest().as_ref())
                    .await?;
            }
            _ => {
                let token = challenge.token.clone();
                answers
                    .add_http01(&token, key_authorization.as_str())
                    .await?;
            }
        }
        chosen.push((name, offered));
    }
    let result = async {
        if let Some(dns) = spec.dns.filter(|_| !dns_records.is_empty()) {
            for (fqdn, value) in &dns_records {
                wait_until_visible(fqdn, value, &dns.lookup, dns.timeout).await;
            }
        }
        if chosen.iter().any(|(_, t)| *t != ChallengeType::Dns01) {
            answers.ready().await?;
        }
        let mut authorizations = order.authorizations();
        while let Some(authorization) = authorizations.next().await {
            let mut authorization = authorization?;
            let name = authorization.identifier().to_string();
            let Some((_, kind)) = chosen.iter().find(|(n, _)| *n == name) else {
                continue;
            };
            if authorization.status != AuthorizationStatus::Pending {
                continue;
            }
            if let Some(mut challenge) = authorization.challenge(kind.clone()) {
                challenge.set_ready().await?;
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
    .await;
    if let Some(dns) = spec.dns {
        for (fqdn, value) in &dns_records {
            if let Err(e) = dns.solver.cleanup(fqdn, value).await {
                warn!(fqdn = %fqdn, error = %e, "cannot remove the DNS-01 record");
            }
        }
    }
    result
}

/// Creates the order. `replaces` (RFC 9773) only earns a renewal its rate-limit exemption, so
/// when the CA refuses an order because of it (`alreadyReplaced`, or a CA that cannot match the
/// replaced certificate), the order is created again without it. Rate limits are not retried.
pub async fn new_order(account: &Account, spec: OrderSpec<'_>) -> Result<Order, IssueError> {
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
pub(crate) fn csr_params(names: &[String]) -> Result<CertificateParams, IssueError> {
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
pub(crate) fn validation_certificate(
    name: &str,
    digest: &[u8],
) -> Result<Arc<CertifiedKey>, IssueError> {
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
