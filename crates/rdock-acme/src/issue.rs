//! One certificate order: identifiers, challenges, CSR, download.

use std::net::IpAddr;
use std::time::Duration;

use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, NewOrder, OrderStatus, RetryPolicy,
};
use std::sync::Arc;

use rcgen::{CertificateParams, CustomExtension, KeyPair};
use rdock_tls::Challenges;
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
}

/// Removes the challenge answers when the order ends, whatever the outcome.
struct Answers<'a> {
    challenges: &'a Challenges,
    tokens: Vec<String>,
    names: Vec<String>,
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
    let identifiers: Vec<Identifier> = spec.names.iter().map(|n| identifier(n)).collect();
    let mut new_order = NewOrder::new(&identifiers);
    if let Some(profile) = spec.profile {
        new_order = new_order.profile(profile);
    }
    let mut order = account.new_order(&new_order).await?;
    let mut answers = Answers {
        challenges,
        tokens: Vec::new(),
        names: Vec::new(),
    };
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
            .filter(|t| !(is_ip && **t == ChallengeType::TlsAlpn01))
            .find(|t| authorization.challenges.iter().any(|c| c.r#type == **t))
            .cloned()
            .ok_or_else(|| IssueError::NoChallenge(name.clone()))?;
        let mut challenge = authorization
            .challenge(offered.clone())
            .ok_or_else(|| IssueError::NoChallenge(name.clone()))?;
        let key_authorization = challenge.key_authorization();
        if offered == ChallengeType::TlsAlpn01 {
            let certificate = validation_certificate(&name, key_authorization.digest().as_ref())?;
            challenges.add_tls_alpn01(&name, &certificate);
            answers.names.push(name);
        } else {
            let token = challenge.token.clone();
            challenges.add_http01(&token, key_authorization.as_str());
            answers.tokens.push(token);
        }
        challenge.set_ready().await?;
    }
    let status = order
        .poll_ready(&RetryPolicy::new().timeout(VALIDATION_TIMEOUT))
        .await?;
    drop(answers);
    if status != OrderStatus::Ready {
        return Err(IssueError::Invalid(failure_detail(&mut order).await));
    }
    let key = KeyPair::generate()?;
    let csr = CertificateParams::new(spec.names.to_vec())?.serialize_request(&key)?;
    order.finalize_csr(csr.der()).await?;
    let chain_pem = order
        .poll_certificate(&RetryPolicy::new().timeout(SIGNING_TIMEOUT))
        .await?;
    Ok(Issued {
        chain_pem,
        key_pem: key.serialize_pem(),
    })
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
