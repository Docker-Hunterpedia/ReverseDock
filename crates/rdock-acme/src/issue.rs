//! One certificate order: identifiers, challenges, CSR, download.

use std::net::IpAddr;
use std::time::Duration;

use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, NewOrder, OrderStatus, RetryPolicy,
};
use rcgen::{CertificateParams, KeyPair};
use rdock_tls::Challenges;

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
}

/// Removes HTTP-01 answers when the order ends, whatever the outcome.
struct Answers<'a> {
    challenges: &'a Challenges,
    tokens: Vec<String>,
}

impl Drop for Answers<'_> {
    fn drop(&mut self) {
        for token in &self.tokens {
            self.challenges.remove_http01(token);
        }
    }
}

/// Orders a certificate for `names` from `account`, answering HTTP-01 challenges through
/// `challenges`. Each certificate gets a new private key.
pub async fn issue(
    account: &Account,
    names: &[String],
    profile: Option<&str>,
    challenges: &Challenges,
) -> Result<Issued, IssueError> {
    let identifiers: Vec<Identifier> = names.iter().map(|n| identifier(n)).collect();
    let mut new_order = NewOrder::new(&identifiers);
    if let Some(profile) = profile {
        new_order = new_order.profile(profile);
    }
    let mut order = account.new_order(&new_order).await?;
    let mut answers = Answers {
        challenges,
        tokens: Vec::new(),
    };
    let mut authorizations = order.authorizations();
    while let Some(authorization) = authorizations.next().await {
        let mut authorization = authorization?;
        if authorization.status == AuthorizationStatus::Valid {
            continue;
        }
        let name = authorization.identifier().to_string();
        let mut challenge = authorization
            .challenge(ChallengeType::Http01)
            .ok_or(IssueError::NoChallenge(name))?;
        let token = challenge.token.clone();
        challenges.add_http01(&token, challenge.key_authorization().as_str());
        answers.tokens.push(token);
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
    let csr = CertificateParams::new(names.to_vec())?.serialize_request(&key)?;
    order.finalize_csr(csr.der()).await?;
    let chain_pem = order
        .poll_certificate(&RetryPolicy::new().timeout(SIGNING_TIMEOUT))
        .await?;
    Ok(Issued {
        chain_pem,
        key_pem: key.serialize_pem(),
    })
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
