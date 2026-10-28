//! ACME accounts: one per CA directory, stored next to the certificates.

use std::collections::HashMap;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use instant_acme::{Account, ExternalAccountKey, NewAccount};
use rdock_model::acme::{Acme, AcmeProfile};
use tracing::info;

use crate::directory::directory_url;
use crate::storage::Storage;

/// Accounts in use, by directory URL.
#[derive(Default)]
pub(crate) struct Accounts {
    cache: HashMap<String, Account>,
}

impl Accounts {
    /// The account for `acme`'s CA: cached, loaded from storage, or created.
    pub async fn get(&mut self, acme: &Acme, storage: &Storage) -> Result<Account, AccountError> {
        let directory = directory_url(acme)?;
        if let Some(account) = self.cache.get(&directory) {
            return Ok(account.clone());
        }
        let builder = match &acme.ca_root {
            Some(root) => Account::builder_with_root(root)?,
            None => Account::builder()?,
        };
        let account = if let Some(credentials) = storage.load_account(&directory)? {
            builder.from_credentials(credentials).await?
        } else {
            let contact = acme.email.as_ref().map(|e| format!("mailto:{e}"));
            let contacts: Vec<&str> = contact.iter().map(String::as_str).collect();
            let eab = external_account_key(acme)?;
            let (account, credentials) = builder
                .create(
                    &NewAccount {
                        contact: &contacts,
                        terms_of_service_agreed: true,
                        only_return_existing: false,
                    },
                    directory.clone(),
                    eab.as_ref(),
                )
                .await?;
            storage.save_account(&directory, &credentials)?;
            info!(directory = %directory, "created an ACME account, which accepts the CA's terms of service");
            account
        };
        self.cache.insert(directory, account.clone());
        Ok(account)
    }
}

/// Why the ACME account cannot be used.
#[derive(Debug, thiserror::Error)]
pub(crate) enum AccountError {
    #[error(transparent)]
    Directory(#[from] crate::directory::DirectoryError),
    #[error(transparent)]
    Acme(#[from] instant_acme::Error),
    #[error("account storage: {0}")]
    Storage(#[from] std::io::Error),
    #[error("acme.eab.hmac_key: {0}")]
    Eab(String),
}

fn external_account_key(acme: &Acme) -> Result<Option<ExternalAccountKey>, AccountError> {
    let Some(eab) = &acme.eab else {
        return Ok(None);
    };
    let encoded = rdock_config::interpolate::expand(&eab.hmac_key, &rdock_config::System)
        .map_err(|e| AccountError::Eab(e.to_string()))?;
    let key = URL_SAFE_NO_PAD
        .decode(encoded.trim().trim_end_matches('='))
        .map_err(|e| AccountError::Eab(format!("not base64url: {e}")))?;
    Ok(Some(ExternalAccountKey::new(eab.key_id.clone(), &key)))
}

/// The profile to order: the configured one, else `tlsserver` when the CA offers it (ADR-0020),
/// else none.
pub(crate) fn choose_profile(account: &Account, configured: Option<AcmeProfile>) -> Option<String> {
    let name = |p: AcmeProfile| match p {
        AcmeProfile::Classic => "classic",
        AcmeProfile::Tlsserver => "tlsserver",
        AcmeProfile::Shortlived => "shortlived",
    };
    match configured {
        Some(profile) => Some(name(profile).to_owned()),
        None => account
            .profiles()
            .any(|p| p.name == "tlsserver")
            .then(|| "tlsserver".to_owned()),
    }
}
