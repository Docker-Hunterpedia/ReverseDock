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
    /// The `Retry-After` each CA last asked for, by directory URL.
    hints: HashMap<String, crate::client::RetryHint>,
}

impl Accounts {
    /// The account for `acme`'s CA: cached, loaded from storage, or created. In a cluster one
    /// instance creates it under a lease and the others load it (ADR-0031).
    pub async fn get(
        &mut self,
        acme: &Acme,
        storage: &Storage,
        holder: &str,
    ) -> Result<Account, AccountError> {
        let directory = directory_url(acme)?;
        if let Some(account) = self.cache.get(&directory) {
            return Ok(account.clone());
        }
        let hint = self.hints.entry(directory.clone()).or_default().clone();
        let builder = || -> Result<instant_acme::AccountBuilder, instant_acme::Error> {
            let client = crate::client::TimedClient::new(acme.ca_root.as_deref(), hint.clone())?;
            Ok(Account::builder_with_http(Box::new(client)))
        };
        if let Some(credentials) = storage.load_account(&directory).await? {
            let account = builder()?.from_credentials(credentials).await?;
            self.cache.insert(directory, account.clone());
            return Ok(account);
        }
        let name = crate::storage::account_lease(&directory);
        let ttl = std::time::Duration::from_secs(60);
        let mut lease = None;
        for _ in 0..60 {
            if let Some(held) = storage
                .store()
                .acquire(&name, holder, ttl)
                .await
                .map_err(crate::storage::StorageError::from)?
            {
                lease = Some(held);
                break;
            }
            // Another instance is creating it.
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            if let Some(credentials) = storage.load_account(&directory).await? {
                let account = builder()?.from_credentials(credentials).await?;
                self.cache.insert(directory, account.clone());
                return Ok(account);
            }
        }
        let Some(lease) = lease else {
            return Err(AccountError::Busy);
        };
        let builder = builder()?;
        let account = if let Some(credentials) = storage.load_account(&directory).await? {
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
            let saved = storage
                .save_account(&directory, &credentials, Some(&lease))
                .await;
            if let Err(e) = saved {
                let _ = storage.store().release(&lease).await;
                return Err(e.into());
            }
            info!(directory = %directory, "created an ACME account, which accepts the CA's terms of service");
            account
        };
        let _ = storage.store().release(&lease).await;
        self.cache.insert(directory, account.clone());
        Ok(account)
    }
}

impl Accounts {
    /// When the CA of `directory` asked to be contacted again (`Retry-After` on a `429` or
    /// `503`), if that is still ahead; asking clears it.
    pub fn retry_after(&self, directory: &str) -> Option<std::time::SystemTime> {
        self.hints
            .get(directory)
            .and_then(crate::client::RetryHint::take)
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
    Storage(#[from] crate::storage::StorageError),
    #[error("another instance keeps creating the ACME account; trying again later")]
    Busy,
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
