//! TSIG (RFC 8945): requests are signed and the server's answers verified with HMAC from ring.
//! hickory-proto lays out the bytes that are signed; its signer is not used because it has no
//! HMAC-SHA1, which RFC 8945 still allows.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::Name;
use hickory_proto::rr::rdata::tsig::{
    TSIG, TsigAlgorithm as WireAlgorithm, TsigError, make_tsig_record, message_tbs,
    signed_bitmessage_to_buf,
};
use rdock_acme::dns::DnsError;
use rdock_model::acme::TsigAlgorithm;
use ring::hmac;

use crate::secret;

/// The clock difference a signature tolerates, as RFC 8945 recommends.
pub(super) const FUDGE: u16 = 300;

/// A TSIG key: its name, algorithm, and secret reference (resolved for each exchange).
#[derive(Debug)]
pub(super) struct TsigKey {
    name: Name,
    algorithm: Mac,
    secret: String,
}

/// The HMAC algorithms TSIG may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mac {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl Mac {
    fn hmac(self) -> hmac::Algorithm {
        match self {
            Self::Sha1 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            Self::Sha256 => hmac::HMAC_SHA256,
            Self::Sha384 => hmac::HMAC_SHA384,
            Self::Sha512 => hmac::HMAC_SHA512,
        }
    }

    fn wire(self) -> WireAlgorithm {
        match self {
            Self::Sha1 => WireAlgorithm::HmacSha1,
            Self::Sha256 => WireAlgorithm::HmacSha256,
            Self::Sha384 => WireAlgorithm::HmacSha384,
            Self::Sha512 => WireAlgorithm::HmacSha512,
        }
    }
}

impl TsigKey {
    /// The key `name` with the secret reference `secret`. Refuses `hmac-md5` (RFC 8945: "MUST
    /// NOT be used").
    pub(super) fn new(
        name: &str,
        secret: &str,
        algorithm: TsigAlgorithm,
    ) -> Result<Self, DnsError> {
        let algorithm = match algorithm {
            TsigAlgorithm::HmacSha256 => Mac::Sha256,
            TsigAlgorithm::HmacSha384 => Mac::Sha384,
            TsigAlgorithm::HmacSha512 => Mac::Sha512,
            TsigAlgorithm::HmacSha1 => Mac::Sha1,
            TsigAlgorithm::HmacMd5 => {
                return Err(DnsError(
                    "tsig_algorithm hmac-md5 must not be used (RFC 8945); use hmac-sha256".into(),
                ));
            }
        };
        let mut name = Name::from_ascii(name)
            .map_err(|e| DnsError(format!("tsig_key_name `{name}` is not a DNS name: {e}")))?;
        name.set_fqdn(true);
        Ok(Self {
            name,
            algorithm,
            secret: secret.to_owned(),
        })
    }

    /// The key with its secret read now, so a rotated secret file is used from the next update.
    pub(super) fn resolve(&self) -> Result<SigningKey<'_>, DnsError> {
        let secret = secret::resolve(&self.secret, "tsig_secret")?;
        let bytes = STANDARD
            .decode(secret.as_bytes())
            .map_err(|_| DnsError("tsig_secret is not base64".into()))?;
        Ok(SigningKey {
            key: self,
            hmac: hmac::Key::new(self.algorithm.hmac(), &bytes),
        })
    }
}

/// A key ready to sign one exchange.
pub(super) struct SigningKey<'a> {
    key: &'a TsigKey,
    hmac: hmac::Key,
}

impl SigningKey<'_> {
    /// Adds the TSIG record to `message`, signed at `now` (Unix seconds); returns its MAC, which
    /// the answer's signature covers.
    pub(super) fn sign(&self, message: &mut Message, now: u64) -> Result<Vec<u8>, DnsError> {
        let stub = TSIG::new(
            self.key.algorithm.wire(),
            now,
            FUDGE,
            Vec::new(),
            message.metadata.id,
            None,
            Vec::new(),
        );
        let signed = message_tbs(message, &stub, &self.key.name)
            .map_err(|e| DnsError(format!("cannot sign the DNS message: {e}")))?;
        let mac = hmac::sign(&self.hmac, &signed).as_ref().to_vec();
        message.signature = Some(Box::new(make_tsig_record(
            self.key.name.clone(),
            stub.set_mac(mac.clone()),
        )));
        Ok(mac)
    }

    /// Checks the signature of `answer` (decoded from `bytes`) to the request signed with
    /// `request_mac`. An unsigned error answer passes, so its response code can be reported;
    /// an unsigned success does not.
    pub(super) fn verify(
        &self,
        answer: &Message,
        bytes: &[u8],
        request_mac: &[u8],
        now: u64,
    ) -> Result<(), String> {
        let Some(signature) = &answer.signature else {
            return if answer.metadata.response_code == ResponseCode::NoError {
                Err("the answer is not signed with the TSIG key".into())
            } else {
                Ok(())
            };
        };
        if let Some(error) = signature.data.error {
            return Err(format!(
                "the server rejected the TSIG signature: {}",
                describe(error)
            ));
        }
        let (covered, record) = signed_bitmessage_to_buf(bytes, Some(request_mac), true)
            .map_err(|e| format!("cannot read the answer's TSIG record: {e}"))?;
        if record.name != self.key.name || record.data.algorithm != self.key.algorithm.wire() {
            return Err("the answer is signed with another TSIG key".into());
        }
        hmac::verify(&self.hmac, &covered, &record.data.mac)
            .map_err(|_| "the answer's TSIG signature does not match the key".to_owned())?;
        if now.abs_diff(record.data.time) > u64::from(record.data.fudge) {
            return Err(format!(
                "the answer was signed more than {} s away from this clock; check the clocks",
                record.data.fudge
            ));
        }
        Ok(())
    }
}

fn describe(error: TsigError) -> String {
    match error {
        TsigError::BadSig => "BADSIG (the secret does not match the server's)".into(),
        TsigError::BadKey => "BADKEY (the server knows no key of this name and algorithm)".into(),
        TsigError::BadTime => "BADTIME (the clocks differ by more than 5 minutes)".into(),
        TsigError::BadTrunc => "BADTRUNC".into(),
        TsigError::Unknown(code) => format!("TSIG error {code}"),
    }
}

#[cfg(test)]
mod tests;
