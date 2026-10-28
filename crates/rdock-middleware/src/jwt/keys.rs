//! JSON Web Keys (RFC 7517, RFC 7518 §6, RFC 8037) for signature verification. Each key is
//! pinned to exactly one algorithm, so a token can never pick how its signature is checked
//! (no algorithm confusion, RFC 8725 §2.1).

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rdock_model::middleware::JwtAlgorithm;
use ring::{hmac, signature};
use serde::Deserialize;

/// A verification key.
pub(crate) struct Key {
    /// `kid`, when the set names its keys.
    pub(crate) kid: Option<String>,
    /// The only algorithm this key verifies.
    pub(crate) alg: JwtAlgorithm,
    material: Material,
}

enum Material {
    Rsa {
        n: Vec<u8>,
        e: Vec<u8>,
    },
    /// Uncompressed EC point (`0x04 || x || y`) or an Ed25519 public key.
    Public(Vec<u8>),
    Hmac(hmac::Key),
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Key")
            .field("kid", &self.kid)
            .field("alg", &self.alg)
            .finish_non_exhaustive()
    }
}

impl Key {
    /// An HMAC key for `alg` (an HS algorithm).
    pub(crate) fn hmac(alg: JwtAlgorithm, secret: &[u8]) -> Self {
        let algorithm = match alg {
            JwtAlgorithm::Hs384 => hmac::HMAC_SHA384,
            JwtAlgorithm::Hs512 => hmac::HMAC_SHA512,
            _ => hmac::HMAC_SHA256,
        };
        Self {
            kid: None,
            alg,
            material: Material::Hmac(hmac::Key::new(algorithm, secret)),
        }
    }

    /// Whether `signature` is valid for `message`.
    pub(crate) fn verify(&self, message: &[u8], sig: &[u8]) -> bool {
        use JwtAlgorithm as A;
        match &self.material {
            Material::Hmac(key) => hmac::verify(key, message, sig).is_ok(),
            Material::Rsa { n, e } => {
                let params: &signature::RsaParameters = match self.alg {
                    A::Rs256 => &signature::RSA_PKCS1_2048_8192_SHA256,
                    A::Rs384 => &signature::RSA_PKCS1_2048_8192_SHA384,
                    A::Rs512 => &signature::RSA_PKCS1_2048_8192_SHA512,
                    A::Ps256 => &signature::RSA_PSS_2048_8192_SHA256,
                    A::Ps384 => &signature::RSA_PSS_2048_8192_SHA384,
                    A::Ps512 => &signature::RSA_PSS_2048_8192_SHA512,
                    _ => return false,
                };
                signature::RsaPublicKeyComponents { n, e }
                    .verify(params, message, sig)
                    .is_ok()
            }
            Material::Public(bytes) => {
                let algorithm: &dyn signature::VerificationAlgorithm = match self.alg {
                    A::Es256 => &signature::ECDSA_P256_SHA256_FIXED,
                    A::Es384 => &signature::ECDSA_P384_SHA384_FIXED,
                    A::EdDsa => &signature::ED25519,
                    _ => return false,
                };
                signature::UnparsedPublicKey::new(algorithm, bytes)
                    .verify(message, sig)
                    .is_ok()
            }
        }
    }
}

#[derive(Deserialize)]
struct Set {
    keys: Vec<Jwk>,
}

#[derive(Deserialize)]
struct Jwk {
    kty: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    alg: Option<String>,
    #[serde(rename = "use", default)]
    usage: Option<String>,
    #[serde(default)]
    crv: Option<String>,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
    #[serde(default)]
    x: Option<String>,
    #[serde(default)]
    y: Option<String>,
}

fn b64(value: Option<&String>) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(value?.trim_end_matches('=')).ok()
}

/// The verification keys of a JWKS document, restricted to `allowed` algorithms. Keys for
/// encryption, symmetric keys and keys that cannot be read are skipped; it is an error only when
/// the document is not a key set at all.
pub(crate) fn parse_set(text: &str, allowed: &[JwtAlgorithm]) -> Result<Vec<Key>, String> {
    let set: Set =
        serde_json::from_str(text).map_err(|e| format!("not a JSON Web Key Set: {e}"))?;
    Ok(set
        .keys
        .into_iter()
        .filter(|jwk| jwk.usage.as_deref().is_none_or(|u| u == "sig"))
        .filter_map(key_of)
        .filter(|key| allowed.contains(&key.alg))
        .collect())
}

fn key_of(jwk: Jwk) -> Option<Key> {
    use JwtAlgorithm as A;
    let named = |name: &str| {
        [
            A::Rs256,
            A::Rs384,
            A::Rs512,
            A::Ps256,
            A::Ps384,
            A::Ps512,
            A::Es256,
            A::Es384,
            A::EdDsa,
        ]
        .into_iter()
        .find(|a| a.name() == name)
    };
    let (alg, material) = match (jwk.kty.as_str(), jwk.crv.as_deref()) {
        ("RSA", _) => {
            let alg = match jwk.alg.as_deref() {
                None => A::Rs256,
                Some(name) => named(name).filter(|a| a.name().starts_with(['R', 'P']))?,
            };
            let (n, e) = (b64(jwk.n.as_ref())?, b64(jwk.e.as_ref())?);
            (alg, Material::Rsa { n, e })
        }
        ("EC", Some(curve @ ("P-256" | "P-384"))) => {
            let alg = if curve == "P-256" { A::Es256 } else { A::Es384 };
            if jwk.alg.as_deref().is_some_and(|a| a != alg.name()) {
                return None;
            }
            let (x, y) = (b64(jwk.x.as_ref())?, b64(jwk.y.as_ref())?);
            let size = if alg == A::Es256 { 32 } else { 48 };
            if x.len() != size || y.len() != size {
                return None;
            }
            let mut point = vec![0x04];
            point.extend_from_slice(&x);
            point.extend_from_slice(&y);
            (alg, Material::Public(point))
        }
        ("OKP", Some("Ed25519")) => {
            if jwk.alg.as_deref().is_some_and(|a| a != "EdDSA") {
                return None;
            }
            let x = b64(jwk.x.as_ref()).filter(|x| x.len() == 32)?;
            (A::EdDsa, Material::Public(x))
        }
        _ => return None,
    };
    Some(Key {
        kid: jwk.kid,
        alg,
        material,
    })
}
