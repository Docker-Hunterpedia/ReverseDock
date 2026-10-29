//! Tokens are signed here with ring (RSA from a throw-away test key in `testdata`, EC and
//! Ed25519 generated per test) and verified through JWKS documents, as in production.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rdock_model::middleware::JwtAlgorithm;
use ring::rand::SystemRandom;
use ring::signature::{self, KeyPair};
use serde_json::{Value, json};

use super::keys::{Key, parse_set};
use super::token::{Invalid, Rules, verify};

const RSA_PKCS8: &[u8] = include_bytes!("../../testdata/jwt-test-rsa.pk8");

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn claims() -> Value {
    json!({ "iss": "https://idp.test", "aud": ["api", "other"], "sub": "user-1", "exp": now() + 300 })
}

fn rules(audiences: &[String]) -> Rules<'_> {
    Rules {
        issuer: Some("https://idp.test"),
        audiences: Some(audiences),
        leeway: Duration::from_secs(60),
        now: SystemTime::now(),
    }
}

/// `header.payload` for `header` and `claims`.
fn signing_input(header: &Value, claims: &Value) -> String {
    format!(
        "{}.{}",
        b64(header.to_string().as_bytes()),
        b64(claims.to_string().as_bytes())
    )
}

/// Signs a message with a test key.
type SignFn = Box<dyn Fn(&[u8]) -> Vec<u8>>;

struct Signer {
    jwk: Value,
    sign: SignFn,
    alg: &'static str,
}

impl Signer {
    fn token(&self, kid: Option<&str>, claims: &Value) -> String {
        let mut header = json!({ "alg": self.alg, "typ": "JWT" });
        if let Some(kid) = kid {
            header["kid"] = json!(kid);
        }
        let input = signing_input(&header, claims);
        format!("{input}.{}", b64(&(self.sign)(input.as_bytes())))
    }

    fn keys(&self, allowed: &[JwtAlgorithm]) -> Vec<Key> {
        parse_set(&json!({ "keys": [self.jwk] }).to_string(), allowed).unwrap()
    }
}

fn rsa(alg: &'static str) -> Signer {
    let pair = signature::RsaKeyPair::from_pkcs8(RSA_PKCS8).unwrap();
    let public: signature::RsaPublicKeyComponents<Vec<u8>> = pair.public().into();
    let padding: &'static dyn signature::RsaEncoding = match alg {
        "PS256" => &signature::RSA_PSS_SHA256,
        _ => &signature::RSA_PKCS1_SHA256,
    };
    Signer {
        jwk: json!({ "kty": "RSA", "kid": "rsa-1", "alg": alg, "n": b64(&public.n), "e": b64(&public.e) }),
        sign: Box::new(move |msg| {
            let mut sig = vec![0; pair.public().modulus_len()];
            pair.sign(padding, &SystemRandom::new(), msg, &mut sig)
                .unwrap();
            sig
        }),
        alg,
    }
}

fn es256() -> Signer {
    let rng = SystemRandom::new();
    let alg = &signature::ECDSA_P256_SHA256_FIXED_SIGNING;
    let pkcs8 = signature::EcdsaKeyPair::generate_pkcs8(alg, &rng).unwrap();
    let pair = signature::EcdsaKeyPair::from_pkcs8(alg, pkcs8.as_ref(), &rng).unwrap();
    let point = pair.public_key().as_ref().to_vec();
    Signer {
        jwk: json!({ "kty": "EC", "crv": "P-256", "kid": "ec-1", "x": b64(&point[1..33]), "y": b64(&point[33..]) }),
        sign: Box::new(move |msg| {
            pair.sign(&SystemRandom::new(), msg)
                .unwrap()
                .as_ref()
                .to_vec()
        }),
        alg: "ES256",
    }
}

fn ed25519() -> Signer {
    let pkcs8 = signature::Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    Signer {
        jwk: json!({ "kty": "OKP", "crv": "Ed25519", "x": b64(pair.public_key().as_ref()) }),
        sign: Box::new(move |msg| pair.sign(msg).as_ref().to_vec()),
        alg: "EdDSA",
    }
}

#[test]
fn every_algorithm_family_verifies() {
    let aud = vec!["api".to_owned()];
    for (signer, alg) in [
        (rsa("RS256"), JwtAlgorithm::Rs256),
        (rsa("PS256"), JwtAlgorithm::Ps256),
        (es256(), JwtAlgorithm::Es256),
        (ed25519(), JwtAlgorithm::EdDsa),
    ] {
        let keys = signer.keys(&[alg]);
        assert_eq!(keys.len(), 1, "{alg:?}");
        let refs: Vec<&Key> = keys.iter().collect();
        let token = signer.token(signer.jwk.get("kid").and_then(Value::as_str), &claims());
        let verified = verify(&token, &refs, &rules(&aud)).unwrap();
        assert_eq!(verified["sub"], "user-1", "{alg:?}");
        // One flipped byte of the payload breaks the signature.
        let mut parts: Vec<String> = token.split('.').map(str::to_owned).collect();
        parts[1] = b64(
            json!({ "iss": "https://idp.test", "aud": "api", "sub": "admin", "exp": now() + 300 })
                .to_string()
                .as_bytes(),
        );
        assert_eq!(
            verify(&parts.join("."), &refs, &rules(&aud)),
            Err(Invalid::Signature),
            "{alg:?}"
        );
    }
}

#[test]
fn hmac_needs_the_secret() {
    let key = Key::hmac(JwtAlgorithm::Hs256, b"0123456789abcdef0123456789abcdef");
    let header = json!({ "alg": "HS256" });
    let input = signing_input(&header, &claims());
    let tag = ring::hmac::sign(
        &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"0123456789abcdef0123456789abcdef"),
        input.as_bytes(),
    );
    let token = format!("{input}.{}", b64(tag.as_ref()));
    let aud = vec!["api".to_owned()];
    assert!(verify(&token, &[&key], &rules(&aud)).is_ok());
    let wrong = Key::hmac(JwtAlgorithm::Hs256, b"another-secret-another-secret-xx");
    assert_eq!(
        verify(&token, &[&wrong], &rules(&aud)),
        Err(Invalid::Signature)
    );
}

#[test]
fn rfc8725_attacks_are_refused() {
    let signer = rsa("RS256");
    let keys = signer.keys(&[JwtAlgorithm::Rs256]);
    let refs: Vec<&Key> = keys.iter().collect();
    let aud = vec!["api".to_owned()];
    // `alg: none` with an empty signature.
    let none = format!("{}.", signing_input(&json!({ "alg": "none" }), &claims()));
    assert_eq!(
        verify(&none, &refs, &rules(&aud)),
        Err(Invalid::Algorithm("none".into()))
    );
    // HS256 "signed" with the RSA public key as the secret (algorithm confusion).
    let input = signing_input(&json!({ "alg": "HS256" }), &claims());
    let n = signer.jwk["n"].as_str().unwrap();
    let tag = ring::hmac::sign(
        &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, n.as_bytes()),
        input.as_bytes(),
    );
    let confused = format!("{input}.{}", b64(tag.as_ref()));
    assert_eq!(
        verify(&confused, &refs, &rules(&aud)),
        Err(Invalid::Algorithm("HS256".into()))
    );
    // `crit` extensions are not understood, so they are refused.
    let input = signing_input(&json!({ "alg": "RS256", "crit": ["exp"] }), &claims());
    let crit = format!("{input}.{}", b64(&(signer.sign)(input.as_bytes())));
    assert_eq!(verify(&crit, &refs, &rules(&aud)), Err(Invalid::Critical));
    // A `kid` the set does not have.
    let unknown = signer.token(Some("rotated-away"), &claims());
    assert_eq!(
        verify(&unknown, &refs, &rules(&aud)),
        Err(Invalid::UnknownKey)
    );
    for garbage in ["", "a.b", "a.b.c.d", "!!.!!.!!"] {
        assert_eq!(
            verify(garbage, &refs, &rules(&aud)),
            Err(Invalid::Malformed),
            "{garbage:?}"
        );
    }
}

#[test]
fn claims_are_checked() {
    let signer = es256();
    let keys = signer.keys(&[JwtAlgorithm::Es256]);
    let refs: Vec<&Key> = keys.iter().collect();
    let aud = vec!["api".to_owned()];
    let with = |patch: Value| {
        let mut c = claims();
        for (k, v) in patch.as_object().unwrap() {
            if v.is_null() {
                c.as_object_mut().unwrap().remove(k);
            } else {
                c[k] = v.clone();
            }
        }
        verify(&signer.token(Some("ec-1"), &c), &refs, &rules(&aud))
    };
    assert!(with(json!({})).is_ok());
    assert!(
        with(json!({ "exp": now() - 30 })).is_ok(),
        "within the leeway"
    );
    assert_eq!(
        with(json!({ "exp": now() - 120 })).map(drop),
        Err(Invalid::Expired)
    );
    assert_eq!(
        with(json!({ "exp": null })).map(drop),
        Err(Invalid::NoExpiry)
    );
    assert_eq!(
        with(json!({ "nbf": now() + 600 })).map(drop),
        Err(Invalid::NotYetValid)
    );
    assert_eq!(
        with(json!({ "iss": "https://evil.test" })).map(drop),
        Err(Invalid::Issuer)
    );
    assert_eq!(with(json!({ "iss": null })).map(drop), Err(Invalid::Issuer));
    assert_eq!(
        with(json!({ "aud": "other" })).map(drop),
        Err(Invalid::Audience)
    );
    assert_eq!(
        with(json!({ "aud": null })).map(drop),
        Err(Invalid::Audience)
    );
    assert!(
        with(json!({ "aud": "api" })).is_ok(),
        "a single string audience"
    );
    assert_eq!(
        with(json!({ "exp": "soon" })).map(drop),
        Err(Invalid::Malformed)
    );
}

#[test]
fn key_sets_skip_what_they_cannot_use() {
    let set = json!({ "keys": [
        { "kty": "RSA", "use": "enc", "n": "AQAB", "e": "AQAB" },
        { "kty": "oct", "k": "c2VjcmV0" },
        { "kty": "EC", "crv": "P-521", "x": "AA", "y": "AA" },
        { "kty": "EC", "crv": "P-256", "x": "AA", "y": "AA" },
        { "kty": "RSA", "alg": "ES256", "n": "AQAB", "e": "AQAB" },
        { "kty": "RSA", "kid": "ok", "n": "AQAB", "e": "AQAB" }
    ]});
    let keys = parse_set(
        &set.to_string(),
        &[JwtAlgorithm::Rs256, JwtAlgorithm::Es256],
    )
    .unwrap();
    assert_eq!(keys.len(), 1, "{keys:?}");
    assert_eq!(keys[0].kid.as_deref(), Some("ok"));
    assert_eq!(
        keys[0].alg,
        JwtAlgorithm::Rs256,
        "an RSA key without `alg` is pinned to RS256"
    );
    assert!(parse_set("{}", &[JwtAlgorithm::Rs256]).is_err());
    assert!(parse_set("[1,2]", &[JwtAlgorithm::Rs256]).is_err());
}
