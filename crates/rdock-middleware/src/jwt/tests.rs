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

#[test]
fn a_claim_names_the_consumer_and_another_its_groups() {
    let claims = json!({ "sub": "user-1", "email": "a@example.com", "email_verified": true,
        "roles": ["admin", "staff"], "n": 7 });
    let claims = claims.as_object().unwrap();
    let consumer = super::claim_consumer(claims, "email", Some("roles"), false).unwrap();
    assert_eq!(&*consumer.name, "a@example.com");
    assert_eq!(consumer.groups.len(), 2);
    let numeric = super::claim_consumer(claims, "n", None, false).unwrap();
    assert_eq!(&*numeric.name, "7");
    assert!(numeric.groups.is_empty());
    assert!(super::claim_consumer(claims, "missing", None, false).is_none());
}

/// H1 of the v0.8 review: an address the issuer has not verified does not name the consumer.
#[test]
fn an_unverified_email_never_names_the_consumer() {
    for verified in [json!(false), json!("false"), Value::Null] {
        let mut claims = json!({ "sub": "user-1", "email": "victim@corp.example" });
        if !verified.is_null() {
            claims["email_verified"] = verified.clone();
        }
        let claims = claims.as_object().unwrap();
        let consumer = super::claim_consumer(claims, "email", None, false).unwrap();
        assert_eq!(&*consumer.name, "user-1", "email_verified = {verified}");
    }
    // `unverified_emails` trusts an address without `email_verified`, never one marked false.
    let absent = json!({ "sub": "user-1", "email": "a@example.com" });
    let absent = absent.as_object().unwrap();
    assert_eq!(
        &*super::claim_consumer(absent, "email", None, true)
            .unwrap()
            .name,
        "a@example.com"
    );
    let refused = json!({ "sub": "user-1", "email": "a@example.com", "email_verified": false });
    let refused = refused.as_object().unwrap();
    assert_eq!(
        &*super::claim_consumer(refused, "email", None, true)
            .unwrap()
            .name,
        "user-1"
    );
    // Without `sub` to fall back on there is no consumer.
    let bare = json!({ "email": "a@example.com" });
    assert!(super::claim_consumer(bare.as_object().unwrap(), "email", None, false).is_none());
}

/// H1 of the v0.8 review: a service token never shares a user's identity, and neither shares
/// one with a consumer of `consumers`.
#[test]
fn access_identities_are_keyed_on_the_team() {
    let issuer = "https://acme.cloudflareaccess.com";
    let user = json!({ "sub": "u1", "email": "x@acme.example" });
    let user = super::access_consumer(user.as_object().unwrap(), issuer).unwrap();
    let service = json!({ "sub": "", "common_name": "x@acme.example" });
    let service = super::access_consumer(service.as_object().unwrap(), issuer).unwrap();
    assert_eq!(user.name, service.name);
    assert_ne!(user.key(), service.key());
    assert_ne!(user.key(), crate::Consumer::named("x@acme.example").key());
    assert_eq!(&*service.groups[0], super::SERVICE_TOKEN_GROUP);
    assert!(user.groups.is_empty());
}

/// A `jwt` middleware with `consumer_claim: sub` and an HS256 key, built from `extra` settings,
/// with the consumers `user-7` (group `vip`).
fn mapping_jwt(extra: &Value) -> super::Jwt {
    const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";
    let mut config = json!({
        "issuer": "https://idp.test", "audiences": ["api"], "algorithms": ["HS256"],
        "consumer_claim": "sub", "groups_claim": "roles",
    });
    for (k, v) in extra.as_object().unwrap() {
        config[k] = v.clone();
    }
    let config: rdock_model::middleware::JwtConfig = serde_json::from_value(config).unwrap();
    let consumers: std::collections::BTreeMap<String, rdock_model::gateway::Consumer> =
        serde_json::from_value(json!({ "user-7": { "groups": ["vip"] } })).unwrap();
    let index = crate::ConsumerIndex::build(&consumers).unwrap();
    let mut jwt = super::Jwt::new(
        "auth",
        &config,
        std::sync::Arc::new(crate::HttpClient::default()),
        std::sync::Arc::new(index),
    )
    .unwrap();
    jwt.local.push(Key::hmac(JwtAlgorithm::Hs256, SECRET));
    jwt
}

fn hs256(claims: &Value) -> String {
    let input = signing_input(&json!({ "alg": "HS256" }), claims);
    let tag = ring::hmac::sign(
        &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"0123456789abcdef0123456789abcdef"),
        input.as_bytes(),
    );
    format!("{input}.{}", b64(tag.as_ref()))
}

/// H1 of the v0.8 review: a token's consumer is keyed on its issuer and gets nothing from a
/// consumer of `consumers` with the same name, unless `map_to_consumers` is set.
#[tokio::test]
async fn token_consumers_map_to_configured_ones_only_when_asked() {
    use crate::Middleware as _;
    let token = hs256(&json!({
        "iss": "https://idp.test", "aud": "api", "sub": "user-7", "exp": now() + 300,
        "roles": ["staff"],
    }));
    let run = |jwt: super::Jwt| {
        let token = token.clone();
        async move {
            let mut req = crate::test_support::request(
                "GET",
                "/",
                &[("authorization", &format!("Bearer {token}"))],
            );
            let mut cx = crate::test_support::cx();
            assert!(matches!(
                jwt.request(&mut req, &mut cx).await,
                crate::Flow::Next
            ));
            cx.consumer.unwrap()
        }
    };
    let plain = mapping_jwt(&json!({}));
    let consumer = run(plain).await;
    assert_eq!(&*consumer.name, "user-7");
    let groups: Vec<&str> = consumer.groups.iter().map(|g| &**g).collect();
    assert_eq!(groups, ["staff"], "no `vip` from `consumers.user-7`");
    assert_ne!(consumer.key(), crate::Consumer::named("user-7").key());
    assert_eq!(consumer.issuer.as_deref(), Some("https://idp.test"));

    let mapped = mapping_jwt(&json!({ "map_to_consumers": true }));
    let consumer = run(mapped).await;
    let groups: Vec<&str> = consumer.groups.iter().map(|g| &**g).collect();
    assert_eq!(groups, ["staff", "vip"]);
    assert_eq!(consumer.key(), crate::Consumer::named("user-7").key());

    // A name `consumers` does not define stays keyed on the issuer, mapping or not.
    let other = hs256(&json!({
        "iss": "https://idp.test", "aud": "api", "sub": "ip:192.0.2.1", "exp": now() + 300,
    }));
    let mapped = mapping_jwt(&json!({ "map_to_consumers": true }));
    let mut req =
        crate::test_support::request("GET", "/", &[("authorization", &format!("Bearer {other}"))]);
    let mut cx = crate::test_support::cx();
    assert!(matches!(
        mapped.request(&mut req, &mut cx).await,
        crate::Flow::Next
    ));
    let consumer = cx.consumer.unwrap();
    assert_eq!(consumer.issuer.as_deref(), Some("https://idp.test"));
    assert!(consumer.key().starts_with('~'));
}
