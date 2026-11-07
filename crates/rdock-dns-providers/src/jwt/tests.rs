//! JWT construction with the test-only keys. The fixed RS256 signature was made with
//! `openssl dgst -sha256 -sign tests/fixtures/test-only-rsa-2048-a.pem` over the same input, so
//! it checks PKCS#1 v1.5 with SHA-256 (RFC 7518 §3.3) independently of ring.

use base64::Engine;
use ring::signature::{RSA_PKCS1_2048_8192_SHA256, RSA_PSS_2048_8192_SHA256};
use serde_json::json;

use super::*;
use crate::testdata::{TEST_ONLY_KEY_A, jwt_part, jwt_verifies};

const OPENSSL_RS256: &str = "NNV2Cwhvy4zlS1rDnG-KoWq1jCajt_Y-KWzkUkFELNZ9XuIaf5FGzj6wFGKvIScqAHX-rtn1iPIvpXBdbPkHZzY0N4AHLqUCNFwsUEFF3Oa-IFVB1aXmz2RE_NoGJtrB_hcreEDnDVfa24tcgx4qoq-sEp6JXja9uIa-8clRY4T8u6BWc_C2I-NnQwwKa8ZgC_lRyCq6Do-A8SBarPS6GBms0-HWMLzF1PDcBEuc0QQtZUZgnl6o82O6pNg3Btku58w3SshjzvYapnYt3JLKNC-K6OKMH1sM25eFRJcN20Ycgc-IRms4htGDNQUwBWkyEY1o7QAXF8PbEFh-4dczRA";

fn key() -> RsaKey {
    RsaKey::from_pem(TEST_ONLY_KEY_A.as_bytes(), "test key").unwrap()
}

#[test]
fn rs256_matches_openssl() {
    let signature = key()
        .signature(
            Algorithm::Rs256,
            b"eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJyZG9jay10ZXN0In0",
        )
        .unwrap();
    assert_eq!(URL_SAFE_NO_PAD.encode(signature), OPENSSL_RS256);
}

#[test]
fn tokens_carry_header_claims_and_a_valid_signature() {
    let key = key();
    let claims = json!({ "iss": "svc@example.iam.gserviceaccount.com", "iat": 1, "exp": 3601 });
    let token = key
        .sign(Algorithm::Rs256, &json!({ "kid": "abc" }), &claims)
        .unwrap();
    assert_eq!(
        jwt_part(&token, 0),
        json!({ "alg": "RS256", "typ": "JWT", "kid": "abc" })
    );
    assert_eq!(jwt_part(&token, 1), claims);
    assert!(jwt_verifies(
        &token,
        &key.public_der(),
        &RSA_PKCS1_2048_8192_SHA256
    ));

    let pss = key.sign(Algorithm::Ps256, &json!({}), &claims).unwrap();
    assert_eq!(jwt_part(&pss, 0)["alg"], "PS256");
    assert!(jwt_verifies(
        &pss,
        &key.public_der(),
        &RSA_PSS_2048_8192_SHA256
    ));
}

#[test]
fn keys_must_be_pem() {
    let error = RsaKey::from_pem(b"not pem", "credentials_file").unwrap_err();
    assert_eq!(error.0, "credentials_file: no private key in PEM form");
}
