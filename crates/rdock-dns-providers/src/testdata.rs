//! Throwaway keys for tests only, generated for this crate with
//! `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048` and
//! `openssl req -x509 -new -key …`. They protect nothing and are never accepted anywhere real.

/// A 2048-bit RSA key, PKCS#8 PEM.
pub(crate) const TEST_ONLY_KEY_A: &str = include_str!("../tests/fixtures/test-only-rsa-2048-a.pem");
/// Another 2048-bit RSA key, PKCS#8 PEM, for rotation tests.
pub(crate) const TEST_ONLY_KEY_B: &str = include_str!("../tests/fixtures/test-only-rsa-2048-b.pem");
/// A self-signed certificate for [`TEST_ONLY_KEY_A`], PEM.
pub(crate) const TEST_ONLY_CERT_A: &str = include_str!("../tests/fixtures/test-only-cert-a.pem");

/// The JSON payload of a JWT, decoded.
pub(crate) fn jwt_part(token: &str, index: usize) -> serde_json::Value {
    use base64::Engine;
    let part = token.split('.').nth(index).unwrap();
    serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(part)
            .unwrap(),
    )
    .unwrap()
}

/// Whether `token`'s signature verifies with `key`'s public key under `algorithm`.
pub(crate) fn jwt_verifies(
    token: &str,
    public_der: &[u8],
    algorithm: &'static dyn ring::signature::VerificationAlgorithm,
) -> bool {
    use base64::Engine;
    let (input, signature) = token.rsplit_once('.').unwrap();
    let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(signature)
        .unwrap();
    ring::signature::UnparsedPublicKey::new(algorithm, public_der)
        .verify(input.as_bytes(), &signature)
        .is_ok()
}
