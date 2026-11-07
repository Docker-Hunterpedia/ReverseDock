//! The contract every DNS-01 adapter passes against a fake of its provider (ADR-0026).
//!
//! The fake serves one zone, `example.com`, and refuses writes anywhere else, so a passing run
//! also shows that the adapter found the zone by walking up from [`FQDN`]. The run:
//!
//! 1. for providers with private zones, adds a private zone `app.example.com`, closer to
//!    [`FQDN`] than `example.com`, which refuses writes: the adapter must skip it;
//! 2. builds the solver with its credential as a `${file:…}` reference;
//! 3. presents two values on one name (a wildcard and its base name) and checks both are served;
//! 4. cleans up one and checks the other stays;
//! 5. rotates the credential file and checks the next call reads the new one;
//! 6. makes the next write fail once with a transient error and checks the call still succeeds;
//! 7. cleans up everything.

use std::sync::Arc;

use rdock_acme::dns::DnsSolver;

/// The challenge name every run uses: two labels below the zone `example.com`.
pub const FQDN: &str = "_acme-challenge.app.example.com";

/// What the contract needs from a provider fake.
pub trait ContractFake: Send + Sync {
    /// The TXT values the fake serves at `fqdn`, in any order.
    fn txt_values(&self, fqdn: &str) -> Vec<String>;
    /// From now on, accepts only `credential` (what the solver reads from its credential file).
    fn accept_only(&self, credential: &str);
    /// Fails the next write once with a transient error: `429` with `Retry-After`, `SERVFAIL`.
    fn fail_next_write(&self);
    /// For providers with private zones: adds a private zone `app.example.com` that refuses
    /// writes. Fakes of providers without private zones keep this default, which does nothing.
    fn add_private_zone(&self) {}
}

/// Runs the contract. `credentials` are two valid credentials for the fake, used before and
/// after the rotation; `build` makes the solver from a credential reference.
pub async fn run(
    fake: &dyn ContractFake,
    credentials: [&str; 2],
    build: impl Fn(&str) -> Arc<dyn DnsSolver>,
) {
    // Every write below lands in `example.com` only when the adapter skips this zone.
    fake.add_private_zone();
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("credential");
    std::fs::write(&file, format!("{}\n", credentials[0])).unwrap();
    fake.accept_only(credentials[0]);
    let solver = build(&format!("${{file:{}}}", file.display()));

    solver.present(FQDN, "apex-value").await.unwrap();
    solver.present(FQDN, "wildcard-value").await.unwrap();
    assert_eq!(
        sorted(fake.txt_values(FQDN)),
        ["apex-value", "wildcard-value"]
    );

    solver.cleanup(FQDN, "apex-value").await.unwrap();
    assert_eq!(
        fake.txt_values(FQDN),
        ["wildcard-value"],
        "cleaning up one value keeps the other"
    );

    std::fs::write(&file, credentials[1]).unwrap();
    fake.accept_only(credentials[1]);
    solver
        .present(FQDN, "after-rotation")
        .await
        .expect("the rotated credential is read on the next call");

    fake.fail_next_write();
    solver
        .present(FQDN, "after-retry")
        .await
        .expect("a transient failure is retried");
    assert_eq!(
        sorted(fake.txt_values(FQDN)),
        ["after-retry", "after-rotation", "wildcard-value"]
    );

    for value in ["wildcard-value", "after-rotation", "after-retry"] {
        solver.cleanup(FQDN, value).await.unwrap();
    }
    assert_eq!(fake.txt_values(FQDN), Vec::<String>::new());
}

fn sorted(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values
}
