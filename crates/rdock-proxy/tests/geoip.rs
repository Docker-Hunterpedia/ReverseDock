//! GeoIP (H-SEC-04): lookups in generated MaxMind DB files, both record shapes, reload and
//! reuse, freshness, and how `ClientCountry` and its negation treat unknown addresses.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;

use http::HeaderMap;
use rdock_model::settings::{GeoIp as Settings, OnStale};
use rdock_model::values::Duration;
use rdock_proxy::geoip::GeoIp;
use rdock_proxy::router::{Facts, Rule};
use rdock_testkit::mmdb::{self, Value};

const GB: &str = "81.2.69.142";
const SE: &str = "89.160.20.112";
const JP: &str = "2001:218::1";
const UNKNOWN: &str = "8.8.4.4";

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn country_db(path: &Path, days_old: u64, gb_as: &str) {
    let bytes = mmdb::build(
        "GeoLite2-Country",
        mmdb::days_ago(days_old),
        &[
            (ip("81.2.69.0"), 24, mmdb::country(gb_as, "EU")),
            (ip("89.160.20.0"), 24, mmdb::country("SE", "EU")),
            (ip("2001:218::"), 32, mmdb::country("JP", "AS")),
        ],
    );
    std::fs::write(path, bytes).unwrap();
}

fn asn_db(path: &Path) {
    let bytes = mmdb::build(
        "GeoLite2-ASN",
        mmdb::days_ago(1),
        &[
            (ip("81.2.69.0"), 24, mmdb::asn(64496)),
            (ip("89.160.20.0"), 24, mmdb::asn(65551)),
        ],
    );
    std::fs::write(path, bytes).unwrap();
}

fn settings(dir: &Path) -> Settings {
    Settings {
        database: Some(dir.join("country.mmdb")),
        asn_database: Some(dir.join("asn.mmdb")),
        ..Settings::default()
    }
}

fn load(settings: &Settings, previous: Option<&GeoIp>) -> Arc<GeoIp> {
    GeoIp::load(settings, previous, SystemTime::now())
        .unwrap()
        .geoip
}

#[test]
fn looks_up_country_continent_and_asn() {
    let dir = tempfile::tempdir().unwrap();
    country_db(&dir.path().join("country.mmdb"), 1, "GB");
    asn_db(&dir.path().join("asn.mmdb"));
    let geo = load(&settings(dir.path()), None);
    let gb = geo.lookup(ip(GB));
    assert_eq!(gb.country_str(), Some("GB"));
    assert_eq!(gb.continent, Some(*b"EU"));
    assert_eq!(gb.asn, Some(64496));
    assert_eq!(geo.lookup(ip(SE)).asn, Some(65551));
    assert_eq!(geo.lookup(ip(JP)).country_str(), Some("JP"));
    // IPv4-mapped IPv6 is looked up as IPv4.
    assert_eq!(
        geo.lookup(ip("::ffff:81.2.69.142")).country_str(),
        Some("GB")
    );
    // Unknown and non-global addresses have nothing.
    assert_eq!(
        geo.lookup(ip(UNKNOWN)),
        rdock_proxy::geoip::GeoRecord::default()
    );
    assert_eq!(
        geo.lookup(ip("10.0.0.1")),
        rdock_proxy::geoip::GeoRecord::default()
    );
    assert_eq!(
        geo.lookup(ip("127.0.0.1")),
        rdock_proxy::geoip::GeoRecord::default()
    );
}

#[test]
fn reads_ipinfo_lite_records() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ipinfo.mmdb");
    let record = Value::map(&[
        ("country_code", Value::str("SE")),
        ("continent_code", Value::str("EU")),
        ("asn", Value::str("AS65551")),
    ]);
    std::fs::write(
        &path,
        mmdb::build(
            "ipinfo lite",
            mmdb::days_ago(1),
            &[(ip("89.160.20.0"), 24, record)],
        ),
    )
    .unwrap();
    let geo = load(
        &Settings {
            database: Some(path),
            ..Settings::default()
        },
        None,
    );
    let se = geo.lookup(ip(SE));
    assert_eq!(se.country_str(), Some("SE"));
    assert_eq!(se.asn, Some(65551), "ASN from the country file");
}

#[test]
fn a_reload_reuses_an_unchanged_file_and_swaps_a_changed_one() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("country.mmdb");
    country_db(&file, 1, "GB");
    asn_db(&dir.path().join("asn.mmdb"));
    let s = settings(dir.path());
    let first = load(&s, None);
    let again = load(&s, Some(&first));
    let (a, b) = (first.databases(), again.databases());
    assert!(
        std::ptr::eq(a["country"], b["country"]),
        "unchanged file reused"
    );
    // A new file (written aside and renamed, as downloaders do) is read again.
    let tmp = dir.path().join("country.tmp");
    country_db(&tmp, 0, "IE");
    std::fs::rename(&tmp, &file).unwrap();
    let swapped = load(&s, Some(&again));
    assert_eq!(swapped.lookup(ip(GB)).country_str(), Some("IE"));
    assert_eq!(
        again.lookup(ip(GB)).country_str(),
        Some("GB"),
        "the old set is untouched"
    );
}

#[test]
fn stale_databases_warn_or_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    country_db(&dir.path().join("country.mmdb"), 45, "GB");
    asn_db(&dir.path().join("asn.mmdb"));
    let mut s = settings(dir.path());
    let loaded = GeoIp::load(&s, None, SystemTime::now()).unwrap();
    assert_eq!(loaded.warnings.len(), 1);
    assert!(
        loaded.warnings[0].contains("45 days"),
        "{}",
        loaded.warnings[0]
    );
    s.on_stale = OnStale::Refuse;
    let err = GeoIp::load(&s, None, SystemTime::now()).unwrap_err();
    assert!(err.contains("max_age"), "{err}");
    s.max_age = Duration::from_secs(60 * 86_400);
    assert!(GeoIp::load(&s, None, SystemTime::now()).is_ok());
}

#[test]
fn missing_or_broken_files_are_errors() {
    let dir = tempfile::tempdir().unwrap();
    let s = settings(dir.path());
    assert!(GeoIp::load(&s, None, SystemTime::now()).is_err());
    std::fs::write(dir.path().join("country.mmdb"), b"not a database").unwrap();
    asn_db(&dir.path().join("asn.mmdb"));
    let err = GeoIp::load(&s, None, SystemTime::now()).unwrap_err();
    assert!(err.contains("not a MaxMind DB"), "{err}");
}

#[test]
fn unknown_addresses_never_match_and_negation_lets_them_through() {
    let dir = tempfile::tempdir().unwrap();
    country_db(&dir.path().join("country.mmdb"), 1, "GB");
    asn_db(&dir.path().join("asn.mmdb"));
    let geo = load(&settings(dir.path()), None);
    let headers = HeaderMap::new();
    let matches = |rule: &str, client: &str| {
        let rule = Rule::compile_with(&rdock_rules::parse(rule).unwrap(), Some(&geo)).unwrap();
        rule.matches(&Facts {
            host: "a.test",
            path: "/",
            method: "GET",
            headers: &headers,
            query: &[],
            client_ip: ip(client),
            fingerprint: None,
        })
    };
    assert!(matches("ClientCountry(`GB`, `SE`)", GB));
    assert!(
        matches("ClientCountry(`gb`)", GB),
        "codes compare in upper case"
    );
    assert!(!matches("ClientCountry(`GB`)", SE));
    assert!(matches("ClientContinent(`AS`)", JP));
    assert!(matches("ClientASN(`64496`)", GB));
    assert!(!matches("ClientASN(`64496`)", SE));
    for nowhere in [UNKNOWN, "10.0.0.1", "::1"] {
        assert!(!matches("ClientCountry(`GB`)", nowhere), "{nowhere}");
        assert!(!matches("ClientContinent(`EU`)", nowhere), "{nowhere}");
        assert!(!matches("ClientASN(`64496`)", nowhere), "{nowhere}");
        // Negation is boolean: an unknown address is not in `GB`, so `!ClientCountry` matches.
        // A deny rule written as a negation therefore lets unknown addresses through; an
        // allow-list (`ClientCountry(...)`) keeps them out.
        assert!(matches("!ClientCountry(`GB`)", nowhere), "{nowhere}");
    }
    assert!(!matches("!ClientCountry(`GB`)", GB));
    assert!(Rule::compile(&rdock_rules::parse("ClientCountry(`GB`)").unwrap()).is_err());
}
