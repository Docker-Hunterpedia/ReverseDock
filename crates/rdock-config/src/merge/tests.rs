use std::collections::BTreeSet;

use super::*;
use crate::{Format, load_str};

const FILE: &str = "
listeners:
  web: { address: \":8080\" }
defaults: { listeners: [web], tls: off }
routes:
  site: { match: \"Host(`site.example.com`)\", service: site }
services:
  site: { backends: [{ address: \"site:80\" }] }
middlewares:
  secure: { type: headers, response: { set: { X-Frame-Options: DENY } } }
";

fn base(yaml: &str) -> Config {
    let loaded = load_str(yaml, Format::Yaml).unwrap();
    assert!(!loaded.has_errors(), "{:?}", loaded.diagnostics);
    loaded.config
}

fn docker(yaml: &str) -> Snapshot {
    let fragment: Fragment = serde_saphyr::from_str(yaml).unwrap();
    Snapshot {
        provider: "docker".to_owned(),
        fragment,
        diagnostics: Vec::new(),
    }
}

const APP: &str = "
routes:
  app: { match: \"Host(`app.example.com`)\", service: app, middlewares: [secure, limit] }
services:
  app: { backends: [{ address: \"10.0.0.5:3000\" }] }
middlewares:
  limit: { type: rate_limit, average: 10 }
";

#[test]
fn provider_objects_get_qualified_keys_and_same_provider_references() {
    let merged = assemble(&base(FILE), &[&docker(APP)], &BTreeSet::new());
    assert_eq!(merged.errors, Vec::new());
    assert_eq!(merged.skipped, Vec::new());
    let route = &merged.config.routes["app@docker"];
    assert_eq!(route.service, "app@docker");
    // `secure` exists only in the file; `limit` is the container's own.
    assert_eq!(route.middlewares, ["secure", "limit@docker"]);
    assert!(merged.config.services.contains_key("app@docker"));
    assert!(merged.config.routes.contains_key("site"));
}

#[test]
fn a_bad_object_is_left_out_with_what_needs_it() {
    let snapshot = docker(
        "
routes:
  app: { match: \"Host(`app.example.com`)\", service: app }
  broken: { match: \"Host(`b.example.com`)\", service: missing }
services:
  app: { backends: [{ address: \"10.0.0.5:3000\" }] }
",
    );
    let merged = assemble(&base(FILE), &[&snapshot], &BTreeSet::new());
    assert_eq!(merged.errors, Vec::new());
    assert!(merged.config.routes.contains_key("app@docker"));
    assert!(!merged.config.routes.contains_key("broken@docker"));
    assert_eq!(merged.skipped.len(), 1);
    assert_eq!(merged.skipped[0].path, "routes[\"broken@docker\"]");
    assert!(
        merged.skipped[0]
            .message
            .starts_with("left out: service `missing` does not exist")
    );
}

#[test]
fn excluded_objects_take_their_dependents_with_them() {
    let excluded = BTreeSet::from([(Section::Services, "app@docker".to_owned())]);
    let merged = assemble(&base(FILE), &[&docker(APP)], &excluded);
    assert_eq!(merged.errors, Vec::new());
    assert!(!merged.config.routes.contains_key("app@docker"));
    assert_eq!(merged.skipped.len(), 1, "{:?}", merged.skipped);
}

#[test]
fn a_file_route_that_needs_a_missing_provider_object_is_left_out() {
    let file = FILE.replace(
        "routes:\n",
        "routes:\n  other: { match: \"Host(`o.example.com`)\", service: \"app@docker\" }\n",
    );
    let merged = assemble(&base(&file), &[], &BTreeSet::new());
    assert_eq!(merged.errors, Vec::new());
    assert!(!merged.config.routes.contains_key("other"));
    assert!(merged.config.routes.contains_key("site"));
}

#[test]
fn owners_are_found_in_both_path_forms() {
    assert_eq!(
        owner("routes.app.tls"),
        Some((Section::Routes, "app".to_owned()))
    );
    assert_eq!(
        owner("services[\"api@docker\"].backends[0].address"),
        Some((Section::Services, "api@docker".to_owned()))
    );
    assert_eq!(
        owner("middlewares.limit"),
        Some((Section::Middlewares, "limit".to_owned()))
    );
    assert_eq!(owner("tcp_routes.db"), None);
    assert_eq!(owner("defaults.certificate"), None);
}
