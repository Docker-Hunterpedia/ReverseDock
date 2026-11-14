//! JSON Schema generation.

use schemars::transform::{RecursiveTransform, Transform};
use schemars::{Schema, SchemaGenerator};
use serde_json::{Map, Value, json};

use crate::Config;
use crate::deprecation::{self, Deprecation, Kind};
use crate::maturity::{self, Level};

/// Identifier of the published schema (`schema/rdock.v1.json` in the repository): the file at
/// the release tag of this version, so the URL does not move once the tag exists (ADR-0033).
pub const SCHEMA_ID: &str = concat!(
    "https://raw.githubusercontent.com/Docker-Hunterpedia/ReverseDock/v",
    env!("CARGO_PKG_VERSION"),
    "/schema/rdock.v1.json"
);

/// The JSON Schema (draft 2020-12) of `rdock.yaml`. Objects reject unknown keys, as ReverseDock
/// does, so editors flag typos; keys starting with `x-` are allowed everywhere (extension fields
/// for YAML anchors).
///
/// Features below stable carry `x-rdock-maturity` (`beta` or `experimental`), `x-rdock-feature`
/// and `x-rdock-since`; deprecated settings carry `"deprecated": true` and
/// `x-rdock-deprecated`. The root lists the whole maturity registry (`x-rdock-features`) and
/// the deprecations (`x-rdock-deprecations`), which the website's pages are generated from.
#[must_use]
pub fn json_schema() -> Schema {
    json_schema_with(&deprecation::entries())
}

/// [`json_schema`] with `deprecations` as the deprecation registry.
#[must_use]
pub fn json_schema_with(deprecations: &[&'static Deprecation]) -> Schema {
    let mut schema = schemars::schema_for!(Config);
    RecursiveTransform(deny_unknown_properties).transform(&mut schema);
    schema.insert("$id".to_owned(), SCHEMA_ID.into());
    schema.insert(
        "title".to_owned(),
        "ReverseDock configuration (rdock.yaml)".into(),
    );
    let mut value = schema.to_value();
    annotate_maturity(&mut value);
    annotate_deprecations(&mut value, deprecations);
    if let Some(root) = value.as_object_mut() {
        root.insert(
            "x-rdock-features".to_owned(),
            serde_json::to_value(maturity::FEATURES).unwrap_or_default(),
        );
        root.insert(
            "x-rdock-deprecations".to_owned(),
            serde_json::to_value(deprecations).unwrap_or_default(),
        );
    }
    Schema::try_from(value).unwrap_or_else(|_| schema_fallback())
}

fn schema_fallback() -> Schema {
    schemars::schema_for!(Config)
}

/// The schema as pretty-printed JSON with a trailing newline, as committed in the repository.
pub fn json_schema_string() -> serde_json::Result<String> {
    serde_json::to_string_pretty(&json_schema()).map(|text| {
        text + "
"
    })
}

/// `experimental`: a list of the experimental features' names.
pub(crate) fn experimental_schema(_: &mut SchemaGenerator) -> Schema {
    let names: Vec<&str> = maturity::experimental_ids().collect();
    let value = json!({
        "type": "array",
        "items": { "type": "string", "enum": names },
        "uniqueItems": true,
    });
    Schema::try_from(value).unwrap_or_default()
}

fn deny_unknown_properties(schema: &mut Schema) {
    if let Some(object) = schema.as_object_mut()
        && object.contains_key("properties")
        && !object.contains_key("additionalProperties")
    {
        object.insert(
            "patternProperties".to_owned(),
            serde_json::json!({ "^x-": {} }),
        );
        object.insert("additionalProperties".to_owned(), false.into());
    }
}

/// Adds `x-rdock-maturity`, `x-rdock-feature` and `x-rdock-since` where a feature below stable
/// lives. A location in a shared definition is marked there, which is right as long as every
/// use of the definition is the same feature (checked by the registry's tests).
fn annotate_maturity(root: &mut Value) {
    for feature in maturity::FEATURES
        .iter()
        .filter(|f| f.level != Level::Stable)
    {
        for location in feature.locations {
            let Some(pointer) = locate(root, location) else {
                continue;
            };
            if let Some(Value::Object(node)) = root.pointer_mut(&pointer) {
                node.insert("x-rdock-maturity".to_owned(), feature.level.as_str().into());
                node.insert("x-rdock-feature".to_owned(), feature.id.into());
                node.insert("x-rdock-since".to_owned(), feature.since.into());
            }
        }
    }
}

/// Marks deprecated settings and values: `"deprecated": true` (JSON Schema 2020-12, which
/// editors show struck through), the facts under `x-rdock-deprecated` and a sentence in the
/// description. A renamed key the model no longer reads is added back under its old name with
/// the schema of the new one.
fn annotate_deprecations(root: &mut Value, deprecations: &[&'static Deprecation]) {
    for entry in deprecations {
        let location = match entry.kind {
            Kind::ConfigKey | Kind::ConfigValue => entry.element,
            _ => continue,
        };
        let pointer = match locate(root, location) {
            Some(pointer) => pointer,
            None => match restore_renamed(root, entry) {
                Some(pointer) => pointer,
                None => continue,
            },
        };
        if let Some(Value::Object(node)) = root.pointer_mut(&pointer) {
            mark_deprecated(node, entry);
        }
    }
}

fn mark_deprecated(node: &mut Map<String, Value>, entry: &Deprecation) {
    node.insert("deprecated".to_owned(), true.into());
    node.insert(
        "x-rdock-deprecated".to_owned(),
        json!({ "since": entry.since, "removal": entry.removal, "replacement": entry.replacement }),
    );
    let sentence = format!(
        "Deprecated since {}, removed in {}: use {}.",
        entry.since, entry.removal, entry.replacement
    );
    let description = match node.get("description").and_then(Value::as_str) {
        Some(text) => format!("{text}\n\n{sentence}"),
        None => sentence,
    };
    node.insert("description".to_owned(), description.into());
}

/// For a key renamed away from the model: its old name, next to the new one, with the new
/// one's schema. Returns where it was added.
fn restore_renamed(root: &mut Value, entry: &Deprecation) -> Option<String> {
    let deprecation::Rewrite::RenameKey(to) = entry.rewrite else {
        return None;
    };
    let (parent, old) = entry.element.rsplit_once('.')?;
    let target = locate(root, &format!("{parent}.{to}"))?;
    let schema = root.pointer(&target)?.clone();
    let (properties, _) = target.rsplit_once('/')?;
    let map = root.pointer_mut(properties)?.as_object_mut()?;
    map.insert(old.to_owned(), schema);
    Some(format!("{properties}/{}", escape(old)))
}

/// The JSON pointer of a schema location (the syntax of
/// [`Feature::locations`](crate::maturity::Feature::locations)): the property for a key, the
/// variant for `key=value`.
#[must_use]
pub fn locate(root: &Value, location: &str) -> Option<String> {
    let mut pointer = String::new();
    let mut first = true;
    for segment in location.split('.') {
        pointer = if first {
            first = false;
            step(root, "", segment)?
        } else {
            step(root, &pointer, segment)?
        };
    }
    Some(pointer)
}

fn escape(key: &str) -> String {
    key.replace('~', "~0").replace('/', "~1")
}

/// One segment from the node at `at`.
fn step(root: &Value, at: &str, segment: &str) -> Option<String> {
    if let Some((key, value)) = segment.split_once('=') {
        // A variant of a tagged object (`type=wasm`), or a value of a property.
        if let Some(found) = search(root, at, &|root, p| variant_with(root, p, key, value), 0) {
            return Some(found);
        }
        let property = search(root, at, &|root, p| property(root, p, key), 0)?;
        return search(root, &property, &|root, p| const_variant(root, p, value), 0)
            .or(Some(property));
    }
    if segment == "*" {
        return search(
            root,
            at,
            &|root, p| {
                let node = root.pointer(p)?;
                if node
                    .get("additionalProperties")
                    .is_some_and(Value::is_object)
                {
                    Some(format!("{p}/additionalProperties"))
                } else if node.get("items").is_some_and(Value::is_object) {
                    Some(format!("{p}/items"))
                } else {
                    None
                }
            },
            0,
        );
    }
    search(root, at, &|root, p| property(root, p, segment), 0)
}

fn property(root: &Value, at: &str, key: &str) -> Option<String> {
    root.pointer(at)?
        .get("properties")?
        .get(key)
        .map(|_| format!("{at}/properties/{}", escape(key)))
}

fn variant_with(root: &Value, at: &str, key: &str, value: &str) -> Option<String> {
    let node = root.pointer(at)?;
    for combinator in ["oneOf", "anyOf"] {
        if let Some(variants) = node.get(combinator).and_then(Value::as_array) {
            for (i, variant) in variants.iter().enumerate() {
                let tag = variant.get("properties").and_then(|p| p.get(key));
                if tag.and_then(|t| t.get("const")).and_then(Value::as_str) == Some(value) {
                    return Some(format!("{at}/{combinator}/{i}"));
                }
            }
        }
    }
    None
}

fn const_variant(root: &Value, at: &str, value: &str) -> Option<String> {
    let node = root.pointer(at)?;
    for combinator in ["oneOf", "anyOf"] {
        if let Some(variants) = node.get(combinator).and_then(Value::as_array) {
            for (i, variant) in variants.iter().enumerate() {
                if variant.get("const").and_then(Value::as_str) == Some(value) {
                    return Some(format!("{at}/{combinator}/{i}"));
                }
            }
        }
    }
    None
}

/// `find` at `at`, else through `$ref` and the alternatives of `anyOf`, `oneOf` and `allOf`.
fn search(
    root: &Value,
    at: &str,
    find: &dyn Fn(&Value, &str) -> Option<String>,
    depth: usize,
) -> Option<String> {
    if depth > 8 {
        return None;
    }
    if let Some(found) = find(root, at) {
        return Some(found);
    }
    let node = root.pointer(at)?;
    if let Some(target) = node.get("$ref").and_then(Value::as_str) {
        let pointer = target.strip_prefix('#')?;
        return search(root, pointer, find, depth + 1);
    }
    for combinator in ["anyOf", "oneOf", "allOf"] {
        if let Some(variants) = node.get(combinator).and_then(Value::as_array) {
            for i in 0..variants.len() {
                if let Some(found) =
                    search(root, &format!("{at}/{combinator}/{i}"), find, depth + 1)
                {
                    return Some(found);
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committed_schema_is_up_to_date() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../schema/rdock.v1.json");
        let committed = std::fs::read_to_string(path).unwrap_or_default();
        assert!(
            committed == json_schema_string().unwrap(),
            "schema/rdock.v1.json is out of date; run `just schema` and commit the result"
        );
    }

    #[test]
    fn schema_has_identity_and_rejects_unknown_root_keys() {
        let schema = json_schema();
        assert_eq!(schema.get("$id").and_then(|v| v.as_str()), Some(SCHEMA_ID));
        assert_eq!(
            schema.get("additionalProperties"),
            Some(&serde_json::Value::Bool(false))
        );
        assert!(
            schema
                .get("patternProperties")
                .is_some_and(|p| p.get("^x-").is_some())
        );
    }

    #[test]
    fn locations_resolve_to_properties_and_variants() {
        let root = schemars::schema_for!(Config).to_value();
        let wasm = locate(&root, "middlewares.*.type=wasm").unwrap();
        assert!(wasm.contains("/oneOf/"), "{wasm}");
        let http3 = locate(&root, "listeners.*.http3").unwrap();
        assert!(http3.ends_with("/properties/http3"), "{http3}");
        let ewma = locate(&root, "services.*.load_balancer.policy=peak_ewma").unwrap();
        assert_eq!(
            root.pointer(&ewma).and_then(|v| v.get("const")),
            Some(&Value::from("peak_ewma"))
        );
        let dns = locate(&root, "acme.dns_provider").unwrap();
        assert!(dns.ends_with("/properties/dns_provider"), "{dns}");
        assert_eq!(locate(&root, "listeners.*.no_such_key"), None);
        let spiffe = locate(&root, "middlewares.*.type=client_cert.spiffe").unwrap();
        assert!(spiffe.ends_with("/properties/spiffe"), "{spiffe}");
    }

    #[test]
    fn experimental_features_are_marked_and_listed() {
        let schema = json_schema().to_value();
        let wasm = locate(&schema, "middlewares.*.type=wasm").unwrap();
        assert_eq!(
            schema.pointer(&format!("{wasm}/x-rdock-maturity")),
            Some(&Value::from("experimental"))
        );
        let cache = locate(&schema, "caches").unwrap();
        assert_eq!(
            schema.pointer(&format!("{cache}/x-rdock-maturity")),
            Some(&Value::from("beta"))
        );
        let routes = locate(&schema, "routes").unwrap();
        assert_eq!(schema.pointer(&format!("{routes}/x-rdock-maturity")), None);
        let features = schema["x-rdock-features"].as_array().unwrap();
        assert_eq!(features.len(), maturity::FEATURES.len());
        assert_eq!(
            schema["properties"]["experimental"]["items"]["enum"],
            json!(["wasm", "http3"])
        );
    }

    #[test]
    fn deprecations_are_marked_and_renamed_keys_come_back() {
        let entries: Vec<&'static Deprecation> = deprecation::REGISTRY
            .iter()
            .chain(deprecation::TEST_ENTRIES)
            .collect();
        let schema = json_schema_with(&entries).to_value();
        let webhook = locate(&schema, "observability.alerts.webhook").unwrap();
        assert_eq!(
            schema.pointer(&format!("{webhook}/deprecated")),
            Some(&Value::Bool(true))
        );
        assert_eq!(
            schema.pointer(&format!("{webhook}/x-rdock-deprecated/removal")),
            Some(&Value::from("2.0"))
        );
        let rule = locate(&schema, "routes.*.rule").unwrap();
        assert_eq!(
            schema.pointer(&format!("{rule}/deprecated")),
            Some(&Value::Bool(true))
        );
        assert_eq!(schema["x-rdock-deprecations"].as_array().unwrap().len(), 4);
        // The committed schema carries only the real registry.
        let plain = json_schema_with(&deprecation::REGISTRY.iter().collect::<Vec<_>>()).to_value();
        assert_eq!(locate(&plain, "routes.*.rule"), None);
    }
}
