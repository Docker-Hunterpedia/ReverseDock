//! JSON Schema generation.

use schemars::Schema;
use schemars::transform::{RecursiveTransform, Transform};

use crate::Config;

/// Stable identifier of the published schema (`schema/rdock.v1.json` in the repository).
pub const SCHEMA_ID: &str =
    "https://raw.githubusercontent.com/Docker-Hunterpedia/ReverseDock/main/schema/rdock.v1.json";

/// The JSON Schema (draft 2020-12) of `rdock.yaml`. Objects reject unknown keys so editors flag
/// typos; at runtime unknown keys are warnings unless `--strict` is used.
#[must_use]
pub fn json_schema() -> Schema {
    let mut schema = schemars::schema_for!(Config);
    RecursiveTransform(deny_unknown_properties).transform(&mut schema);
    schema.insert("$id".to_owned(), SCHEMA_ID.into());
    schema.insert(
        "title".to_owned(),
        "ReverseDock configuration (rdock.yaml)".into(),
    );
    schema
}

/// The schema as pretty-printed JSON with a trailing newline, as committed in the repository.
pub fn json_schema_string() -> serde_json::Result<String> {
    serde_json::to_string_pretty(&json_schema()).map(|text| {
        text + "
"
    })
}

fn deny_unknown_properties(schema: &mut Schema) {
    if let Some(object) = schema.as_object_mut()
        && object.contains_key("properties")
        && !object.contains_key("additionalProperties")
    {
        object.insert("additionalProperties".to_owned(), false.into());
    }
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
    }
}
