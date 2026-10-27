//! Dotted label keys into a JSON tree, and the tree into model types.
//!
//! `health.active.path=/healthz` and `health.active.interval=5s` become
//! `{"health": {"active": {"path": "/healthz", "interval": "5s"}}}`. Values are scalars:
//! `true`/`false` and integers that print back exactly become booleans and numbers, a value
//! in brackets (`[/a, /b]`) becomes a list, anything else stays a string. When a field wants a
//! string and got a number or boolean, the value is turned back into its text and decoding is
//! tried again, so `X-Count: 10` stays a header value.

use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

/// Decode attempts before giving up on type fixes (one per mistyped leaf).
const MAX_FIXES: usize = 32;

/// A JSON object built from dotted keys.
#[derive(Debug, Clone, Default)]
pub(crate) struct Tree(Map<String, Value>);

impl Tree {
    /// Sets `path` (dot-separated) to the scalar `value`. Fails when a prefix of the path is
    /// already a value, or the path is already an object.
    pub(crate) fn set(&mut self, path: &str, value: Value) -> Result<(), String> {
        let mut segments = path.split('.').peekable();
        let mut map = &mut self.0;
        while let Some(segment) = segments.next() {
            if segment.is_empty() {
                return Err(format!("empty segment in `{path}`"));
            }
            if segments.peek().is_none() {
                if map.contains_key(segment) {
                    return Err(format!("`{path}` is set twice"));
                }
                map.insert(segment.to_owned(), value);
                return Ok(());
            }
            let entry = map
                .entry(segment.to_owned())
                .or_insert_with(|| Value::Object(Map::new()));
            let Value::Object(next) = entry else {
                return Err(format!("`{path}` is below a value"));
            };
            map = next;
        }
        Ok(())
    }

    /// Appends `value` to the list at `path`, creating it.
    pub(crate) fn push(&mut self, path: &str, value: Value) -> Result<(), String> {
        let (parent, last) = path.rsplit_once('.').unwrap_or(("", path));
        let mut map = &mut self.0;
        for segment in parent.split('.').filter(|s| !s.is_empty()) {
            let entry = map
                .entry(segment.to_owned())
                .or_insert_with(|| Value::Object(Map::new()));
            let Value::Object(next) = entry else {
                return Err(format!("`{path}` is below a value"));
            };
            map = next;
        }
        match map
            .entry(last.to_owned())
            .or_insert_with(|| Value::Array(Vec::new()))
        {
            Value::Array(items) => {
                items.push(value);
                Ok(())
            }
            _ => Err(format!("`{path}` is not a list")),
        }
    }

    /// Whether nothing was set (every label of the object was rejected).
    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Whether `key` is set at the top level.
    pub(crate) fn has(&self, key: &str) -> bool {
        self.0.contains_key(key)
    }

    /// The tree as a JSON value.
    pub(crate) fn into_value(self) -> Value {
        Value::Object(self.0)
    }
}

/// A label value as a scalar or a bracketed list of scalars.
pub(crate) fn scalar(text: &str) -> Value {
    let trimmed = text.trim();
    if let Some(inner) = trimmed.strip_prefix('[').and_then(|t| t.strip_suffix(']')) {
        return Value::Array(
            inner
                .split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(single)
                .collect(),
        );
    }
    single(text)
}

fn single(text: &str) -> Value {
    match text {
        "true" => Value::Bool(true),
        "false" => Value::Bool(false),
        _ => match text.parse::<i64>() {
            Ok(n) if n.to_string() == text => Value::from(n),
            _ => Value::String(text.to_owned()),
        },
    }
}

/// A comma-separated label value as a list of strings (`a, b` → `["a", "b"]`).
pub(crate) fn list(text: &str) -> Value {
    Value::Array(
        text.split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(|item| Value::String(item.to_owned()))
            .collect(),
    )
}

/// Decodes `value` into `T`; numbers and booleans where `T` wants text are retried as text.
/// The error names the field.
pub(crate) fn decode<T: DeserializeOwned>(mut value: Value) -> Result<T, String> {
    for _ in 0..MAX_FIXES {
        let error = match serde_path_to_error::deserialize::<_, T>(&value) {
            Ok(decoded) => return Ok(decoded),
            Err(error) => error,
        };
        let message = error.inner().to_string();
        let wants_text = message.starts_with("invalid type: integer")
            || message.starts_with("invalid type: boolean");
        if !(wants_text && stringify(&mut value, error.path())) {
            let path = error.path().to_string();
            return Err(if path == "." {
                message
            } else {
                format!("{path}: {message}")
            });
        }
    }
    Err("too many values of the wrong type".to_owned())
}

/// Turns the number or boolean at `path` back into text; false if there is none.
fn stringify(value: &mut Value, path: &serde_path_to_error::Path) -> bool {
    let mut node = value;
    for segment in path {
        node = match (segment, node) {
            (serde_path_to_error::Segment::Map { key }, Value::Object(map)) => {
                match map.get_mut(key) {
                    Some(next) => next,
                    None => return false,
                }
            }
            (serde_path_to_error::Segment::Seq { index }, Value::Array(items)) => {
                match items.get_mut(*index) {
                    Some(next) => next,
                    None => return false,
                }
            }
            _ => return false,
        };
    }
    let text = match node {
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        _ => return false,
    };
    *node = Value::String(text);
    true
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn dotted_keys_build_nested_objects() {
        let mut tree = Tree::default();
        tree.set("health.active.path", scalar("/healthz")).unwrap();
        tree.set("health.active.interval", scalar("5s")).unwrap();
        tree.set("pass_host_header", scalar("false")).unwrap();
        assert_eq!(
            tree.into_value(),
            serde_json::json!({ "health": { "active": { "path": "/healthz", "interval": "5s" } }, "pass_host_header": false })
        );
    }

    #[test]
    fn conflicting_paths_are_errors() {
        let mut tree = Tree::default();
        tree.set("a.b", scalar("1")).unwrap();
        assert!(tree.set("a.b", scalar("2")).is_err());
        assert!(tree.set("a.b.c", scalar("2")).is_err());
        assert!(tree.set("a..c", scalar("2")).is_err());
    }

    #[test]
    fn scalars_keep_text_that_does_not_round_trip() {
        assert_eq!(scalar("10"), Value::from(10));
        assert_eq!(scalar("010"), Value::from("010"));
        assert_eq!(scalar("off"), Value::from("off"));
        assert_eq!(scalar("[/a, /b]"), serde_json::json!(["/a", "/b"]));
        assert_eq!(list("a, b,,c"), serde_json::json!(["a", "b", "c"]));
    }

    #[test]
    fn numbers_become_text_where_text_is_wanted() {
        let value = serde_json::json!({ "X-Count": 10, "X-On": true });
        let headers: BTreeMap<String, String> = decode(value).unwrap();
        assert_eq!(headers["X-Count"], "10");
        assert_eq!(headers["X-On"], "true");
    }

    #[test]
    fn errors_name_the_field() {
        #[derive(Debug, serde::Deserialize)]
        #[allow(dead_code)]
        struct Port {
            port: u16,
        }
        let err = decode::<Port>(serde_json::json!({ "port": "http" })).unwrap_err();
        assert!(err.starts_with("port: invalid type"), "{err}");
    }
}
