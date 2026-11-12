//! OpenAPI 3.1 documents for `validate`: operations matched by method and path template, their
//! parameters and `application/json` request bodies compiled against the document.
//!
//! The document is registered as one schema resource (`urn:rdock:openapi`) and each schema is
//! compiled as a `$ref` into it, so `#/components/schemas/…` references resolve inside the
//! document and nowhere else. Only OpenAPI 3.1 is accepted (its Schema Objects are JSON Schema
//! 2020-12; 3.0's are not). Parameters use the default serialisation (`form` with `explode`
//! for query and cookie, `simple` for path and header); other styles and `content` parameters
//! are refused with a diagnostic rather than checked wrongly.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use http::Method;
use jsonschema::Draft;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use rdock_model::json_patch::{escape_token, lookup};
use rdock_model::transform::is_json_media_type;
use rdock_model::validation::{UnknownOperations, external_references};
use serde_json::{Value, json};

use super::{BodySpec, Media, Operation, Params, PathParams, compile, shape_of};
use crate::{BuildError, Issue, ProblemKind, Reply};

/// The URI the document is registered under.
const DOC_URI: &str = "urn:rdock:openapi";
/// Largest document read.
const MAX_DOCUMENT: usize = 16 << 20;
/// The operation keys of a Path Item, in OpenAPI's order.
const METHODS: [&str; 8] = [
    "get", "put", "post", "delete", "options", "head", "patch", "trace",
];
/// Characters kept as they are in a URI fragment (RFC 3986 `pchar` / `?`, minus `%`).
const FRAGMENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'/')
    .remove(b'~')
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'!')
    .remove(b'$')
    .remove(b'&')
    .remove(b'\'')
    .remove(b'(')
    .remove(b')')
    .remove(b'*')
    .remove(b'+')
    .remove(b',')
    .remove(b';')
    .remove(b'=')
    .remove(b':')
    .remove(b'@');

/// A path template and its operations.
#[derive(Debug)]
struct Template {
    regex: regex::Regex,
    methods: Vec<(Method, usize)>,
    vars: usize,
    literal: usize,
}

/// What a request matched.
pub(crate) enum Found<'a> {
    /// An operation; `path` is the request path below `base_path`.
    Operation { index: usize, path: &'a str },
    /// No operation, and unknown operations are allowed.
    Pass,
    /// No operation: the `404` or `405` to answer.
    Refuse(Reply),
}

/// The operations of a document.
#[derive(Debug)]
pub(crate) struct Router {
    templates: Vec<Template>,
    operations: Vec<Operation>,
    base_path: Option<String>,
    unknown: UnknownOperations,
}

fn issue(message: impl Into<String>) -> Issue {
    Issue::new("openapi", message)
}

/// A JSON Pointer as a `$ref` into the document.
fn reference(pointer: &str) -> Value {
    json!({ "$ref": format!("{DOC_URI}#{}", utf8_percent_encode(pointer, FRAGMENT)) })
}

/// Follows Reference Objects (`$ref: "#/components/…"`) from `pointer`; returns the pointer
/// of the object finally referenced.
fn follow(doc: &Value, mut pointer: String) -> Result<String, String> {
    for _ in 0..8 {
        let value = lookup(doc, &pointer).map_err(|_| format!("`{pointer}` does not exist"))?;
        match value.get("$ref").and_then(Value::as_str) {
            Some(target) => {
                let fragment = target
                    .strip_prefix('#')
                    .ok_or_else(|| format!("`{target}` is outside the document"))?;
                pointer = percent_encoding::percent_decode_str(fragment)
                    .decode_utf8_lossy()
                    .into_owned();
            }
            None => return Ok(pointer),
        }
    }
    Err(format!("`{pointer}`: references nest too deeply"))
}

/// A path template as a regular expression, with its variable names and literal length.
fn template_regex(template: &str) -> Result<(regex::Regex, Vec<String>, usize), String> {
    let mut pattern = String::from("^");
    let mut names = Vec::new();
    let mut literal = 0;
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        let (before, after) = rest.split_at(open);
        pattern.push_str(&regex::escape(before));
        literal += before.len();
        let close = after
            .find('}')
            .ok_or_else(|| format!("path `{template}` has an unclosed `{{`"))?;
        let name = &after[1..close];
        if name.is_empty() {
            return Err(format!("path `{template}` has an empty `{{}}`"));
        }
        names.push(name.to_owned());
        pattern.push_str("([^/]+)");
        rest = &after[close + 1..];
    }
    pattern.push_str(&regex::escape(rest));
    literal += rest.len();
    pattern.push('$');
    let regex = regex::Regex::new(&pattern).map_err(|e| e.to_string())?;
    Ok((regex, names, literal))
}

/// One parameter, resolved.
struct Param {
    name: String,
    location: String,
    required: bool,
    /// Pointer to its `schema`.
    schema: String,
}

/// The parameters of `list_pointer` (an array of Parameter or Reference Objects).
fn parameters(doc: &Value, list_pointer: &str, at: &str) -> Result<Vec<Param>, String> {
    let Ok(list) = lookup(doc, list_pointer) else {
        return Ok(Vec::new());
    };
    let Some(items) = list.as_array() else {
        return Err(format!("{at}: `parameters` is not a list"));
    };
    let mut out = Vec::new();
    for i in 0..items.len() {
        let pointer = follow(doc, format!("{list_pointer}/{i}"))?;
        let param = lookup(doc, &pointer).map_err(|_| format!("`{pointer}` does not exist"))?;
        let name = param
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{at}: parameter {i} has no `name`"))?;
        let location = param
            .get("in")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{at}: parameter `{name}` has no `in`"))?;
        if !matches!(location, "path" | "query" | "header" | "cookie") {
            return Err(format!(
                "{at}: parameter `{name}`: `in: {location}` is not supported (path, query, header, cookie)"
            ));
        }
        if param.get("content").is_some() {
            return Err(format!(
                "{at}: parameter `{name}` uses `content`; only `schema` parameters are checked (planned for a later version)"
            ));
        }
        let default_style = match location {
            "query" | "cookie" => "form",
            _ => "simple",
        };
        let style = param
            .get("style")
            .and_then(Value::as_str)
            .unwrap_or(default_style);
        let explode = param
            .get("explode")
            .and_then(Value::as_bool)
            .unwrap_or(style == "form");
        if style != default_style || explode != (default_style == "form") {
            return Err(format!(
                "{at}: parameter `{name}` uses `style: {style}`/`explode: {explode}`; only the default serialisation is checked (planned for a later version)"
            ));
        }
        if param.get("schema").is_none() {
            return Err(format!("{at}: parameter `{name}` has no `schema`"));
        }
        // OpenAPI: these header parameters are ignored (the fields of the request say it).
        if location == "header"
            && ["accept", "content-type", "authorization"]
                .contains(&name.to_ascii_lowercase().as_str())
        {
            continue;
        }
        out.push(Param {
            name: if location == "header" {
                name.to_ascii_lowercase()
            } else {
                name.to_owned()
            },
            location: location.to_owned(),
            required: location == "path"
                || param.get("required").and_then(Value::as_bool) == Some(true),
            schema: format!("{pointer}/schema"),
        });
    }
    Ok(out)
}

impl Router {
    /// Reads and compiles the document at `path`.
    pub(crate) fn load(
        path: &Path,
        base_path: Option<&str>,
        unknown: UnknownOperations,
        formats: bool,
    ) -> Result<Self, BuildError> {
        let bytes = crate::read_file(path)?;
        if bytes.len() > MAX_DOCUMENT {
            return Err(BuildError::Issues(vec![issue(format!(
                "`{}` is larger than 16 MiB",
                path.display()
            ))]));
        }
        let text = String::from_utf8(bytes).map_err(|_| {
            BuildError::Issues(vec![issue(format!(
                "`{}` is not UTF-8 text",
                path.display()
            ))])
        })?;
        let doc = rdock_config::parse_document(&text, rdock_config::Format::from_path(path))
            .map_err(|e| BuildError::Issues(vec![issue(format!("`{}`: {e}", path.display()))]))?;
        Self::from_document(&doc, base_path, unknown, formats).map_err(|messages| {
            BuildError::Issues(
                messages
                    .into_iter()
                    .map(|m| issue(format!("`{}`: {m}", path.display())))
                    .collect(),
            )
        })
    }

    /// Compiles a parsed document.
    pub(crate) fn from_document(
        doc: &Value,
        base_path: Option<&str>,
        unknown: UnknownOperations,
        formats: bool,
    ) -> Result<Self, Vec<String>> {
        let version = doc
            .get("openapi")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !version.starts_with("3.1.") {
            return Err(vec![format!(
                "`openapi: {version}` is not supported: only OpenAPI 3.1 documents (JSON Schema 2020-12) are read"
            )]);
        }
        if let Some(dialect) = doc.get("jsonSchemaDialect").and_then(Value::as_str)
            && dialect != "https://json-schema.org/draft/2020-12/schema"
            && !dialect.starts_with("https://spec.openapis.org/oas/3.1/dialect/")
        {
            return Err(vec![format!(
                "`jsonSchemaDialect: {dialect}` is not supported; use JSON Schema 2020-12"
            )]);
        }
        let external = external_references(doc);
        if !external.is_empty() {
            return Err(external
                .into_iter()
                .take(5)
                .map(|(at, target)| {
                    format!("`{at}` refers to `{target}`, outside the document; only `#/…` references are allowed")
                })
                .collect());
        }
        let registry = jsonschema::Registry::new()
            .draft(Draft::Draft202012)
            .add(DOC_URI, doc.clone())
            .and_then(jsonschema::RegistryBuilder::prepare)
            .map_err(|e| vec![format!("the document cannot be read as JSON Schema: {e}")])?;
        let Some(paths) = doc.get("paths").and_then(Value::as_object) else {
            return Err(vec!["the document has no `paths`".to_owned()]);
        };
        let mut errors = Vec::new();
        let mut templates = Vec::new();
        let mut operations = Vec::new();
        for path in paths.keys() {
            match template(doc, &registry, path, formats, &mut operations) {
                Ok(t) => templates.push(t),
                Err(e) => errors.extend(e),
            }
        }
        if !errors.is_empty() {
            errors.truncate(20);
            return Err(errors);
        }
        // OpenAPI: concrete paths match before templated ones.
        templates.sort_by_key(|t| (t.vars, std::cmp::Reverse(t.literal)));
        Ok(Self {
            templates,
            operations,
            base_path: base_path.map(str::to_owned),
            unknown,
        })
    }

    /// The operation at `index`.
    pub(crate) fn operation(&self, index: usize) -> Option<&Operation> {
        self.operations.get(index)
    }

    /// Whether some operation checks a body.
    pub(crate) fn has_bodies(&self) -> bool {
        self.operations.iter().any(|op| {
            op.body
                .as_ref()
                .is_some_and(|b| b.content.iter().any(|(_, v)| v.is_some()))
        })
    }

    /// The operation for a request.
    pub(crate) fn find<'a>(&self, method: &Method, path: &'a str) -> Found<'a> {
        let relative = match &self.base_path {
            Some(base) if base != "/" => match path.strip_prefix(base.as_str()) {
                Some("") => Some("/"),
                Some(rest) if rest.starts_with('/') => Some(rest),
                _ => None,
            },
            _ => Some(path),
        };
        let template = relative.and_then(|p| {
            self.templates
                .iter()
                .find(|t| t.regex.is_match(p))
                .map(|t| (t, p))
        });
        if let Some((template, relative)) = template {
            let found = template
                .methods
                .iter()
                .find(|(m, _)| m == method)
                .or_else(|| {
                    (method == Method::HEAD)
                        .then(|| template.methods.iter().find(|(m, _)| m == Method::GET))
                        .flatten()
                });
            if let Some((_, index)) = found {
                return Found::Operation {
                    index: *index,
                    path: relative,
                };
            }
            if self.unknown == UnknownOperations::Allow {
                return Found::Pass;
            }
            let methods: Vec<Method> = template.methods.iter().map(|(m, _)| m.clone()).collect();
            let mut reply = Reply::problem(ProblemKind::MethodNotAllowed);
            if let Some(allow) = super::allow_header(&methods) {
                reply = reply.header(http::header::ALLOW, allow);
            }
            return Found::Refuse(reply);
        }
        match self.unknown {
            UnknownOperations::Allow => Found::Pass,
            UnknownOperations::Deny => Found::Refuse(Reply::problem(ProblemKind::NotFound)),
        }
    }
}

/// Compiles the operations of the path item at `template`, appending them to `operations`.
fn template(
    doc: &Value,
    registry: &jsonschema::Registry<'_>,
    template: &str,
    formats: bool,
    operations: &mut Vec<Operation>,
) -> Result<Template, Vec<String>> {
    if !template.starts_with('/') {
        return Err(vec![format!("path `{template}` does not start with `/`")]);
    }
    let item_pointer =
        follow(doc, format!("/paths/{}", escape_token(template))).map_err(|e| vec![e])?;
    let (regex, names, literal) = template_regex(template).map_err(|e| vec![e])?;
    let shared =
        parameters(doc, &format!("{item_pointer}/parameters"), template).map_err(|e| vec![e])?;
    let mut methods = Vec::new();
    let mut errors = Vec::new();
    for method in METHODS {
        let op_pointer = format!("{item_pointer}/{method}");
        if lookup(doc, &op_pointer).is_err() {
            continue;
        }
        let at = format!("{} {template}", method.to_ascii_uppercase());
        match operation(
            doc,
            registry,
            &op_pointer,
            &at,
            &shared,
            (&regex, &names),
            formats,
        ) {
            Ok(op) => {
                methods.push((
                    Method::from_bytes(method.to_ascii_uppercase().as_bytes())
                        .unwrap_or(Method::GET),
                    operations.len(),
                ));
                operations.push(op);
            }
            Err(e) => errors.extend(e),
        }
    }
    if !errors.is_empty() {
        return Err(errors);
    }
    Ok(Template {
        regex,
        vars: names.len(),
        methods,
        literal,
    })
}

/// Compiles one operation.
fn operation(
    doc: &Value,
    registry: &jsonschema::Registry<'_>,
    op_pointer: &str,
    at: &str,
    shared: &[Param],
    template: (&regex::Regex, &[String]),
    formats: bool,
) -> Result<Operation, Vec<String>> {
    let own = parameters(doc, &format!("{op_pointer}/parameters"), at).map_err(|e| vec![e])?;
    // Operation parameters override path-level ones with the same name and location.
    let mut params: Vec<&Param> = shared
        .iter()
        .filter(|s| {
            !own.iter()
                .any(|o| o.name == s.name && o.location == s.location)
        })
        .collect();
    params.extend(own.iter());
    let mut errors = Vec::new();
    let mut location = |name: &str| -> Option<Params> {
        let list: Vec<&&Param> = params.iter().filter(|p| p.location == name).collect();
        if list.is_empty() {
            return None;
        }
        let properties: serde_json::Map<String, Value> = list
            .iter()
            .map(|p| (p.name.clone(), reference(&p.schema)))
            .collect();
        let required: Vec<&str> = list
            .iter()
            .filter(|p| p.required)
            .map(|p| p.name.as_str())
            .collect();
        let schema = json!({ "type": "object", "properties": properties, "required": required });
        let shapes: HashMap<String, super::Shape> = list
            .iter()
            .map(|p| {
                let schema = lookup(doc, &p.schema).unwrap_or(&Value::Null);
                (p.name.clone(), shape_of(doc, schema))
            })
            .collect();
        match compile(&schema, formats, Some(registry)) {
            Ok(validator) => Some(Params { validator, shapes }),
            Err(e) => {
                errors.push(format!("{at}: the `{name}` parameters do not compile: {e}"));
                None
            }
        }
    };
    let query = location("query");
    let headers = location("header");
    let cookies = location("cookie");
    let path_params = location("path");
    let (regex, names) = template;
    let path = Some(PathParams {
        regex: regex.clone(),
        names: names.iter().cloned().map(Some).collect(),
        params: path_params,
    });
    let body = match request_body(doc, registry, op_pointer, at, formats) {
        Ok(body) => body,
        Err(e) => {
            errors.push(e);
            None
        }
    };
    if errors.is_empty() {
        Ok(Operation {
            path,
            query,
            headers,
            cookies,
            body,
        })
    } else {
        Err(errors)
    }
}

fn request_body(
    doc: &Value,
    registry: &jsonschema::Registry<'_>,
    op_pointer: &str,
    at: &str,
    formats: bool,
) -> Result<Option<BodySpec>, String> {
    let body_pointer = format!("{op_pointer}/requestBody");
    if lookup(doc, &body_pointer).is_err() {
        return Ok(None);
    }
    let body_pointer = follow(doc, body_pointer)?;
    let body = lookup(doc, &body_pointer).map_err(|_| format!("{at}: `requestBody` is missing"))?;
    let required = body.get("required").and_then(Value::as_bool) == Some(true);
    let Some(content) = body.get("content").and_then(Value::as_object) else {
        return Err(format!("{at}: `requestBody` has no `content`"));
    };
    let mut spec = BodySpec {
        required,
        content: Vec::new(),
    };
    for (media, object) in content {
        let validator = if is_json_media_type(media) && object.get("schema").is_some() {
            let pointer = format!("{body_pointer}/content/{}/schema", escape_token(media));
            let validator = compile(&reference(&pointer), formats, Some(registry))
                .map_err(|e| format!("{at}: the `{media}` body schema does not compile: {e}"))?;
            Some(Arc::new(validator))
        } else {
            None
        };
        spec.content.push((Media::parse(media), validator));
    }
    spec.sort();
    Ok(Some(spec))
}
