//! `validate`: request parameters and JSON bodies checked against JSON Schema 2020-12, inline
//! or from an OpenAPI 3.1 document (F-GW-03, ADR-0030).
//!
//! Schemas are compiled once, when the middleware is built; a schema that does not compile is
//! a configuration error. No schema can fetch anything: `jsonschema` is built without its HTTP
//! and file resolvers and every validator is offline, and references outside the schema's own
//! document are refused before compiling. `pattern` uses the linear-time `regex` engine, so a
//! client cannot make a pattern backtrack.
//!
//! Parameters are checked in the `request` phase; the body, when a schema needs it, in the
//! `request_body` phase (held up to `max_body`). Answers list at most `max_errors` entries
//! `{ pointer, message }`: the pointer names the location (`/query/limit`, `/body/items/0`),
//! the message the failing keyword and the schema's own limits, never the request's value.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use http::{HeaderValue, Method};
use jsonschema::{Draft, PatternOptions, Validator};
use pingora::http::RequestHeader;
use rdock_model::transform::is_json_media_type;
use rdock_model::validation::{ValidateConfig, ValidationMode};
use serde_json::{Map, Value, json};

use crate::held::HeldBody;
use crate::phase::{BodyHold, BodyVerdict, Capabilities};
use crate::{BuildError, Context, Flow, Issue, Middleware, ProblemKind, Reply};

mod openapi;

/// Longest pointer reported; longer ones are cut (they come from the client's JSON keys).
const MAX_POINTER: usize = 256;

/// What a parameter value converts to before it is checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scalar {
    String,
    Integer,
    Number,
    Boolean,
}

/// A parameter's shape: one value, or an array of values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Shape {
    One(Scalar),
    Many(Scalar),
}

/// The declared shape of `schema`, following `$ref`s inside `root`.
pub(crate) fn shape_of(root: &Value, schema: &Value) -> Shape {
    let resolved = resolve(root, schema);
    match type_of(resolved) {
        Some("array") => {
            let items = resolved
                .get("items")
                .map_or(&Value::Null, |i| resolve(root, i));
            Shape::Many(scalar(type_of(items)))
        }
        other => Shape::One(scalar(other)),
    }
}

fn scalar(name: Option<&str>) -> Scalar {
    match name {
        Some("integer") => Scalar::Integer,
        Some("number") => Scalar::Number,
        Some("boolean") => Scalar::Boolean,
        _ => Scalar::String,
    }
}

/// The first non-null `type` of a schema.
fn type_of(schema: &Value) -> Option<&str> {
    match schema.get("type")? {
        Value::String(t) => Some(t),
        Value::Array(types) => types
            .iter()
            .filter_map(Value::as_str)
            .find(|t| *t != "null"),
        _ => None,
    }
}

/// Follows `$ref: "#…"` inside `root`, at most eight times.
pub(crate) fn resolve<'a>(root: &'a Value, mut schema: &'a Value) -> &'a Value {
    for _ in 0..8 {
        let Some(target) = schema.get("$ref").and_then(Value::as_str) else {
            break;
        };
        let Some(fragment) = target.strip_prefix('#') else {
            break;
        };
        let pointer = percent_encoding::percent_decode_str(fragment).decode_utf8_lossy();
        match rdock_model::json_patch::lookup(root, &pointer) {
            Ok(next) => schema = next,
            Err(_) => break,
        }
    }
    schema
}

/// The shapes of an object schema's properties, keyed by property name (lower-case when
/// `lower`).
pub(crate) fn property_shapes(root: &Value, schema: &Value, lower: bool) -> HashMap<String, Shape> {
    let schema = resolve(root, schema);
    schema
        .get("properties")
        .and_then(Value::as_object)
        .map(|props| {
            props
                .iter()
                .map(|(name, s)| {
                    let key = if lower {
                        name.to_ascii_lowercase()
                    } else {
                        name.clone()
                    };
                    (key, shape_of(root, s))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Compiles a schema: JSON Schema 2020-12 unless `$schema` says otherwise, offline, linear-time
/// patterns, `format` asserted when `formats`.
pub(crate) fn compile(
    schema: &Value,
    formats: bool,
    registry: Option<&jsonschema::Registry<'_>>,
) -> Result<Validator, String> {
    let mut options = jsonschema::options()
        .with_draft(Draft::Draft202012)
        .should_validate_formats(formats)
        .with_pattern_options(PatternOptions::regex());
    if let Some(registry) = registry {
        options = options.with_registry(registry);
    }
    options.build(schema).map_err(|e| e.to_string())
}

/// A parameter location's compiled schema.
#[derive(Debug)]
pub(crate) struct Params {
    pub(crate) validator: Validator,
    pub(crate) shapes: HashMap<String, Shape>,
}

impl Params {
    fn check(&self, pairs: Vec<(String, String)>, prefix: &str, out: &mut Errors) {
        let object = object_of(pairs, &self.shapes);
        out.collect(&self.validator, &object, prefix);
    }
}

/// Path parameters: a regular expression for the path and the names of its groups.
#[derive(Debug)]
pub(crate) struct PathParams {
    pub(crate) regex: regex::Regex,
    /// The parameter name of capture group `i + 1`.
    pub(crate) names: Vec<Option<String>>,
    pub(crate) params: Option<Params>,
}

/// Which bodies an operation accepts.
#[derive(Debug)]
pub(crate) enum Media {
    /// `application/json` and `+json` types.
    Json,
    /// One media type, lower-case (`application/xml`).
    Exact(String),
    /// A type with any subtype (`image/*`).
    Type(String),
    /// Anything (`*/*`).
    Any,
}

impl Media {
    pub(crate) fn parse(range: &str) -> Self {
        let range = range
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        if range == "*/*" {
            Self::Any
        } else if let Some(main) = range.strip_suffix("/*") {
            Self::Type(main.to_owned())
        } else {
            Self::Exact(range)
        }
    }

    fn matches(&self, content_type: &str) -> bool {
        let media = content_type
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        match self {
            Self::Json => is_json_media_type(&media),
            Self::Exact(m) => *m == media,
            Self::Type(t) => media.split('/').next() == Some(t.as_str()),
            Self::Any => true,
        }
    }

    /// More specific ranges first: exact, JSON, type, any.
    fn rank(&self) -> u8 {
        match self {
            Self::Exact(_) => 0,
            Self::Json => 1,
            Self::Type(_) => 2,
            Self::Any => 3,
        }
    }
}

/// An operation's request body.
#[derive(Debug)]
pub(crate) struct BodySpec {
    pub(crate) required: bool,
    /// Accepted media types, most specific first, with the schema of JSON ones.
    pub(crate) content: Vec<(Media, Option<Arc<Validator>>)>,
}

impl BodySpec {
    pub(crate) fn sort(&mut self) {
        self.content.sort_by_key(|(media, _)| media.rank());
    }

    fn find(&self, content_type: Option<&str>) -> Option<&Option<Arc<Validator>>> {
        let content_type = content_type?;
        self.content
            .iter()
            .find(|(media, _)| media.matches(content_type))
            .map(|(_, v)| v)
    }
}

/// Everything checked for one operation.
#[derive(Debug, Default)]
pub(crate) struct Operation {
    pub(crate) path: Option<PathParams>,
    pub(crate) query: Option<Params>,
    pub(crate) headers: Option<Params>,
    pub(crate) cookies: Option<Params>,
    pub(crate) body: Option<BodySpec>,
}

#[derive(Debug)]
enum Spec {
    Inline(Box<Operation>),
    OpenApi(openapi::Router),
}

/// Errors found so far, at most `max`.
struct Errors {
    max: usize,
    list: Vec<Value>,
    /// More errors than `max` were found.
    truncated: bool,
}

impl Errors {
    fn new(max: usize) -> Self {
        Self {
            max,
            list: Vec::new(),
            truncated: false,
        }
    }

    fn push(&mut self, pointer: &str, message: &str) {
        if self.list.len() >= self.max {
            self.truncated = true;
            return;
        }
        let mut pointer = pointer.to_owned();
        if pointer.len() > MAX_POINTER {
            let mut cut = MAX_POINTER;
            while !pointer.is_char_boundary(cut) {
                cut -= 1;
            }
            pointer.truncate(cut);
            pointer.push('…');
        }
        self.list
            .push(json!({ "pointer": pointer, "message": message }));
    }

    fn collect(&mut self, validator: &Validator, instance: &Value, prefix: &str) {
        for error in validator.iter_errors(instance) {
            if self.list.len() >= self.max {
                self.truncated = true;
                return;
            }
            let pointer = format!("{prefix}{}", error.instance_path().as_str());
            self.push(&pointer, &message(error.kind()));
        }
    }

    fn is_empty(&self) -> bool {
        self.list.is_empty()
    }
}

/// A message for a failed keyword. It quotes only the schema (its limits, required names,
/// formats), never the instance.
fn message(kind: &jsonschema::error::ValidationErrorKind) -> String {
    use jsonschema::error::{TypeKind, ValidationErrorKind as K};
    match kind {
        K::Required { property } => match property.as_str() {
            Some(name) => format!("`{name}` is required"),
            None => "a required member is missing".to_owned(),
        },
        K::Type { kind } => match kind {
            TypeKind::Single(t) => format!("must be of type {t}"),
            TypeKind::Multiple(set) => format!(
                "must be of type {}",
                set.iter()
                    .map(|t| t.to_string())
                    .collect::<Vec<_>>()
                    .join(" or ")
            ),
        },
        K::Minimum { limit } => format!("must be at least {limit}"),
        K::Maximum { limit } => format!("must be at most {limit}"),
        K::ExclusiveMinimum { limit } => format!("must be greater than {limit}"),
        K::ExclusiveMaximum { limit } => format!("must be less than {limit}"),
        K::MinLength { limit } => format!("must be at least {limit} characters long"),
        K::MaxLength { limit } => format!("must be at most {limit} characters long"),
        K::MinItems { limit } => format!("must have at least {limit} items"),
        K::MaxItems { limit } => format!("must have at most {limit} items"),
        K::MinProperties { limit } => format!("must have at least {limit} members"),
        K::MaxProperties { limit } => format!("must have at most {limit} members"),
        K::Format { format } => format!("is not a valid `{format}`"),
        K::Enum { .. } | K::Constant { .. } => "is not an allowed value".to_owned(),
        K::Pattern { .. } => "does not match the required pattern".to_owned(),
        K::AdditionalProperties { .. } | K::UnevaluatedProperties { .. } => {
            "has members the schema does not allow".to_owned()
        }
        K::FalseSchema => "is not allowed".to_owned(),
        K::UniqueItems => "must not repeat items".to_owned(),
        other => format!("fails `{}`", other.keyword()),
    }
}

fn convert(value: &str, scalar: Scalar) -> Value {
    match scalar {
        Scalar::String => Value::String(value.to_owned()),
        Scalar::Integer => value
            .parse::<i64>()
            .map(Value::from)
            .or_else(|_| value.parse::<u64>().map(Value::from))
            .unwrap_or_else(|_| Value::String(value.to_owned())),
        Scalar::Number => value
            .parse::<f64>()
            .ok()
            .and_then(serde_json::Number::from_f64)
            .map_or_else(|| Value::String(value.to_owned()), Value::Number),
        Scalar::Boolean => match value {
            "true" => Value::Bool(true),
            "false" => Value::Bool(false),
            other => Value::String(other.to_owned()),
        },
    }
}

/// The object a parameter schema checks: one member per name; a repeated name whose schema
/// is not an array becomes an array, which fails its type (parameter pollution is refused).
fn object_of(pairs: Vec<(String, String)>, shapes: &HashMap<String, Shape>) -> Value {
    let mut grouped: Vec<(String, Vec<String>)> = Vec::new();
    for (name, value) in pairs {
        match grouped.iter_mut().find(|(n, _)| *n == name) {
            Some((_, values)) => values.push(value),
            None => grouped.push((name, vec![value])),
        }
    }
    let mut object = Map::new();
    for (name, values) in grouped {
        let value = match shapes.get(&name) {
            Some(Shape::Many(s)) => Value::Array(values.iter().map(|v| convert(v, *s)).collect()),
            Some(Shape::One(s)) if values.len() == 1 => convert(&values[0], *s),
            None if values.len() == 1 => Value::String(values[0].clone()),
            _ => Value::Array(values.into_iter().map(Value::String).collect()),
        };
        object.insert(name, value);
    }
    Value::Object(object)
}

fn decode(text: &str) -> String {
    percent_encoding::percent_decode_str(text)
        .decode_utf8_lossy()
        .into_owned()
}

fn query_pairs(req: &RequestHeader) -> Vec<(String, String)> {
    req.uri
        .query()
        .map(|q| {
            url::form_urlencoded::parse(q.as_bytes())
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect()
        })
        .unwrap_or_default()
}

fn header_pairs(req: &RequestHeader) -> Vec<(String, String)> {
    req.headers
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_owned(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect()
}

fn cookie_pairs(req: &RequestHeader) -> Vec<(String, String)> {
    req.headers
        .get_all(http::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| {
            let (name, value) = pair.trim().split_once('=')?;
            Some((
                name.trim().to_owned(),
                value.trim().trim_matches('"').to_owned(),
            ))
        })
        .collect()
}

/// What `request` leaves for `request_body`.
struct Pending {
    validator: Arc<Validator>,
}

/// The `validate` middleware.
#[derive(Debug)]
pub(crate) struct Validate {
    name: Arc<str>,
    spec: Spec,
    mode: ValidationMode,
    max_errors: usize,
    max_body: u64,
    metrics: Option<rdock_observability::Metrics>,
}

impl Validate {
    pub(crate) fn new(
        name: &str,
        config: &ValidateConfig,
        metrics: Option<&rdock_observability::Metrics>,
    ) -> Result<Self, BuildError> {
        let spec = match &config.openapi {
            Some(path) => Spec::OpenApi(openapi::Router::load(
                path,
                config.base_path.as_deref(),
                config.unknown_operations,
                config.formats,
            )?),
            None => Spec::Inline(Box::new(inline(config)?)),
        };
        Ok(Self {
            name: Arc::from(name),
            spec,
            mode: config.mode,
            max_errors: usize::try_from(config.max_errors.max(1)).unwrap_or(5),
            max_body: config.max_body.as_u64(),
            metrics: metrics.cloned(),
        })
    }

    fn count(&self, result: &str) {
        if let Some(m) = &self.metrics {
            m.validation_requests
                .with_label_values(&[&*self.name, result])
                .inc();
        }
    }

    fn operation(&self, index: usize) -> Option<&Operation> {
        match &self.spec {
            Spec::Inline(op) => Some(op),
            Spec::OpenApi(router) => router.operation(index),
        }
    }

    /// Fails the request with `errors`, or lets it through in `report` mode.
    fn fail(&self, errors: &Errors, cx: &Context) -> Option<Reply> {
        if self.mode == ValidationMode::Report {
            self.count("reported");
            let first = errors
                .list
                .first()
                .and_then(|e| e["pointer"].as_str())
                .unwrap_or_default();
            tracing::warn!(
                middleware = %self.name,
                route = %cx.route,
                request_id = %cx.request_id,
                errors = errors.list.len(),
                first,
                "request does not match its schema (report mode: let through)"
            );
            return None;
        }
        self.count("invalid");
        let mut reply = Reply::problem(ProblemKind::ValidationFailed)
            .extension("errors", Value::Array(errors.list.clone()));
        if errors.truncated {
            reply = reply.extension("errors_truncated", Value::Bool(true));
        }
        Some(reply)
    }

    fn unsupported(&self, cx: &Context) -> Option<Reply> {
        self.count("unsupported_media_type");
        if self.mode == ValidationMode::Report {
            tracing::warn!(middleware = %self.name, route = %cx.route, request_id = %cx.request_id, "request body has an unsupported content type (report mode: let through)");
            return None;
        }
        Some(Reply::problem(ProblemKind::UnsupportedMediaType))
    }
}

/// The inline schemas of `config` as one operation.
fn inline(config: &ValidateConfig) -> Result<Operation, BuildError> {
    let mut issues = Vec::new();
    let mut params = |field: &str, schema: Option<&Value>, lower: bool| {
        let schema = schema?;
        match compile(schema, config.formats, None) {
            Ok(validator) => Some(Params {
                validator,
                shapes: property_shapes(schema, schema, lower),
            }),
            Err(e) => {
                issues.push(Issue::new(
                    field,
                    format!("the schema does not compile: {e}"),
                ));
                None
            }
        }
    };
    let query = params("query", config.query.as_ref(), false);
    let headers = params("headers", config.headers.as_ref(), true);
    let cookies = params("cookies", config.cookies.as_ref(), false);
    let path_schema = params(
        "path.schema",
        config.path.as_ref().map(|p| &p.schema),
        false,
    );
    let path = match &config.path {
        Some(p) => match regex::RegexBuilder::new(&p.regex)
            .size_limit(1 << 20)
            .build()
        {
            Ok(regex) => {
                let names = regex
                    .capture_names()
                    .skip(1)
                    .map(|n| n.map(str::to_owned))
                    .collect();
                Some(PathParams {
                    regex,
                    names,
                    params: path_schema,
                })
            }
            Err(e) => {
                issues.push(Issue::new(
                    "path.regex",
                    format!("invalid regular expression: {e}"),
                ));
                None
            }
        },
        None => None,
    };
    let body = match &config.body {
        Some(schema) => match compile(schema, config.formats, None) {
            Ok(v) => Some(BodySpec {
                required: config.body_required,
                content: vec![(Media::Json, Some(Arc::new(v)))],
            }),
            Err(e) => {
                issues.push(Issue::new(
                    "body",
                    format!("the schema does not compile: {e}"),
                ));
                None
            }
        },
        None => None,
    };
    if issues.is_empty() {
        Ok(Operation {
            path,
            query,
            headers,
            cookies,
            body,
        })
    } else {
        Err(BuildError::Issues(issues))
    }
}

#[async_trait]
impl Middleware for Validate {
    fn capabilities(&self) -> Capabilities {
        let caps = Capabilities::DEFAULT.with_state();
        let body = match &self.spec {
            Spec::Inline(op) => op.body.is_some(),
            Spec::OpenApi(router) => router.has_bodies(),
        };
        if body {
            caps.with_body(BodyHold::new(self.max_body))
        } else {
            caps
        }
    }

    async fn request(&self, req: &mut RequestHeader, cx: &mut Context) -> Flow {
        let raw_path = req.uri.path().to_owned();
        let (index, path) = match &self.spec {
            Spec::Inline(_) => (0, raw_path.as_str()),
            Spec::OpenApi(router) => match router.find(&req.method, &raw_path) {
                openapi::Found::Operation { index, path } => (index, path),
                openapi::Found::Pass => {
                    cx.waive_body_hold();
                    return Flow::Next;
                }
                openapi::Found::Refuse(reply) => {
                    cx.waive_body_hold();
                    self.count("unknown_operation");
                    if self.mode == ValidationMode::Report {
                        tracing::warn!(middleware = %self.name, route = %cx.route, request_id = %cx.request_id, "request matches no operation of the document (report mode: let through)");
                        return Flow::Next;
                    }
                    return Flow::Reply(reply);
                }
            },
        };
        let Some(op) = self.operation(index) else {
            cx.waive_body_hold();
            return Flow::Next;
        };
        let mut errors = Errors::new(self.max_errors);
        if let Some(p) = &op.path {
            match p.regex.captures(path) {
                Some(captures) => {
                    if let Some(params) = &p.params {
                        let pairs = p
                            .names
                            .iter()
                            .enumerate()
                            .filter_map(|(i, name)| {
                                let name = name.as_ref()?;
                                let value = captures.get(i + 1)?;
                                Some((name.clone(), decode(value.as_str())))
                            })
                            .collect();
                        params.check(pairs, "/path", &mut errors);
                    }
                }
                None => errors.push("/path", "does not match the path pattern"),
            }
        }
        if let Some(params) = &op.query {
            params.check(query_pairs(req), "/query", &mut errors);
        }
        if let Some(params) = &op.headers {
            params.check(header_pairs(req), "/headers", &mut errors);
        }
        if let Some(params) = &op.cookies {
            params.check(cookie_pairs(req), "/cookies", &mut errors);
        }
        let mut pending = None;
        match &op.body {
            Some(body) if cx.has_body => {
                let content_type = req
                    .headers
                    .get(http::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok());
                match body.find(content_type) {
                    None => {
                        cx.waive_body_hold();
                        if let Some(reply) = self.unsupported(cx) {
                            return Flow::Reply(reply);
                        }
                    }
                    Some(None) => {
                        cx.waive_body_hold();
                    }
                    Some(Some(validator)) => pending = Some(validator.clone()),
                }
            }
            Some(body) => {
                cx.waive_body_hold();
                if body.required {
                    errors.push("/body", "a request body is required");
                }
            }
            None => {
                cx.waive_body_hold();
            }
        }
        if !errors.is_empty() {
            if pending.is_some() {
                cx.waive_body_hold();
            }
            return match self.fail(&errors, cx) {
                Some(reply) => Flow::Reply(reply),
                None => Flow::Next,
            };
        }
        match pending {
            Some(validator) => cx.set_state(Pending { validator }),
            None => self.count("valid"),
        }
        Flow::Next
    }

    async fn request_body(&self, body: &HeldBody, cx: &mut Context) -> BodyVerdict {
        let Some(pending) = cx.take_state::<Pending>() else {
            return BodyVerdict::Continue;
        };
        let bytes = match body.bytes().await {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::error!(middleware = %self.name, error = %e, "reading the held request body failed");
                return BodyVerdict::Reply(Reply::problem(ProblemKind::InternalError));
            }
        };
        let mut errors = Errors::new(self.max_errors);
        match serde_json::from_slice::<Value>(&bytes) {
            Ok(instance) => errors.collect(&pending.validator, &instance, "/body"),
            Err(_) => errors.push("/body", "is not valid JSON"),
        }
        if errors.is_empty() {
            self.count("valid");
            return BodyVerdict::Continue;
        }
        match self.fail(&errors, cx) {
            Some(reply) => BodyVerdict::Reply(reply),
            None => BodyVerdict::Continue,
        }
    }
}

/// `Allow` for a 405.
pub(crate) fn allow_header(methods: &[Method]) -> Option<HeaderValue> {
    let list: Vec<&str> = methods.iter().map(Method::as_str).collect();
    HeaderValue::from_str(&list.join(", ")).ok()
}

#[cfg(test)]
mod tests;
