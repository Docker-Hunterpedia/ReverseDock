//! Deprecations (ADR-0033): one registry of every element on its way out, with the release that
//! deprecated it, the release that removes it, its replacement and, where it can be automated,
//! the rewrite that moves a configuration to the replacement.
//!
//! Everything that reports a deprecation reads this registry: `rdock validate` (a warning with
//! code `deprecated`, `since`, `removal` and `replacement`), the log line and the
//! `rdock_deprecated_config_in_use` metric at load, the admin API's status, the dashboard,
//! `"deprecated": true` in the JSON Schema and the OpenAPI document, the `Deprecation` and
//! `Sunset` headers of a deprecated API operation, a warning for a deprecated CLI flag, the
//! website's "Deprecations" page and `rdock migrate config`, which applies the rewrites.
//!
//! A schema migration (v1 → v2, once a v2 exists) is a list of the same rewrite rules
//! ([`SCHEMA_MIGRATIONS`]); there is none yet.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};

use serde::{Serialize, Serializer};
use serde_json::{Map, Value};

use crate::diagnostics::{Diagnostic, path_index, path_key};

/// The configuration schema version this release reads and writes.
pub const SCHEMA_VERSION: u32 = 1;

/// What kind of element is deprecated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// A key of the configuration file, as a schema path (`observability.alerts.webhook`).
    /// Labels map to the same paths (`rdock.routes.<name>.<field>`), so a deprecated route,
    /// service or middleware field is deprecated in labels too.
    ConfigKey,
    /// One value of a key: `path=value`.
    ConfigValue,
    /// A Docker label key with no configuration path of its own (a shorthand label).
    Label,
    /// A CLI flag: `<command words> --flag`, e.g. `migrate traefik --output`.
    CliFlag,
    /// A CLI command: its words, e.g. `config diff`.
    CliCommand,
    /// An admin API operation: `METHOD /api/v1/path/{param}`.
    ApiOperation,
    /// A field of an admin API document: `METHOD /api/v1/path field`.
    ApiField,
    /// A metric name.
    Metric,
}

impl Kind {
    /// A word for messages: `setting`, `value`, `label`, `flag`, …
    #[must_use]
    pub const fn noun(self) -> &'static str {
        match self {
            Self::ConfigKey => "setting",
            Self::ConfigValue => "value",
            Self::Label => "label",
            Self::CliFlag => "flag",
            Self::CliCommand => "command",
            Self::ApiOperation => "API operation",
            Self::ApiField => "API field",
            Self::Metric => "metric",
        }
    }
}

/// Builds extra entries for a moved mapping from the mapping as written.
pub type Extra = fn(&Map<String, Value>) -> Vec<(String, Value)>;

/// How a configuration is moved to the replacement.
#[derive(Debug, Clone, Copy)]
pub enum Rewrite {
    /// No automatic rewrite: the replacement needs a decision (`rdock migrate config` reports
    /// it and leaves it alone).
    Manual,
    /// The key gets a new name in the same mapping.
    RenameKey(&'static str),
    /// A string value is replaced (`ConfigValue` elements).
    ReplaceValue(&'static str),
    /// The mapping moves under another mapping (created when missing) as `key`; when `key` is
    /// taken there, `key-2`, `key-3`, …; a `*` in `parent` stands for the key the same `*`
    /// matched in the element's path.
    Move {
        /// Path of the new parent mapping.
        parent: &'static str,
        /// Key of the moved mapping in it.
        key: &'static str,
        /// Keys of the old mapping that are not carried over (they had no effect).
        drop: &'static [&'static str],
        /// Entries added at the top of the moved mapping.
        extra: Extra,
    },
}

impl Rewrite {
    /// Whether `rdock migrate config` can apply it.
    #[must_use]
    pub const fn is_automatic(&self) -> bool {
        !matches!(self, Self::Manual)
    }
}

/// One deprecated element.
#[derive(Debug, Clone, Copy)]
pub struct Deprecation {
    /// What kind of element.
    pub kind: Kind,
    /// The element: a schema path (`a.*.b`), `path=value`, a label key, `command --flag`,
    /// `METHOD /path` or a metric name. Also its id in the metric and in `code`'s companion
    /// fields.
    pub element: &'static str,
    /// The release that deprecated it, e.g. `1.0`.
    pub since: &'static str,
    /// The release that removes it, e.g. `2.0`: never before the next major.
    pub removal: &'static str,
    /// The date the deprecating release came out (`YYYY-MM-DD`), for the HTTP `Deprecation`
    /// header of an API operation (RFC 9745). `None` until that release is dated.
    pub deprecated_on: Option<&'static str>,
    /// The date after which an API operation may stop answering (`YYYY-MM-DD`), for the HTTP
    /// `Sunset` header (RFC 8594). `None` when no date is promised.
    pub sunset: Option<&'static str>,
    /// What to use instead, in one line.
    pub replacement: &'static str,
    /// Why, and anything a migration should know.
    pub note: &'static str,
    /// How `rdock migrate config` moves to the replacement.
    pub rewrite: Rewrite,
    /// Whether the configuration model still reads the element itself. When `false`, the
    /// loader applies [`Deprecation::rewrite`] before reading, so the old form keeps working
    /// after the model dropped it (the overlap of a rename).
    pub read_by_model: bool,
}

impl Serialize for Deprecation {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct View<'a> {
            kind: Kind,
            element: &'a str,
            since: &'a str,
            removal: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            deprecated_on: Option<&'a str>,
            #[serde(skip_serializing_if = "Option::is_none")]
            sunset: Option<&'a str>,
            replacement: &'a str,
            note: &'a str,
            automatic: bool,
        }
        View {
            kind: self.kind,
            element: self.element,
            since: self.since,
            removal: self.removal,
            deprecated_on: self.deprecated_on,
            sunset: self.sunset,
            replacement: self.replacement,
            note: self.note,
            automatic: self.rewrite.is_automatic(),
        }
        .serialize(serializer)
    }
}

impl fmt::Display for Deprecation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "`{}` is deprecated since {} and will be removed in {}: {}",
            self.element, self.since, self.removal, self.replacement
        )
    }
}

/// `observability.alerts.webhook` → a `webhook` channel: keep receiving on loopback, which the
/// v0.3 webhook allowed by itself.
fn webhook_channel_extra(old: &Map<String, Value>) -> Vec<(String, Value)> {
    let mut extra = vec![("type".to_owned(), Value::from("webhook"))];
    let loopback = old
        .get("url")
        .and_then(Value::as_str)
        .and_then(|u| url::Url::parse(u).ok())
        .is_some_and(|u| match u.host() {
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            Some(url::Host::Domain(d)) => d == "localhost",
            None => false,
        });
    if loopback {
        extra.push(("allow_private_targets".to_owned(), Value::Bool(true)));
    }
    extra
}

/// Every deprecated element of this release.
pub static REGISTRY: &[Deprecation] = &[Deprecation {
    kind: Kind::ConfigKey,
    element: "observability.alerts.webhook",
    since: "1.0",
    removal: "2.0",
    deprecated_on: None,
    sunset: None,
    replacement: "a channel under `observability.alerts.channels` with `type: webhook`",
    note: "The single v0.3 webhook has worked as a channel named `webhook` since v0.5. Its `timeout` has had no effect since then (channels wait 5 s), so it is dropped. A channel treats its `url` as a secret: write it as a `${file:…}` or `${env:…}` reference to avoid the warning.",
    rewrite: Rewrite::Move {
        parent: "observability.alerts.channels",
        key: "webhook",
        drop: &["timeout"],
        extra: webhook_channel_extra,
    },
    read_by_model: true,
}];

/// Entries that exist only to exercise the plumbing end to end in tests: a renamed key the
/// model does not read (`routes.<name>.rule`, Traefik's word for `match`), a CLI flag and an
/// API operation. Turned on by [`enable_test_entries`], which only debug builds of `rdock` call
/// (environment `RDOCK_TEST_DEPRECATIONS=1`); never part of a release.
pub static TEST_ENTRIES: &[Deprecation] = &[
    Deprecation {
        kind: Kind::ConfigKey,
        element: "routes.*.rule",
        since: "1.0",
        removal: "2.0",
        deprecated_on: None,
        sunset: None,
        replacement: "`routes.<name>.match`",
        note: "Test entry (RDOCK_TEST_DEPRECATIONS); not a real deprecation.",
        rewrite: Rewrite::RenameKey("match"),
        read_by_model: false,
    },
    Deprecation {
        kind: Kind::CliFlag,
        element: "version --json",
        since: "1.0",
        removal: "2.0",
        deprecated_on: None,
        sunset: None,
        replacement: "`rdock version --json` (test entry)",
        note: "Test entry (RDOCK_TEST_DEPRECATIONS); not a real deprecation.",
        rewrite: Rewrite::Manual,
        read_by_model: true,
    },
    Deprecation {
        kind: Kind::ApiOperation,
        element: "GET /api/v1/listeners",
        since: "1.0",
        removal: "2.0",
        deprecated_on: Some("2026-11-14"),
        sunset: Some("2027-11-14"),
        replacement: "`GET /api/v1/status` (`listeners`) (test entry)",
        note: "Test entry (RDOCK_TEST_DEPRECATIONS); not a real deprecation.",
        rewrite: Rewrite::Manual,
        read_by_model: true,
    },
];

/// A conversion between configuration schema versions: the rewrite rules that turn a file of
/// `from` into one of `to`. Empty until a v2 exists (ADR-0033: v1 is additive through 1.x).
#[derive(Debug, Clone, Copy)]
pub struct SchemaMigration {
    /// The version read.
    pub from: u32,
    /// The version written.
    pub to: u32,
    /// The rules, applied in order.
    pub rules: &'static [Deprecation],
}

/// Every schema conversion this release knows.
pub static SCHEMA_MIGRATIONS: &[SchemaMigration] = &[];

static TEST_ENABLED: AtomicBool = AtomicBool::new(false);

/// Adds [`TEST_ENTRIES`] to [`entries`] for the rest of the process. Test hook: only debug
/// builds of `rdock` call it.
#[doc(hidden)]
pub fn enable_test_entries() {
    TEST_ENABLED.store(true, Ordering::SeqCst);
}

/// The registry in effect: [`REGISTRY`], plus [`TEST_ENTRIES`] when a test turned them on.
#[must_use]
pub fn entries() -> Vec<&'static Deprecation> {
    let mut all: Vec<&'static Deprecation> = REGISTRY.iter().collect();
    if TEST_ENABLED.load(Ordering::SeqCst) {
        all.extend(TEST_ENTRIES.iter());
    }
    all
}

// --- Paths ------------------------------------------------------------------------------------

/// One step of a concrete path into a document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// A mapping key.
    Key(String),
    /// A list index.
    Index(usize),
}

/// A concrete path as diagnostics print it: `routes.app.rule`, `backends[0]`.
#[must_use]
pub fn display(steps: &[Step]) -> String {
    steps.iter().fold(String::new(), |out, step| match step {
        Step::Key(k) => path_key(&out, k),
        Step::Index(i) => path_index(&out, *i),
    })
}

/// A `ConfigKey` or `ConfigValue` element split into its path pattern and value.
fn pattern(entry: &Deprecation) -> Option<(Vec<&'static str>, Option<&'static str>)> {
    match entry.kind {
        Kind::ConfigKey => Some((entry.element.split('.').collect(), None)),
        Kind::ConfigValue => {
            let (path, value) = entry.element.rsplit_once('=')?;
            Some((path.split('.').collect(), Some(value)))
        }
        _ => None,
    }
}

/// Every concrete path in `doc` that matches `segments`, with what each `*` matched.
fn matches(doc: &Value, segments: &[&str]) -> Vec<(Vec<Step>, Vec<String>)> {
    fn walk(
        node: &Value,
        segments: &[&str],
        steps: &mut Vec<Step>,
        captures: &mut Vec<String>,
        out: &mut Vec<(Vec<Step>, Vec<String>)>,
    ) {
        let Some((first, rest)) = segments.split_first() else {
            out.push((steps.clone(), captures.clone()));
            return;
        };
        match (node, *first) {
            (Value::Object(map), "*") => {
                for (key, child) in map {
                    if key.starts_with("x-") {
                        continue;
                    }
                    steps.push(Step::Key(key.clone()));
                    captures.push(key.clone());
                    walk(child, rest, steps, captures, out);
                    captures.pop();
                    steps.pop();
                }
            }
            (Value::Array(items), "*") => {
                for (i, child) in items.iter().enumerate() {
                    steps.push(Step::Index(i));
                    captures.push(i.to_string());
                    walk(child, rest, steps, captures, out);
                    captures.pop();
                    steps.pop();
                }
            }
            (Value::Object(map), key) => {
                if let Some(child) = map.get(key) {
                    steps.push(Step::Key(key.to_owned()));
                    walk(child, rest, steps, captures, out);
                    steps.pop();
                }
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(doc, segments, &mut Vec::new(), &mut Vec::new(), &mut out);
    out
}

/// One use of a deprecated element in a configuration document.
#[derive(Debug, Clone)]
pub struct Found {
    /// The registry entry.
    pub entry: &'static Deprecation,
    /// Where, as written.
    pub path: Vec<Step>,
    /// What each `*` of the element matched.
    pub captures: Vec<String>,
}

impl Found {
    /// The warning `rdock validate` prints for it.
    #[must_use]
    pub fn diagnostic(&self) -> Diagnostic {
        diagnostic(self.entry, display(&self.path))
    }
}

/// The deprecation warning for `entry` at `path`.
#[must_use]
pub fn diagnostic(entry: &Deprecation, path: String) -> Diagnostic {
    let mut hint = entry.note.to_owned();
    if entry.rewrite.is_automatic() && matches!(entry.kind, Kind::ConfigKey | Kind::ConfigValue) {
        hint.push_str("\n`rdock migrate config` rewrites it.");
    }
    let mut d = Diagnostic::warning(
        path,
        format!(
            "deprecated {} (since {}, removed in {}): use {}",
            entry.kind.noun(),
            entry.since,
            entry.removal,
            entry.replacement
        ),
    )
    .with_hint(hint)
    .with_code("deprecated");
    d.element = Some(entry.element.to_owned());
    d.since = Some(entry.since.to_owned());
    d.removal = Some(entry.removal.to_owned());
    d.replacement = Some(entry.replacement.to_owned());
    d
}

/// Every use of a deprecated configuration element in `doc`, by `entries`.
#[must_use]
pub fn scan_with(doc: &Value, entries: &[&'static Deprecation]) -> Vec<Found> {
    let mut found = Vec::new();
    for entry in entries {
        let Some((segments, value)) = pattern(entry) else {
            continue;
        };
        for (path, captures) in matches(doc, &segments) {
            if let Some(wanted) = value {
                let actual = value_at(doc, &path);
                if actual.and_then(Value::as_str) != Some(wanted) {
                    continue;
                }
            }
            found.push(Found {
                entry,
                path,
                captures,
            });
        }
    }
    found
}

/// [`scan_with`] the registry in effect.
#[must_use]
pub fn scan(doc: &Value) -> Vec<Found> {
    scan_with(doc, &entries())
}

fn value_at<'a>(doc: &'a Value, path: &[Step]) -> Option<&'a Value> {
    path.iter().try_fold(doc, |node, step| match step {
        Step::Key(k) => node.get(k),
        Step::Index(i) => node.get(*i),
    })
}

fn value_at_mut<'a>(doc: &'a mut Value, path: &[Step]) -> Option<&'a mut Value> {
    path.iter().try_fold(doc, |node, step| match step {
        Step::Key(k) => node.get_mut(k),
        Step::Index(i) => node.get_mut(*i),
    })
}

/// A rewrite that was applied, or why it was not.
#[derive(Debug, Clone)]
pub struct Applied {
    /// The use it is about.
    pub found: Found,
    /// The path after the rewrite; `None` when it was not applied.
    pub to: Option<Vec<Step>>,
    /// Why it was not applied (a manual change, or the target is taken).
    pub skipped: Option<String>,
}

/// Rewrites every use of a deprecated element in `doc` to its replacement, by `entries`,
/// skipping the entries `only` rejects. Returns what was done, in document order of the
/// entries. Uses whose rewrite is [`Rewrite::Manual`] are reported, not changed.
pub fn rewrite_with(
    doc: &mut Value,
    entries: &[&'static Deprecation],
    only: impl Fn(&Deprecation) -> bool,
) -> Vec<Applied> {
    let mut done = Vec::new();
    for entry in entries.iter().copied().filter(|e| only(e)) {
        // One entry at a time, so a rewrite never sees paths an earlier one moved.
        for found in scan_with(doc, &[entry]) {
            let result = apply(doc, &found);
            done.push(match result {
                Ok(to) => Applied {
                    found,
                    to: Some(to),
                    skipped: None,
                },
                Err(why) => Applied {
                    found,
                    to: None,
                    skipped: Some(why),
                },
            });
        }
    }
    done
}

/// Applies the load-time rewrites: entries the model no longer reads (renames during their
/// overlap). The caller reports every use with [`scan`] first.
pub fn rewrite_for_loading(doc: &mut Value) -> Vec<Applied> {
    rewrite_with(doc, &entries(), |e| !e.read_by_model)
}

fn apply(doc: &mut Value, found: &Found) -> Result<Vec<Step>, String> {
    let (last, parent_path) = found
        .path
        .split_last()
        .ok_or_else(|| "the element is the whole document".to_owned())?;
    match found.entry.rewrite {
        Rewrite::Manual => Err(format!(
            "needs a manual change: use {}",
            found.entry.replacement
        )),
        Rewrite::RenameKey(to) => {
            let Step::Key(from) = last else {
                return Err("not a key".to_owned());
            };
            let parent = value_at_mut(doc, parent_path)
                .and_then(Value::as_object_mut)
                .ok_or_else(|| "the parent is not a mapping".to_owned())?;
            if parent.contains_key(to) {
                return Err(format!("`{to}` is set too; remove one of them by hand"));
            }
            let value = parent
                .remove(from)
                .ok_or_else(|| "the key is gone".to_owned())?;
            parent.insert(to.to_owned(), value);
            let mut to_path = parent_path.to_vec();
            to_path.push(Step::Key(to.to_owned()));
            Ok(to_path)
        }
        Rewrite::ReplaceValue(to) => {
            let value =
                value_at_mut(doc, &found.path).ok_or_else(|| "the value is gone".to_owned())?;
            *value = Value::from(to);
            Ok(found.path.clone())
        }
        Rewrite::Move {
            parent,
            key,
            drop,
            extra,
        } => {
            let old = value_at(doc, &found.path)
                .and_then(Value::as_object)
                .cloned()
                .ok_or_else(|| "not a mapping".to_owned())?;
            let moved = moved_mapping(&old, drop, extra);
            let target = substitute(parent, &found.captures)?;
            let name = {
                let existing = value_at(doc, &target).and_then(Value::as_object);
                free_key(key, |k| existing.is_some_and(|m| m.contains_key(k)))
            };
            if let Some(Value::Object(old_parent)) = value_at_mut(doc, parent_path)
                && let Step::Key(old_key) = last
            {
                old_parent.remove(old_key);
            }
            let slot = ensure_mapping(doc, &target)?;
            slot.insert(name.clone(), Value::Object(moved));
            let mut to = target;
            to.push(Step::Key(name));
            Ok(to)
        }
    }
}

/// The mapping a [`Rewrite::Move`] writes: `extra` first, then the old entries but `drop`.
#[must_use]
pub fn moved_mapping(old: &Map<String, Value>, drop: &[&str], extra: Extra) -> Map<String, Value> {
    let mut moved = Map::new();
    for (k, v) in extra(old) {
        moved.insert(k, v);
    }
    for (k, v) in old {
        if !drop.contains(&k.as_str()) && !moved.contains_key(k) {
            moved.insert(k.clone(), v.clone());
        }
    }
    moved
}

/// `key`, or `key-2`, `key-3`, … — the first that `taken` does not claim.
#[must_use]
pub fn free_key(key: &str, taken: impl Fn(&str) -> bool) -> String {
    if !taken(key) {
        return key.to_owned();
    }
    // A mapping has finitely many keys, so a free one exists well before the bound.
    (2..=u32::MAX)
        .map(|n| format!("{key}-{n}"))
        .find(|k| !taken(k))
        .unwrap_or_else(|| key.to_owned())
}

/// `parent` with each `*` replaced by the next capture.
pub(crate) fn substitute(parent: &str, captures: &[String]) -> Result<Vec<Step>, String> {
    let mut captures = captures.iter();
    parent
        .split('.')
        .map(|segment| {
            if segment == "*" {
                captures
                    .next()
                    .map(|c| Step::Key(c.clone()))
                    .ok_or_else(|| format!("`{parent}` has more `*` than the element"))
            } else {
                Ok(Step::Key(segment.to_owned()))
            }
        })
        .collect()
}

/// The mapping at `path`, creating empty mappings on the way.
fn ensure_mapping<'a>(
    doc: &'a mut Value,
    path: &[Step],
) -> Result<&'a mut Map<String, Value>, String> {
    let mut node = doc;
    for step in path {
        let Step::Key(key) = step else {
            return Err("a list on the way to the new place".to_owned());
        };
        let map = node.as_object_mut().ok_or_else(|| {
            "a value that is not a mapping on the way to the new place".to_owned()
        })?;
        node = map
            .entry(key.clone())
            .or_insert_with(|| Value::Object(Map::new()));
        if node.is_null() {
            *node = Value::Object(Map::new());
        }
    }
    node.as_object_mut()
        .ok_or_else(|| "the new place is not a mapping".to_owned())
}

// --- Labels -----------------------------------------------------------------------------------

/// A Docker label rewritten to its replacement, with the entry that asked for it: a full-form
/// `rdock.<section>.<name>.<field>` label whose configuration path is a renamed key, or a
/// `Label` entry renamed outright.
#[must_use]
pub fn rewrite_label_with(
    key: &str,
    entries: &[&'static Deprecation],
) -> Option<(String, &'static Deprecation)> {
    for entry in entries {
        match (entry.kind, entry.rewrite) {
            (Kind::Label, Rewrite::RenameKey(to)) if entry.element == key => {
                return Some((to.to_owned(), entry));
            }
            (Kind::ConfigKey, Rewrite::RenameKey(to)) => {
                let path = key.strip_prefix("rdock.")?;
                let segments: Vec<&str> = entry.element.split('.').collect();
                let parts: Vec<&str> = path.splitn(segments.len(), '.').collect();
                if parts.len() == segments.len()
                    && segments
                        .iter()
                        .zip(&parts)
                        .all(|(s, p)| *s == "*" || s == p)
                {
                    let mut new = parts.clone();
                    if let Some(last) = new.last_mut() {
                        *last = to;
                    }
                    return Some((format!("rdock.{}", new.join(".")), entry));
                }
            }
            _ => {}
        }
    }
    None
}

/// [`rewrite_label_with`] the registry in effect.
#[must_use]
pub fn rewrite_label(key: &str) -> Option<(String, &'static Deprecation)> {
    rewrite_label_with(key, &entries())
}

/// A `Label` entry that is deprecated without a rename (detection only).
#[must_use]
pub fn label(key: &str) -> Option<&'static Deprecation> {
    entries()
        .into_iter()
        .find(|e| e.kind == Kind::Label && e.element == key)
}

// --- CLI and API ------------------------------------------------------------------------------

/// The entry for a CLI flag (`words` are the command's words, `flag` with its dashes).
#[must_use]
pub fn cli_flag(words: &[&str], flag: &str) -> Option<&'static Deprecation> {
    let element = format!("{} {flag}", words.join(" "));
    entries()
        .into_iter()
        .find(|e| e.kind == Kind::CliFlag && e.element == element)
}

/// The entry for a CLI command (its words).
#[must_use]
pub fn cli_command(words: &[&str]) -> Option<&'static Deprecation> {
    let element = words.join(" ");
    entries()
        .into_iter()
        .find(|e| e.kind == Kind::CliCommand && e.element == element)
}

/// The entry for an admin API request: `method` and the request path, matched against the
/// templates of the registry (`{param}` matches one segment).
#[must_use]
pub fn api_operation(method: &str, path: &str) -> Option<&'static Deprecation> {
    entries().into_iter().find(|e| {
        e.kind == Kind::ApiOperation
            && e.element.split_once(' ').is_some_and(|(m, template)| {
                m.eq_ignore_ascii_case(method) && template_matches(template, path)
            })
    })
}

/// Whether a request path matches an OpenAPI path template.
#[must_use]
pub fn template_matches(template: &str, path: &str) -> bool {
    let mut t = template.trim_end_matches('/').split('/');
    let mut p = path.trim_end_matches('/').split('/');
    loop {
        match (t.next(), p.next()) {
            (None, None) => return true,
            (Some(t), Some(p)) if t.starts_with('{') && t.ends_with('}') && !p.is_empty() => {}
            (Some(t), Some(p)) if t == p => {}
            _ => return false,
        }
    }
}

#[cfg(test)]
mod tests;
