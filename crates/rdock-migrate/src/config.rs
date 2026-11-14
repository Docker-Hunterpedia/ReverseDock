//! `rdock migrate config`: rewrites every deprecated element of a configuration file to its
//! replacement, with the rewrite rules of the deprecation registry (ADR-0033). It is also where
//! a conversion between schema versions will live: a conversion is a list of the same rules
//! (`rdock_model::deprecation::SCHEMA_MIGRATIONS`, empty while only v1 exists).
//!
//! The file is edited as text where it can be: a renamed key, a replaced value and a block
//! mapping moved elsewhere change only the lines involved, so comments, blank lines, quoting,
//! key order and anchors elsewhere stay as they are. The edited text is parsed again and must
//! equal the rewritten document; when an edit cannot be made that way (flow style, a move into
//! a mapping written in flow style, JSON input with a move), the whole document is written out
//! again instead, which keeps the content and loses comments and formatting, and the result
//! says so.

use std::fmt::{self, Write as _};

use rdock_config::Format;
use rdock_model::deprecation::{
    self, Applied, Deprecation, Rewrite, SCHEMA_MIGRATIONS, SCHEMA_VERSION, Step, display,
};
use serde::de::{Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use serde_saphyr::Spanned;

/// One use of a deprecated element and what was done about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    /// The registry's element, e.g. `observability.alerts.webhook`.
    pub element: &'static str,
    /// Where it was, e.g. `observability.alerts.webhook`.
    pub path: String,
    /// Where it is now; `None` when it needs a manual change.
    pub to: Option<String>,
    /// Why it needs a manual change, or the registry's note.
    pub detail: String,
    /// The release that deprecated it.
    pub since: &'static str,
    /// The release that removes it.
    pub removal: &'static str,
}

/// The result of `rdock migrate config`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigMigration {
    /// The migrated document; the input unchanged when there was nothing to do.
    pub text: String,
    /// Rewrites that were applied.
    pub done: Vec<Change>,
    /// Uses that need a manual change.
    pub manual: Vec<Change>,
    /// Whether comments and formatting were kept (edited as text), or the document was
    /// written out again.
    pub formatting_kept: bool,
    /// The schema version of the result.
    pub version: u32,
}

impl ConfigMigration {
    /// Whether the text changed.
    #[must_use]
    pub fn changed(&self) -> bool {
        !self.done.is_empty()
    }
}

/// Why a configuration cannot be migrated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// Not YAML or JSON.
    Syntax(String),
    /// Not a mapping at the top.
    NotAMapping,
    /// A `version` this release does not read.
    Version(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax(message) => f.write_str(message),
            Self::NotAMapping => f.write_str("the configuration is not a mapping"),
            Self::Version(found) => write!(
                f,
                "`version: {found}`: this release reads configuration schema version {SCHEMA_VERSION} only"
            ),
        }
    }
}

/// Migrates `text` (JSON when `format` says so) with the deprecation registry in effect.
pub fn config(text: &str, format: Format) -> Result<ConfigMigration, ConfigError> {
    config_with(text, format, &deprecation::entries())
}

/// [`config`] with `entries` as the registry.
pub fn config_with(
    text: &str,
    format: Format,
    entries: &[&'static Deprecation],
) -> Result<ConfigMigration, ConfigError> {
    let mut document = rdock_config::parse_document(text, format)
        .map_err(|e| ConfigError::Syntax(e.to_string()))?;
    if document.is_null() {
        document = Value::Object(Map::new());
    }
    if !document.is_object() {
        return Err(ConfigError::NotAMapping);
    }
    let version = match document.get("version") {
        None => SCHEMA_VERSION,
        Some(v) if v.as_u64() == Some(u64::from(SCHEMA_VERSION)) => SCHEMA_VERSION,
        Some(other) => return Err(ConfigError::Version(other.to_string())),
    };
    let rules = plan(version, SCHEMA_VERSION, entries);
    let mut rewritten = document.clone();
    let applied = deprecation::rewrite_with(&mut rewritten, &rules, |_| true);
    let (done, manual): (Vec<&Applied>, Vec<&Applied>) =
        applied.iter().partition(|a| a.to.is_some());
    let change = |a: &Applied| Change {
        element: a.found.entry.element,
        path: display(&a.found.path),
        to: a.to.as_deref().map(display),
        detail: a
            .skipped
            .clone()
            .unwrap_or_else(|| a.found.entry.note.to_owned()),
        since: a.found.entry.since,
        removal: a.found.entry.removal,
    };
    let mut result = ConfigMigration {
        text: text.to_owned(),
        done: done.iter().map(|a| change(a)).collect(),
        manual: manual.iter().map(|a| change(a)).collect(),
        formatting_kept: true,
        version,
    };
    if done.is_empty() {
        return Ok(result);
    }
    let edited = (format == Format::Yaml || moves_none(&done))
        .then(|| edit(text, &document, &done))
        .flatten()
        .filter(|edited| {
            rdock_config::parse_document(edited, format).is_ok_and(|v| v == rewritten)
        });
    if let Some(edited) = edited {
        result.text = edited;
    } else {
        result.formatting_kept = false;
        result.text = write_out(&rewritten, format)?;
    }
    Ok(result)
}

fn moves_none(done: &[&Applied]) -> bool {
    !done
        .iter()
        .any(|a| matches!(a.found.entry.rewrite, Rewrite::Move { .. }))
}

/// The rules that take a file of schema `from` to `to`: the conversions in between (none
/// exist yet), then the deprecations of the target version.
fn plan(from: u32, to: u32, entries: &[&'static Deprecation]) -> Vec<&'static Deprecation> {
    let mut rules = Vec::new();
    let mut at = from;
    while at < to {
        let Some(step) = SCHEMA_MIGRATIONS.iter().find(|m| m.from == at) else {
            break;
        };
        rules.extend(step.rules.iter());
        at = step.to;
    }
    rules.extend(entries.iter().copied());
    rules
}

fn write_out(document: &Value, format: Format) -> Result<String, ConfigError> {
    match format {
        Format::Json => serde_json::to_string_pretty(document)
            .map(|t| t + "\n")
            .map_err(|e| ConfigError::Syntax(e.to_string())),
        Format::Yaml => {
            serde_saphyr::to_string(document).map_err(|e| ConfigError::Syntax(e.to_string()))
        }
    }
}

// --- The source as a tree with positions -----------------------------------------------------

#[derive(Debug)]
enum Node {
    Map(Vec<(Spanned<String>, Spanned<Node>)>),
    Seq(Vec<Spanned<Node>>),
    Scalar,
}

impl<'de> Deserialize<'de> for Node {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct NodeVisitor;
        impl<'de> Visitor<'de> for NodeVisitor {
            type Value = Node;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a YAML node")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Node, A::Error> {
                let mut entries = Vec::new();
                while let Some(key) = map.next_key::<Spanned<String>>()? {
                    let value = map.next_value::<Spanned<Node>>()?;
                    entries.push((key, value));
                }
                Ok(Node::Map(entries))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Node, A::Error> {
                let mut items = Vec::new();
                while let Some(item) = seq.next_element::<Spanned<Node>>()? {
                    items.push(item);
                }
                Ok(Node::Seq(items))
            }
            fn visit_bool<E>(self, _: bool) -> Result<Node, E> {
                Ok(Node::Scalar)
            }
            fn visit_i64<E>(self, _: i64) -> Result<Node, E> {
                Ok(Node::Scalar)
            }
            fn visit_u64<E>(self, _: u64) -> Result<Node, E> {
                Ok(Node::Scalar)
            }
            fn visit_f64<E>(self, _: f64) -> Result<Node, E> {
                Ok(Node::Scalar)
            }
            fn visit_str<E>(self, _: &str) -> Result<Node, E> {
                Ok(Node::Scalar)
            }
            fn visit_unit<E>(self) -> Result<Node, E> {
                Ok(Node::Scalar)
            }
            fn visit_none<E>(self) -> Result<Node, E> {
                Ok(Node::Scalar)
            }
        }
        deserializer.deserialize_any(NodeVisitor)
    }
}

/// Byte offset and length of a node or key, when known.
fn span<T>(node: &Spanned<T>) -> Option<(usize, usize)> {
    let span = node.referenced.span();
    let offset = usize::try_from(span.byte_offset()?).ok()?;
    let len = usize::try_from(span.byte_len()?).ok()?;
    Some((offset, len))
}

/// The key (for a mapping entry) and the node at `path`.
fn node_at<'a>(
    root: &'a Spanned<Node>,
    path: &[Step],
) -> Option<(Option<&'a Spanned<String>>, &'a Spanned<Node>)> {
    let mut key = None;
    let mut node = root;
    for step in path {
        match (&node.value, step) {
            (Node::Map(entries), Step::Key(k)) => {
                let (found_key, value) = entries.iter().find(|(name, _)| &name.value == k)?;
                key = Some(found_key);
                node = value;
            }
            (Node::Seq(items), Step::Index(i)) => {
                key = None;
                node = items.get(*i)?;
            }
            _ => return None,
        }
    }
    Some((key, node))
}

// --- Text edits -------------------------------------------------------------------------------

/// A replacement of `text[start..end]`.
struct Edit {
    start: usize,
    end: usize,
    with: String,
}

/// The edited text, or `None` when an edit cannot be made as text.
fn edit(text: &str, document: &Value, done: &[&Applied]) -> Option<String> {
    let root: Spanned<Node> = serde_saphyr::from_str(text).ok()?;
    let lines = Lines::new(text);
    let mut edits = Vec::new();
    for applied in done {
        let found = &applied.found;
        let (key, node) = node_at(&root, &found.path)?;
        match found.entry.rewrite {
            Rewrite::Manual => {}
            Rewrite::RenameKey(to) => {
                let (start, len) = span(key?)?;
                let written = text.get(start..start + len)?;
                let quote = written.chars().next().filter(|c| *c == '"' || *c == '\'');
                let with = match quote {
                    Some(q) => format!("{q}{to}{q}"),
                    None => to.to_owned(),
                };
                edits.push(Edit {
                    start,
                    end: start + len,
                    with,
                });
            }
            Rewrite::ReplaceValue(to) => {
                let (start, len) = span(node)?;
                if len == 0 {
                    return None;
                }
                edits.push(Edit {
                    start,
                    end: start + len,
                    with: scalar(&Value::from(to))?,
                });
            }
            Rewrite::Move { drop, extra, .. } => {
                let to = applied.to.as_ref()?;
                let old = found
                    .path
                    .iter()
                    .try_fold(document, |v, step| match step {
                        Step::Key(k) => v.get(k),
                        Step::Index(i) => v.get(*i),
                    })?
                    .as_object()?;
                let extra = extra(old);
                let block = Block {
                    key: key?,
                    node,
                    drop,
                    extra: &extra,
                };
                edits.extend(move_block(text, &lines, &root, &block, to)?);
            }
        }
    }
    edits.sort_by_key(|e| std::cmp::Reverse(e.start));
    let mut out = text.to_owned();
    let mut limit = usize::MAX;
    for e in edits {
        if e.end > limit {
            return None; // overlapping edits
        }
        out.replace_range(e.start..e.end, &e.with);
        limit = e.start;
    }
    Some(out)
}

/// A YAML scalar for a JSON value: plain when that reads back as the same string, else
/// double-quoted (JSON's escaping is valid YAML).
fn scalar(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => {
            let plain = !s.is_empty()
                && s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/'))
                && s.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
                && !matches!(
                    s.as_str(),
                    "true" | "false" | "null" | "yes" | "no" | "on" | "off" | "y" | "n"
                );
            Some(if plain {
                s.clone()
            } else {
                serde_json::to_string(s).ok()?
            })
        }
        Value::Bool(_) | Value::Number(_) | Value::Null => Some(value.to_string()),
        Value::Array(_) | Value::Object(_) => None,
    }
}

/// The lines of the text with their byte ranges (end includes the line break).
struct Lines<'a> {
    text: &'a str,
    starts: Vec<usize>,
}

impl<'a> Lines<'a> {
    fn new(text: &'a str) -> Self {
        let mut starts = vec![0];
        starts.extend(text.match_indices('\n').map(|(i, _)| i + 1));
        if starts.last() == Some(&text.len()) {
            starts.pop();
        }
        Self { text, starts }
    }

    fn count(&self) -> usize {
        self.starts.len()
    }

    /// Line number (0-based) of a byte offset.
    fn of(&self, offset: usize) -> usize {
        match self.starts.binary_search(&offset) {
            Ok(i) => i,
            Err(i) => i.saturating_sub(1),
        }
    }

    fn start(&self, line: usize) -> usize {
        self.starts.get(line).copied().unwrap_or(self.text.len())
    }

    fn end(&self, line: usize) -> usize {
        self.start(line + 1)
    }

    /// The line with its break.
    fn get(&self, line: usize) -> &'a str {
        self.text
            .get(self.start(line)..self.end(line))
            .unwrap_or("")
    }

    fn blank(&self, line: usize) -> bool {
        self.get(line).trim().is_empty()
    }

    fn indent(&self, line: usize) -> usize {
        let l = self.get(line);
        l.len() - l.trim_start_matches(' ').len()
    }

    /// The last line of the block under the mapping key on `key_line` (indent `indent`): the
    /// lines after it that are more indented, blank lines between them included, trailing
    /// blank lines not.
    fn block_end(&self, key_line: usize, indent: usize) -> usize {
        let mut last = key_line;
        for line in key_line + 1..self.count() {
            if self.blank(line) {
                continue;
            }
            if self.indent(line) <= indent {
                break;
            }
            last = line;
        }
        last
    }
}

/// The key on `key` must start its line: a block mapping entry. Returns its line and indent.
fn block_key(text: &str, lines: &Lines<'_>, key: &Spanned<String>) -> Option<(usize, usize)> {
    let (start, _) = span(key)?;
    let line = lines.of(start);
    let before = text.get(lines.start(line)..start)?;
    before
        .chars()
        .all(|c| c == ' ')
        .then_some((line, before.len()))
}

/// Text after `key:` on its line (spaces and a comment), kept on the moved key's line.
fn rest_of_key_line(text: &str, lines: &Lines<'_>, key: &Spanned<String>) -> Option<String> {
    let (start, len) = span(key)?;
    let line = lines.of(start);
    let after = text.get(start + len..lines.end(line))?;
    let after = after.strip_prefix(':')?;
    let trimmed = after.trim_end_matches(['\n', '\r']);
    let content = trimmed.trim();
    (content.is_empty() || content.starts_with('#')).then(|| trimmed.to_owned())
}

/// The mapping under `node` (at `key`) as block lines, the child indent, the dropped keys
/// removed and `extra` entries first. `None` unless it is a block mapping.
fn child_lines(
    lines: &Lines<'_>,
    key_line: usize,
    key_indent: usize,
    node: &Spanned<Node>,
    drop: &[&str],
    extra: &[(String, Value)],
) -> Option<(Vec<String>, usize)> {
    let Node::Map(entries) = &node.value else {
        return None;
    };
    let (value_start, value_len) = span(node)?;
    if value_len != 0 || lines.of(value_start) <= key_line || entries.is_empty() {
        return None; // flow style, or nothing below
    }
    let end = lines.block_end(key_line, key_indent);
    let first = (key_line + 1..=end)
        .find(|l| !lines.blank(*l) && !lines.get(*l).trim_start().starts_with('#'))?;
    let child_indent = lines.indent(first);
    let mut out: Vec<String> = extra
        .iter()
        .map(|(k, v)| scalar(v).map(|v| format!("{}{k}: {v}\n", " ".repeat(child_indent))))
        .collect::<Option<_>>()?;
    let mut skipping = false;
    for line in key_line + 1..=end {
        let text = lines.get(line);
        let indent = lines.indent(line);
        if !lines.blank(line) && indent <= child_indent {
            let content = text.trim_start();
            skipping = drop.iter().any(|d| {
                content.starts_with(&format!("{d}:"))
                    || content.starts_with(&format!("\"{d}\":"))
                    || content.starts_with(&format!("'{d}':"))
            });
            if !skipping
                && extra
                    .iter()
                    .any(|(k, _)| content.starts_with(&format!("{k}:")))
            {
                return None; // the entry is written already: leave it to the fallback
            }
        }
        if skipping {
            continue;
        }
        let mut owned = text.to_owned();
        if !owned.ends_with('\n') {
            owned.push('\n');
        }
        out.push(owned);
    }
    Some((out, child_indent))
}

/// Re-indents block lines by `delta` spaces (blank lines unchanged).
fn shift(lines: &[String], delta: isize) -> Option<Vec<String>> {
    lines
        .iter()
        .map(|line| {
            if line.trim().is_empty() {
                return Some(line.clone());
            }
            if delta >= 0 {
                Some(format!("{}{line}", " ".repeat(delta.unsigned_abs())))
            } else {
                let cut = delta.unsigned_abs();
                line.starts_with(&" ".repeat(cut))
                    .then(|| line[cut..].to_owned())
            }
        })
        .collect()
}

/// The mapping a [`Rewrite::Move`] moves, as written.
struct Block<'a> {
    key: &'a Spanned<String>,
    node: &'a Spanned<Node>,
    drop: &'a [&'a str],
    extra: &'a [(String, Value)],
}

/// The edits of a [`Rewrite::Move`] of `block` to `to`.
fn move_block(
    text: &str,
    lines: &Lines<'_>,
    root: &Spanned<Node>,
    block: &Block<'_>,
    to: &[Step],
) -> Option<Vec<Edit>> {
    let key = block.key;
    let (key_line, key_indent) = block_key(text, lines, key)?;
    let (name, target) = to.split_last()?;
    let Step::Key(name) = name else {
        return None;
    };
    let (children, child_indent) = child_lines(
        lines,
        key_line,
        key_indent,
        block.node,
        block.drop,
        block.extra,
    )?;
    let step = child_indent.checked_sub(key_indent).filter(|s| *s > 0)?;
    let rest = rest_of_key_line(text, lines, key)?;
    let old_start = lines.start(key_line);
    let old_end = lines.end(lines.block_end(key_line, key_indent));
    let mut edits = Vec::new();
    match node_at(root, target) {
        Some((Some(target_key), target_node)) => {
            // Into an existing block mapping: after its last line.
            let (target_line, target_indent) = block_key(text, lines, target_key)?;
            let Node::Map(entries) = &target_node.value else {
                return None;
            };
            let (value_start, value_len) = span(target_node)?;
            if value_len != 0 || entries.is_empty() || lines.of(value_start) <= target_line {
                return None;
            }
            let target_end = lines.block_end(target_line, target_indent);
            let name_indent = (target_line + 1..=target_end)
                .find(|l| !lines.blank(*l) && !lines.get(*l).trim_start().starts_with('#'))
                .map(|l| lines.indent(l))?;
            let delta =
                isize::try_from(name_indent + step).ok()? - isize::try_from(child_indent).ok()?;
            let mut moved = format!("{}{name}:{rest}\n", " ".repeat(name_indent));
            moved.push_str(&shift(&children, delta)?.concat());
            let at = lines.end(target_end);
            let mut prefix = String::new();
            if at == text.len() && !text.ends_with('\n') {
                prefix.push('\n');
            }
            edits.push(Edit {
                start: at,
                end: at,
                with: format!("{prefix}{moved}"),
            });
            edits.push(Edit {
                start: old_start,
                end: old_end,
                with: String::new(),
            });
        }
        Some((None, _)) => return None,
        None => {
            // A new parent next to the old key: only when it is a sibling of it.
            let (parent_name, grand) = target.split_last()?;
            let Step::Key(parent_name) = parent_name else {
                return None;
            };
            let old_path_parent = node_parent(root, key)?;
            if old_path_parent != grand {
                return None;
            }
            let delta = isize::try_from(step).ok()?;
            let mut moved = format!("{}{parent_name}:\n", " ".repeat(key_indent));
            let _ = writeln!(moved, "{}{name}:{rest}", " ".repeat(key_indent + step));
            moved.push_str(&shift(&children, delta)?.concat());
            edits.push(Edit {
                start: old_start,
                end: old_end,
                with: moved,
            });
        }
    }
    Some(edits)
}

/// The path of the mapping that holds `key`.
fn node_parent(root: &Spanned<Node>, key: &Spanned<String>) -> Option<Vec<Step>> {
    fn walk(node: &Spanned<Node>, key: &Spanned<String>, path: &mut Vec<Step>) -> bool {
        match &node.value {
            Node::Map(entries) => {
                for (k, v) in entries {
                    if std::ptr::eq(k, key) {
                        return true;
                    }
                    path.push(Step::Key(k.value.clone()));
                    if walk(v, key, path) {
                        return true;
                    }
                    path.pop();
                }
                false
            }
            Node::Seq(items) => {
                for (i, item) in items.iter().enumerate() {
                    path.push(Step::Index(i));
                    if walk(item, key, path) {
                        return true;
                    }
                    path.pop();
                }
                false
            }
            Node::Scalar => false,
        }
    }
    let mut path = Vec::new();
    walk(root, key, &mut path).then_some(path)
}

/// A unified diff of the input and the result.
#[must_use]
pub fn diff(before: &str, after: &str, name: &str) -> String {
    similar::TextDiff::from_lines(before, after)
        .unified_diff()
        .context_radius(3)
        .header(name, &format!("{name} (migrated)"))
        .to_string()
}

#[cfg(test)]
mod tests;
