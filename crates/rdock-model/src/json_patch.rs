//! JSON Pointer (RFC 6901) and JSON Patch (RFC 6902) on `serde_json::Value`, for the
//! `transform` middleware (F-GW-04, ADR-0030).
//!
//! The patch language is total: every operation ends and nothing is evaluated. The work is not
//! linear in the patch: each `copy` can double the document (a copy of the root into itself),
//! so [`apply_within`] caps the size of the patched document and fails the patch past it
//! (L5 of the v0.8 review); each operation then costs at most the cap. Errors name the
//! operation and the pointer, never a value from the document (it may be a secret).

use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// One JSON Patch operation (RFC 6902 §4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum PatchOp {
    /// Adds `value` at `path`: a new member, an array element inserted before the index (`-`
    /// appends), or the whole document for `""`. The parent must exist.
    Add {
        /// A JSON Pointer (RFC 6901).
        path: String,
        /// The value to add.
        value: Value,
    },
    /// Removes the value at `path`, which must exist.
    Remove {
        /// A JSON Pointer (RFC 6901).
        path: String,
    },
    /// Replaces the value at `path`, which must exist.
    Replace {
        /// A JSON Pointer (RFC 6901).
        path: String,
        /// The new value.
        value: Value,
    },
    /// Removes the value at `from` and adds it at `path`. `path` must not be inside `from`.
    Move {
        /// Where the value is taken from.
        from: String,
        /// Where it is put.
        path: String,
    },
    /// Copies the value at `from` to `path`.
    Copy {
        /// Where the value is copied from.
        from: String,
        /// Where the copy is put.
        path: String,
    },
    /// Fails the patch unless the value at `path` equals `value` (numbers by their numeric
    /// value, objects regardless of member order).
    Test {
        /// A JSON Pointer (RFC 6901).
        path: String,
        /// The expected value.
        value: Value,
    },
}

impl PatchOp {
    /// The operation's name (`add`, `remove`, …).
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Add { .. } => "add",
            Self::Remove { .. } => "remove",
            Self::Replace { .. } => "replace",
            Self::Move { .. } => "move",
            Self::Copy { .. } => "copy",
            Self::Test { .. } => "test",
        }
    }

    /// The target pointer.
    #[must_use]
    pub fn path(&self) -> &str {
        match self {
            Self::Add { path, .. }
            | Self::Remove { path }
            | Self::Replace { path, .. }
            | Self::Move { path, .. }
            | Self::Copy { path, .. }
            | Self::Test { path, .. } => path,
        }
    }

    /// The source pointer of `move` and `copy`.
    #[must_use]
    pub fn from(&self) -> Option<&str> {
        match self {
            Self::Move { from, .. } | Self::Copy { from, .. } => Some(from),
            _ => None,
        }
    }

    /// Checks the operation without a document: its pointers parse, and a `move` does not
    /// move a value into itself.
    ///
    /// # Errors
    ///
    /// The first problem found.
    pub fn check(&self) -> Result<(), PatchErrorKind> {
        let path = parse_pointer(self.path())?;
        if let Some(from) = self.from() {
            let from = parse_pointer(from)?;
            if matches!(self, Self::Move { .. })
                && path.len() > from.len()
                && path.starts_with(&from)
            {
                return Err(PatchErrorKind::MoveIntoItself);
            }
        }
        Ok(())
    }
}

/// Why a pointer or an operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchErrorKind {
    /// A pointer is neither empty nor starts with `/`.
    PointerStart,
    /// A `~` not followed by `0` or `1`.
    PointerEscape,
    /// The location (or its parent, for `add`) does not exist.
    NotFound,
    /// An array index that is not a number without leading zeros, or past the end.
    BadIndex,
    /// The parent is neither an object nor an array.
    NotContainer,
    /// A `test` operation found a different value.
    TestFailed,
    /// `move` into its own child.
    MoveIntoItself,
    /// `remove` of the whole document.
    RemoveRoot,
    /// The patched document would be larger than allowed.
    TooLarge,
}

impl PatchErrorKind {
    /// A short explanation without values.
    #[must_use]
    pub fn describe(self) -> &'static str {
        match self {
            Self::PointerStart => "a JSON Pointer must be empty or start with `/`",
            Self::PointerEscape => "`~` in a JSON Pointer must be followed by `0` or `1`",
            Self::NotFound => "the location does not exist",
            Self::BadIndex => {
                "the array index is not a number without leading zeros, or is past the end"
            }
            Self::NotContainer => "the parent is neither an object nor an array",
            Self::TestFailed => "the value is not the expected one",
            Self::MoveIntoItself => "`path` is inside `from`: a value cannot be moved into itself",
            Self::RemoveRoot => "the whole document cannot be removed",
            Self::TooLarge => "the patched document would be larger than `max_body`",
        }
    }
}

impl fmt::Display for PatchErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.describe())
    }
}

/// A failed patch: which operation and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchError {
    /// Index of the operation in the patch.
    pub index: usize,
    /// The operation's name.
    pub op: &'static str,
    /// Why it failed.
    pub kind: PatchErrorKind,
}

impl fmt::Display for PatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "operation {} (`{}`): {}", self.index, self.op, self.kind)
    }
}

impl std::error::Error for PatchError {}

/// Splits a JSON Pointer into its unescaped reference tokens (RFC 6901 §3, §4).
///
/// # Errors
///
/// The pointer is not empty and does not start with `/`, or has a bad `~` escape.
pub fn parse_pointer(pointer: &str) -> Result<Vec<String>, PatchErrorKind> {
    if pointer.is_empty() {
        return Ok(Vec::new());
    }
    let Some(rest) = pointer.strip_prefix('/') else {
        return Err(PatchErrorKind::PointerStart);
    };
    rest.split('/').map(unescape).collect()
}

fn unescape(token: &str) -> Result<String, PatchErrorKind> {
    if !token.contains('~') {
        return Ok(token.to_owned());
    }
    let mut out = String::with_capacity(token.len());
    let mut chars = token.chars();
    while let Some(c) = chars.next() {
        if c == '~' {
            match chars.next() {
                Some('0') => out.push('~'),
                Some('1') => out.push('/'),
                _ => return Err(PatchErrorKind::PointerEscape),
            }
        } else {
            out.push(c);
        }
    }
    Ok(out)
}

/// Escapes one reference token for a pointer (`~` → `~0`, `/` → `~1`).
#[must_use]
pub fn escape_token(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
}

/// An array index token: digits without leading zeros (RFC 6901 §4).
fn index(token: &str) -> Option<usize> {
    let valid = !token.is_empty()
        && token.bytes().all(|b| b.is_ascii_digit())
        && (token == "0" || !token.starts_with('0'));
    if valid { token.parse().ok() } else { None }
}

/// The value at `tokens`.
fn get<'a>(doc: &'a Value, tokens: &[String]) -> Result<&'a Value, PatchErrorKind> {
    let mut current = doc;
    for token in tokens {
        current = match current {
            Value::Object(map) => map.get(token).ok_or(PatchErrorKind::NotFound)?,
            Value::Array(items) => {
                let i = index(token).ok_or(PatchErrorKind::BadIndex)?;
                items.get(i).ok_or(PatchErrorKind::NotFound)?
            }
            _ => return Err(PatchErrorKind::NotFound),
        };
    }
    Ok(current)
}

fn get_mut<'a>(doc: &'a mut Value, tokens: &[String]) -> Result<&'a mut Value, PatchErrorKind> {
    let mut current = doc;
    for token in tokens {
        current = match current {
            Value::Object(map) => map.get_mut(token).ok_or(PatchErrorKind::NotFound)?,
            Value::Array(items) => {
                let i = index(token).ok_or(PatchErrorKind::BadIndex)?;
                items.get_mut(i).ok_or(PatchErrorKind::NotFound)?
            }
            _ => return Err(PatchErrorKind::NotFound),
        };
    }
    Ok(current)
}

/// The value at `pointer` in `doc`.
///
/// # Errors
///
/// The pointer is malformed or names nothing.
pub fn lookup<'a>(doc: &'a Value, pointer: &str) -> Result<&'a Value, PatchErrorKind> {
    get(doc, &parse_pointer(pointer)?)
}

fn add(doc: &mut Value, tokens: &[String], value: Value) -> Result<(), PatchErrorKind> {
    let Some((last, parent)) = tokens.split_last() else {
        *doc = value;
        return Ok(());
    };
    match get_mut(doc, parent)? {
        Value::Object(map) => {
            map.insert(last.clone(), value);
            Ok(())
        }
        Value::Array(items) => {
            if last == "-" {
                items.push(value);
                return Ok(());
            }
            let i = index(last).ok_or(PatchErrorKind::BadIndex)?;
            if i > items.len() {
                return Err(PatchErrorKind::BadIndex);
            }
            items.insert(i, value);
            Ok(())
        }
        _ => Err(PatchErrorKind::NotContainer),
    }
}

fn remove(doc: &mut Value, tokens: &[String]) -> Result<Value, PatchErrorKind> {
    let Some((last, parent)) = tokens.split_last() else {
        return Err(PatchErrorKind::RemoveRoot);
    };
    match get_mut(doc, parent)? {
        Value::Object(map) => map.remove(last).ok_or(PatchErrorKind::NotFound),
        Value::Array(items) => {
            let i = index(last).ok_or(PatchErrorKind::BadIndex)?;
            if i >= items.len() {
                return Err(PatchErrorKind::NotFound);
            }
            Ok(items.remove(i))
        }
        _ => Err(PatchErrorKind::NotFound),
    }
}

/// Equality as RFC 6902 §4.6 defines it for `test`: numbers by numeric value, objects by
/// members regardless of order, arrays element by element.
#[must_use]
pub fn json_equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => {
            if x == y {
                return true;
            }
            match (x.as_i64(), y.as_i64(), x.as_u64(), y.as_u64()) {
                (Some(x), Some(y), _, _) => x == y,
                (_, _, Some(x), Some(y)) => x == y,
                // RFC 6902 §4.6: numbers are equal when their values are; exact on purpose.
                #[allow(clippy::float_cmp)]
                _ => match (x.as_f64(), y.as_f64()) {
                    (Some(x), Some(y)) => x == y,
                    _ => false,
                },
            }
        }
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(x, y)| json_equal(x, y))
        }
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len()
                && x.iter()
                    .all(|(k, v)| y.get(k).is_some_and(|w| json_equal(v, w)))
        }
        _ => a == b,
    }
}

/// The length of `value` as compact JSON, counted without building the text.
fn encoded_len(value: &Value) -> u64 {
    struct Count(u64);
    impl std::io::Write for Count {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0 = self.0.saturating_add(buf.len() as u64);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count(0);
    // Writing a `Value` to a writer that never fails cannot fail.
    let _ = serde_json::to_writer(&mut count, value);
    count.0
}

/// An upper bound of the document's encoded length while it is patched: values added count
/// with their length plus a member name's, values removed or replaced are subtracted.
struct Size {
    now: u64,
    max: u64,
}

impl Size {
    fn grow(&mut self, value: &Value, name: &str) -> Result<(), PatchErrorKind> {
        // `"name":` and a separator.
        let added = encoded_len(value).saturating_add(name.len() as u64 + 4);
        self.now = self.now.saturating_add(added);
        if self.now > self.max {
            return Err(PatchErrorKind::TooLarge);
        }
        Ok(())
    }

    fn shrink(&mut self, value: &Value) {
        self.now = self.now.saturating_sub(encoded_len(value));
    }
}

fn apply_one(doc: &mut Value, op: &PatchOp, size: &mut Size) -> Result<(), PatchErrorKind> {
    let last = |tokens: &[String]| tokens.last().cloned().unwrap_or_default();
    match op {
        PatchOp::Add { path, value } => {
            let tokens = parse_pointer(path)?;
            size.grow(value, &last(&tokens))?;
            add(doc, &tokens, value.clone())
        }
        PatchOp::Remove { path } => {
            let removed = remove(doc, &parse_pointer(path)?)?;
            size.shrink(&removed);
            Ok(())
        }
        PatchOp::Replace { path, value } => {
            let tokens = parse_pointer(path)?;
            let slot = get_mut(doc, &tokens)?;
            size.grow(value, "")?;
            let old = std::mem::replace(slot, value.clone());
            size.shrink(&old);
            Ok(())
        }
        PatchOp::Move { from, path } => {
            let from = parse_pointer(from)?;
            let path = parse_pointer(path)?;
            if from == path {
                // Moving a value onto itself changes nothing, if it exists.
                return get(doc, &from).map(drop);
            }
            if path.len() > from.len() && path.starts_with(&from) {
                return Err(PatchErrorKind::MoveIntoItself);
            }
            let value = remove(doc, &from)?;
            add(doc, &path, value)
        }
        PatchOp::Copy { from, path } => {
            let tokens = parse_pointer(path)?;
            let source = get(doc, &parse_pointer(from)?)?;
            // Counted before the clone, so a doubling copy fails without allocating.
            size.grow(source, &last(&tokens))?;
            let value = source.clone();
            add(doc, &tokens, value)
        }
        PatchOp::Test { path, value } => {
            if json_equal(get(doc, &parse_pointer(path)?)?, value) {
                Ok(())
            } else {
                Err(PatchErrorKind::TestFailed)
            }
        }
    }
}

/// Applies `ops` in order to `doc`, without a size limit; for patches whose operations cannot
/// grow the document past what the caller accepts (tests, trusted documents).
///
/// # Errors
///
/// The first operation that fails. `doc` is then partly patched: callers that need the
/// all-or-nothing rule of RFC 6902 §5 apply to a copy and discard it.
pub fn apply(doc: &mut Value, ops: &[PatchOp]) -> Result<(), PatchError> {
    apply_within(doc, ops, u64::MAX)
}

/// Applies `ops` in order to `doc`, failing with [`PatchErrorKind::TooLarge`] as soon as the
/// document could be longer than `max` bytes of JSON (an upper bound: values added count in
/// full, values removed or replaced are subtracted).
///
/// # Errors
///
/// As [`apply`].
pub fn apply_within(doc: &mut Value, ops: &[PatchOp], max: u64) -> Result<(), PatchError> {
    let mut size = Size {
        now: if max == u64::MAX { 0 } else { encoded_len(doc) },
        max,
    };
    for (index, op) in ops.iter().enumerate() {
        apply_one(doc, op, &mut size).map_err(|kind| PatchError {
            index,
            op: op.name(),
            kind,
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
