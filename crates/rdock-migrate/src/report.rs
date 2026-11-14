//! One migration report for every source (ADR-0033): each source item (a label, a file key, a
//! flag, an environment variable, a directive) is accounted for exactly once, at one of four
//! levels, with a stable code, where it came from, what it became, a message and a hint.
//!
//! The JSON form is described by `schema/migrate-report.v1.json` ([`json_schema`]), beta in
//! the maturity registry (`migrate-report`). The finding codes are [`CODES`]; the website's
//! reference page is generated from the schema's `x-rdock-codes`.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use schemars::JsonSchema;
use serde::Serialize;

/// The published schema's identifier.
pub const SCHEMA_ID: &str = "https://raw.githubusercontent.com/Docker-Hunterpedia/ReverseDock/main/schema/migrate-report.v1.json";

/// How faithfully a source item was carried over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    /// The same behaviour; the object is written.
    Exact,
    /// Written, with a stated difference.
    Approximate,
    /// Needs a decision: left out (or written disabled), and the report says what to do.
    Manual,
    /// No equivalent: left out, and the report says why.
    Dropped,
}

impl Level {
    /// `exact`, `approximate`, `manual` or `dropped`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Approximate => "approximate",
            Self::Manual => "manual",
            Self::Dropped => "dropped",
        }
    }

    /// Whether `--strict` fails on it.
    #[must_use]
    pub const fn needs_review(self) -> bool {
        matches!(self, Self::Manual | Self::Dropped)
    }
}

/// One kind of finding.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Code {
    /// Stable identifier, e.g. `traefik.label.unsupported`.
    pub id: &'static str,
    /// The level findings of this kind have.
    pub level: Level,
    /// What it means.
    pub summary: &'static str,
    /// What to do about it in general (each finding adds its own hint).
    pub help: &'static str,
}

const fn code(id: &'static str, level: Level, summary: &'static str, help: &'static str) -> Code {
    Code {
        id,
        level,
        summary,
        help,
    }
}

/// Every finding code. Codes are stable: one is never reused for another meaning.
pub static CODES: &[Code] = &[
    // --- Compose -------------------------------------------------------------------------
    code(
        "compose.deploy_labels",
        Level::Approximate,
        "`deploy.labels` (Swarm) were read as container labels.",
        "To keep them on the stack, run ReverseDock with `providers.swarm` instead of migrating them.",
    ),
    code(
        "compose.interpolation.invalid",
        Level::Manual,
        "A `${…}` reference that Compose cannot read.",
        "Fix the reference; `$$` writes a literal `$`.",
    ),
    code(
        "compose.interpolation.required",
        Level::Manual,
        "A `${NAME?message}` reference whose variable is not set: Compose would refuse the file.",
        "Pass the variable with `--env-file` (or `--process-env`).",
    ),
    code(
        "compose.interpolation.unset",
        Level::Manual,
        "A `${NAME}` reference whose variable is not set: Compose would use an empty string.",
        "Pass the variables with `--env-file FILE` (Compose's `.env`), or `--process-env` to read this process's environment.",
    ),
    code(
        "compose.service",
        Level::Exact,
        "A Compose service with Traefik or ReverseDock labels, reachable by its service name.",
        "None.",
    ),
    code(
        "compose.service.not_exposed",
        Level::Manual,
        "A service with Traefik router labels and no `traefik.enable`: Traefik routes it (its `exposedByDefault` is `true`), ReverseDock does not.",
        "Add `traefik.enable=true`, rerun with `--expose-by-default`, or migrate the static configuration (`--static`), which writes Traefik's setting explicitly.",
    ),
    code(
        "compose.service.problem",
        Level::Manual,
        "A problem with a service as a whole (the message says which: several exposed ports, a network…).",
        "Fix what the message names.",
    ),
    code(
        "compose.service.port_assumed",
        Level::Approximate,
        "No `expose`, `ports` or port label: port 80 was assumed.",
        "Traefik uses the port the image exposes, which a Compose file does not say: check it, or add `traefik.http.services.<name>.loadbalancer.server.port`.",
    ),
    code(
        "compose.service.traefik",
        Level::Exact,
        "The service that runs Traefik itself: its labels and static flags are read, the service is not routed.",
        "Replace its image with ReverseDock's and remove Traefik's flags (`rdock run` does not accept them).",
    ),
    // --- Traefik labels ------------------------------------------------------------------
    code(
        "traefik.label.approximate",
        Level::Approximate,
        "A Traefik label translated with a stated difference (the coverage table's note).",
        "Read the difference; the supported Traefik subset page lists them all.",
    ),
    code(
        "traefik.label.exact",
        Level::Exact,
        "A Traefik label translated with the same behaviour.",
        "None.",
    ),
    code(
        "traefik.label.inactive",
        Level::Exact,
        "A label of a container that `traefik.enable=false` turns off: Traefik ignores it too.",
        "None.",
    ),
    code(
        "traefik.label.invalid",
        Level::Manual,
        "A supported Traefik label whose value was refused.",
        "Fix the value as the message says.",
    ),
    code(
        "traefik.label.manual",
        Level::Manual,
        "A Traefik label that needs a setting outside labels (the message says which).",
        "Write the setting in rdock.yaml.",
    ),
    code(
        "traefik.label.not_exposed",
        Level::Manual,
        "A label of a container nothing exposes (no `traefik.enable`): it was not migrated.",
        "See `compose.service.not_exposed`.",
    ),
    code(
        "traefik.label.object_ignored",
        Level::Manual,
        "A label of an object that was left out (the message says why: no port, an ambiguous service, a conflict…).",
        "Fix what the message names; the object's other labels are then translated.",
    ),
    code(
        "traefik.label.unknown",
        Level::Dropped,
        "A `traefik.*` label that is not a Traefik v3.7 label.",
        "Check its spelling against Traefik's reference.",
    ),
    code(
        "traefik.label.unsupported",
        Level::Dropped,
        "A Traefik label without an equivalent (the message says why).",
        "None, or the alternative the message names.",
    ),
    code(
        "traefik.route.disabled",
        Level::Manual,
        "A route written disabled (`enabled: false`) because a middleware or service it uses was not migrated, so it never goes live without, say, its authentication.",
        "Replace what was not migrated, then remove `enabled: false`.",
    ),
    code(
        "rdock.label",
        Level::Exact,
        "An `rdock.*` label, read as it is.",
        "None.",
    ),
    code(
        "rdock.label.invalid",
        Level::Manual,
        "An `rdock.*` label that was refused.",
        "Fix it as the message says.",
    ),
    code(
        "traefik.router.all_entrypoints",
        Level::Approximate,
        "A router without `entrypoints`: Traefik attaches it to every entry point, ReverseDock to `defaults.listeners`.",
        "Name the entry points, or set `defaults.listeners`.",
    ),
    code(
        "traefik.router.plain_http",
        Level::Approximate,
        "A router without `tls`: Traefik serves it as plain HTTP (unless its entry point sets `http.tls`); the migrated route gets HTTPS with an automatic certificate and HTTP is redirected.",
        "Keep the HTTPS default (recommended), or write `tls: off` on the route; with `--static`, the entry points decide and the route is written as Traefik serves it.",
    ),
    // --- Traefik dynamic configuration files ----------------------------------------------
    code(
        "traefik.file.approximate",
        Level::Approximate,
        "A key of a dynamic configuration file written with a stated difference.",
        "Read the difference.",
    ),
    code(
        "traefik.file.exact",
        Level::Exact,
        "A key of a dynamic configuration file translated with the same behaviour.",
        "None.",
    ),
    code(
        "traefik.file.manual",
        Level::Manual,
        "A key of a dynamic configuration file that needs a decision (the message says which).",
        "Write the setting in rdock.yaml.",
    ),
    code(
        "traefik.file.toml",
        Level::Manual,
        "A TOML file: only YAML is read.",
        "Convert the file to YAML (the keys are the same), then run the migration again.",
    ),
    code(
        "traefik.file.unsupported",
        Level::Dropped,
        "A key of a dynamic configuration file without an equivalent.",
        "None, or the alternative the message names.",
    ),
    code(
        "traefik.file.users_file",
        Level::Exact,
        "`basicAuth.usersFile`: the same file is named, never read or copied.",
        "Make the file readable by ReverseDock at the same path.",
    ),
    // --- Traefik static configuration -----------------------------------------------------
    code(
        "traefik.static.approximate",
        Level::Approximate,
        "A static setting written with a stated difference.",
        "Read the difference.",
    ),
    code(
        "traefik.static.credentials",
        Level::Manual,
        "A credential (DNS provider, EAB key, provider password): never copied; the output refers to an environment variable.",
        "Set the variables the message names in ReverseDock's environment (or use `${file:…}` references).",
    ),
    code(
        "traefik.static.exact",
        Level::Exact,
        "A static setting translated with the same behaviour.",
        "None.",
    ),
    code(
        "traefik.static.expose_by_default",
        Level::Exact,
        "Traefik's `exposedByDefault` (default `true`) written explicitly as `expose_by_default`.",
        "This is a security choice: every container with labels is routed. Set it to `false` and add `traefik.enable=true` where wanted, which is ReverseDock's default.",
    ),
    code(
        "traefik.static.manual",
        Level::Manual,
        "A static setting that needs a decision (the message says which).",
        "Write the setting in rdock.yaml.",
    ),
    code(
        "traefik.static.unknown",
        Level::Dropped,
        "A key that is not a Traefik v3.7 static option this tool knows.",
        "Check its spelling against Traefik's reference.",
    ),
    code(
        "traefik.static.unsupported",
        Level::Dropped,
        "A static setting without an equivalent (the message says why).",
        "None, or the alternative the message names.",
    ),
    // --- The result ------------------------------------------------------------------------
    code(
        "output.invalid",
        Level::Manual,
        "The written configuration has a validation error on its own (for example a reference to an object in another file).",
        "Check it with `rdock validate` once the rest of the configuration is in place.",
    ),
    code(
        "output.labels_live",
        Level::Exact,
        "With `--full` and a Compose file, the label routes are not written: the Docker provider reads the same labels at run time.",
        "Keep the labels on the containers.",
    ),
];

/// The code entry of `id`.
#[must_use]
pub fn code_info(id: &str) -> Option<&'static Code> {
    CODES.iter().find(|c| c.id == id)
}

/// What kind of thing a source item is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ItemKind {
    /// A container label (`traefik.http.routers.web.rule`).
    Label,
    /// A key of a configuration file, as a dotted path (`http.routers.web.rule`).
    Key,
    /// A command-line flag (`--entrypoints.web.address`).
    Flag,
    /// An environment variable (`TRAEFIK_ENTRYPOINTS_WEB_ADDRESS`).
    Env,
    /// A whole file, or a Compose service as a whole.
    Object,
}

/// Where a source item is.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, JsonSchema)]
pub struct Source {
    /// The file it was read from (`-` for standard input).
    pub file: String,
    /// The line, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    /// The object it belongs to in the file: a Compose service, a static section.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// What kind of item it is.
    pub kind: ItemKind,
    /// The item: a label key, a dotted file key, a flag, a variable name, an object name.
    pub item: String,
}

/// One finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct Finding {
    /// The kind of finding (a code of `x-rdock-codes`).
    pub code: String,
    /// How faithfully the item was carried over.
    pub level: Level,
    /// The source item it accounts for; absent for a finding about the written result.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<Source>,
    /// The generated object, as a path in rdock.yaml (`routes.web`), when there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// One line on what happened.
    pub message: String,
    /// What to do, when something can be done.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    /// The item is a security-relevant choice (for example Traefik's `exposedByDefault`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub security: bool,
}

impl Finding {
    /// A finding of the code `id` at its level.
    #[must_use]
    pub fn new(id: &str, message: impl Into<String>) -> Self {
        let level = code_info(id).map_or(Level::Manual, |c| c.level);
        Self {
            code: id.to_owned(),
            level,
            source: None,
            target: None,
            message: message.into(),
            hint: None,
            security: false,
        }
    }

    /// With the generated object's path.
    #[must_use]
    pub fn target(mut self, target: impl Into<String>) -> Self {
        let target = target.into();
        if !target.is_empty() {
            self.target = Some(target);
        }
        self
    }

    /// With a hint.
    #[must_use]
    pub fn hint(mut self, hint: impl Into<String>) -> Self {
        let hint = hint.into();
        if !hint.is_empty() {
            self.hint = Some(hint);
        }
        self
    }

    /// Marked as a security-relevant choice.
    #[must_use]
    pub fn security(mut self) -> Self {
        self.security = true;
        self
    }
}

/// Counts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, JsonSchema)]
pub struct Summary {
    /// Source items read; each is accounted for by exactly one finding.
    pub items: usize,
    /// Items carried over with the same behaviour.
    pub exact: usize,
    /// Items carried over with a stated difference.
    pub approximate: usize,
    /// Items that need a decision.
    pub manual: usize,
    /// Items without an equivalent.
    pub dropped: usize,
    /// Findings about the written result (no source item), counted apart.
    pub result: usize,
}

/// What was read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct SourceInfo {
    /// The other proxy: `traefik` (later `caddy`, `nginx`).
    pub kind: String,
    /// The version the translation was checked against, e.g. `Traefik v3.7`.
    pub checked_against: String,
    /// The files read, in order.
    pub files: Vec<String>,
}

/// The report of one migration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[schemars(title = "rdock migrate report", extend("x-rdock-maturity" = "beta"))]
pub struct Report {
    /// The report format's version: 1.
    pub version: u32,
    /// The command, e.g. `rdock migrate traefik`.
    pub tool: String,
    /// The rdock version that wrote it.
    pub rdock_version: String,
    /// What was read.
    pub source: SourceInfo,
    /// Counts by level.
    pub summary: Summary,
    /// Every finding: one per source item (in reading order), then the findings about the
    /// result.
    pub findings: Vec<Finding>,
}

impl Report {
    /// Whether anything is manual or dropped (`--strict` exits 2).
    #[must_use]
    pub fn needs_review(&self) -> bool {
        self.findings.iter().any(|f| f.level.needs_review())
    }

    /// The findings that are not exact, for headers and summaries.
    pub fn notable(&self) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(|f| f.level != Level::Exact)
    }

    /// One line of counts.
    #[must_use]
    pub fn counts(&self) -> String {
        let s = &self.summary;
        let mut line = format!(
            "{} source item(s): {} exact, {} approximate, {} manual, {} dropped",
            s.items, s.exact, s.approximate, s.manual, s.dropped
        );
        if s.result > 0 {
            let _ = write!(line, "; {} finding(s) about the result", s.result);
        }
        line
    }

    /// The report as text: counts first, then the findings grouped by level (manual, dropped,
    /// approximate; exact ones only with `verbose`).
    #[must_use]
    pub fn text(&self, verbose: bool) -> String {
        let mut out = format!("{}: {}\n", self.tool, self.counts());
        let levels = [
            (Level::Manual, "Needs a decision (manual)"),
            (Level::Dropped, "No equivalent (dropped)"),
            (
                Level::Approximate,
                "Translated with a difference (approximate)",
            ),
            (Level::Exact, "Translated (exact)"),
        ];
        for (level, title) in levels {
            if level == Level::Exact && !verbose {
                continue;
            }
            let group: Vec<&Finding> = self.findings.iter().filter(|f| f.level == level).collect();
            if group.is_empty() {
                continue;
            }
            let _ = writeln!(out, "\n{title}: {}", group.len());
            for finding in group {
                let _ = writeln!(out, "  - {}", finding.line());
                if let Some(hint) = &finding.hint {
                    let _ = writeln!(out, "      hint: {hint}");
                }
            }
        }
        out
    }
}

impl Finding {
    /// `[code] where → target: message`.
    #[must_use]
    pub fn line(&self) -> String {
        let mut line = format!("[{}] ", self.code);
        if let Some(source) = &self.source {
            line.push_str(&source.describe());
        } else {
            line.push_str("result");
        }
        if let Some(target) = &self.target {
            let _ = write!(line, " → {target}");
        }
        let _ = write!(line, ": {}", self.message);
        if self.security {
            line.push_str(" (security-relevant)");
        }
        line
    }
}

impl Source {
    /// `compose.yaml: web: label traefik.http.routers.web.rule`.
    #[must_use]
    pub fn describe(&self) -> String {
        let kind = match self.kind {
            ItemKind::Label => "label ",
            ItemKind::Key => "key ",
            ItemKind::Flag => "flag ",
            ItemKind::Env => "variable ",
            ItemKind::Object => "",
        };
        let mut text = self.file.clone();
        if let Some(line) = self.line {
            let _ = write!(text, ":{line}");
        }
        if let Some(scope) = &self.scope {
            let _ = write!(text, ": {scope}");
        }
        let _ = write!(text, ": {kind}{}", self.item);
        text
    }
}

/// An item accounted for twice, or not at all: a bug in a migration, never the user's input.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("migration accounting is broken (a bug; please report it): {0}")]
pub struct AccountingError(pub String);

/// Builds a report and enforces the accounting invariant: every source item registered with
/// [`Builder::item`] gets exactly one finding.
#[derive(Debug, Default)]
pub struct Builder {
    items: Vec<Source>,
    findings: BTreeMap<usize, Finding>,
    doubles: Vec<usize>,
    result: Vec<Finding>,
}

/// A registered source item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ItemId(usize);

impl Builder {
    /// Registers a source item; it must then be accounted for once.
    pub fn item(&mut self, source: Source) -> ItemId {
        self.items.push(source);
        ItemId(self.items.len() - 1)
    }

    /// The source of an item.
    #[must_use]
    pub fn source(&self, id: ItemId) -> Option<&Source> {
        self.items.get(id.0)
    }

    /// Accounts for an item. A second call for the same item is an accounting error (see
    /// [`Builder::raise`] to replace a finding with a worse one).
    pub fn account(&mut self, id: ItemId, finding: Finding) {
        if self.findings.contains_key(&id.0) {
            self.doubles.push(id.0);
            return;
        }
        self.findings.insert(id.0, finding);
    }

    /// Accounts for an item, or replaces its finding when `finding` is at the same or a worse
    /// level (the later finding is the more specific one).
    pub fn raise(&mut self, id: ItemId, finding: Finding) {
        match self.findings.get(&id.0) {
            Some(existing) if existing.level > finding.level => {}
            _ => {
                self.findings.insert(id.0, finding);
            }
        }
    }

    /// Whether the item is accounted for.
    #[must_use]
    pub fn accounted(&self, id: ItemId) -> bool {
        self.findings.contains_key(&id.0)
    }

    /// The finding of an item so far.
    #[must_use]
    pub fn finding(&self, id: ItemId) -> Option<&Finding> {
        self.findings.get(&id.0)
    }

    /// A finding about the written result, not about one source item.
    pub fn result(&mut self, finding: Finding) {
        self.result.push(finding);
    }

    /// The report, or the accounting error when an item has no finding or was accounted for
    /// twice.
    pub fn finish(self, tool: &str, source: SourceInfo) -> Result<Report, AccountingError> {
        let missing: Vec<String> = (0..self.items.len())
            .filter(|i| !self.findings.contains_key(i))
            .map(|i| self.items[i].describe())
            .collect();
        if !missing.is_empty() || !self.doubles.is_empty() {
            let doubles: Vec<String> = self
                .doubles
                .iter()
                .map(|i| self.items[*i].describe())
                .collect();
            return Err(AccountingError(format!(
                "not accounted for: [{}]; accounted for twice: [{}]",
                missing.join(", "),
                doubles.join(", ")
            )));
        }
        let mut summary = Summary {
            items: self.items.len(),
            result: self.result.len(),
            ..Summary::default()
        };
        let mut findings = Vec::with_capacity(self.items.len() + self.result.len());
        for (index, mut finding) in self.findings {
            match finding.level {
                Level::Exact => summary.exact += 1,
                Level::Approximate => summary.approximate += 1,
                Level::Manual => summary.manual += 1,
                Level::Dropped => summary.dropped += 1,
            }
            finding.source = Some(self.items[index].clone());
            findings.push(finding);
        }
        findings.extend(self.result);
        Ok(Report {
            version: 1,
            tool: tool.to_owned(),
            rdock_version: env!("CARGO_PKG_VERSION").to_owned(),
            source,
            summary,
            findings,
        })
    }
}

/// The JSON Schema of the report (`schema/migrate-report.v1.json`), with the codes under
/// `x-rdock-codes`.
#[must_use]
pub fn json_schema() -> serde_json::Value {
    let mut schema = schemars::schema_for!(Report).to_value();
    if let Some(map) = schema.as_object_mut() {
        map.insert("$id".to_owned(), SCHEMA_ID.into());
        map.insert(
            "x-rdock-codes".to_owned(),
            serde_json::to_value(CODES).unwrap_or_default(),
        );
    }
    schema
}
