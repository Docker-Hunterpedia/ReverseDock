#!/usr/bin/env python3
"""The compatibility gate of ADR-0033: compares the tree's public surfaces with the last release
tag and reports every change that docs/10-stability.md calls breaking.

Standard library only; run with `python3 -I`. Commands:

  check     the gate (CI's `compat` job): every surface against the baseline tag
  snapshot  print a snapshot generated here (`image`, from Dockerfile.release)
  diff      compare two JSON Schema files ad hoc (`--direction input|output`)

The baseline is the newest tag matching `v*` reachable from HEAD (`git describe --tags
--abbrev=0 --match 'v*'`), or `--baseline` / `RDOCK_COMPAT_BASELINE`. The mode is `report`
(print findings, never fail on them) while the tree's version is below 1.0.0-rc.1 and
`enforce` from then on; `--mode` or `RDOCK_COMPAT_MODE` forces either. Stale or missing
snapshots, an invalid exceptions file and a missing baseline fail in both modes.

An element below `stable` in the maturity registry, or deprecated with its removal release
reached, is exempt. A reviewed exception in schema/compat/exceptions.json (surface, element,
rule, reason, release) accepts one finding until the baseline reaches that release.

Exit codes: 0 nothing that fails; 1 a failing finding (enforce mode), drift or an invalid
exceptions file; 2 the gate could not run (no baseline, a shallow clone, a git error).
"""

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys

STABILITY = "docs/10-stability.md"
EXCEPTIONS = "schema/compat/exceptions.json"
ENFORCE_FROM = "1.0.0-rc.1"

# The rows of the table in docs/10-stability.md §2, quoted.
ROWS = {
    "config": "Configuration file (schema v1)",
    "helm": "Helm values",
    "api": "Admin API `/api/v1`",
    "cli": "CLI",
    "metrics": "Metrics",
    "access-log": "JSON access-log fields",
    "problems": "Problem types (RFC 9457)",
    "env": "Documented `RDOCK_*` environment variables",
    "labels": "`rdock.*` labels",
    "traefik": "Traefik label subset (documented, pinned to Traefik v3.7)",
    "image": "Container image",
    "plugin-sdk": "`rdock-plugin-api`",
}

# For each surface: the rule (as quoted from its row) that each kind of change breaks.
RULES = {
    "config": {
        "removed": "Removing or renaming a key",
        "type": "changing a type",
        "required": "making an optional key required",
        "enum": "removing an enum value",
        "refused": "refusing a file that validated before",
        "default": "changing a default that changes behaviour",
    },
    "helm": {
        "removed": "As for the configuration file, on `values.schema.json`: removing or renaming a key",
        "type": "As for the configuration file: changing a type",
        "required": "As for the configuration file: making an optional key required",
        "enum": "As for the configuration file: removing an enum value",
        "refused": "As for the configuration file: refusing a file that validated before",
        "default": "As for the configuration file: changing a default that changes behaviour",
    },
    "api": {
        "removed": "Removing a path, method, field or enum value",
        "type": "changing types",
        "required": "making a request field required",
        "enum": "Removing a path, method, field or enum value",
        "refused": "changing types",
        "default": "changing types",
        "status": "changing status codes",
        "security": "changing the roles an operation needs",
    },
    "cli": {
        "removed": "Removing or renaming a command, flag or documented `RDOCK_*` variable",
        "type": "changing JSON output fields or their types",
        "required": "Removing or renaming a command, flag or documented `RDOCK_*` variable",
        "enum": "Removing or renaming a command, flag or documented `RDOCK_*` variable",
        "refused": "Removing or renaming a command, flag or documented `RDOCK_*` variable",
        "default": "changing a default",
        "exit": "changing what exit codes `0`, `1` and `2` mean",
    },
    "metrics": {
        "removed": "Removing or renaming a metric or label",
        "type": "changing a stable metric's type, unit or histogram buckets",
        "label": "Removing or renaming a metric or label (a new label name on an existing metric counts as a new metric)",
    },
    "access-log": {
        "removed": "Removing or renaming a field",
        "type": "changing its type",
    },
    "problems": {
        "removed": "Removing a `type` URI",
        "status": "changing its status",
    },
    "env": {"removed": "Removing or renaming one"},
    "labels": {"removed": "As for the configuration file: removing or renaming a label"},
    "traefik": {"removed": "Dropping a label listed as supported"},
    "image": {
        "changed": "Entrypoint, default command, user id (65532), data path (`/var/lib/rdock`), exposed ports, health check",
    },
    "plugin-sdk": {
        "semver": "What the Cargo SemVer reference calls major",
    },
}
REVIEW_RULE = "a change the checker cannot classify; treat it as breaking until a reviewer records why it is not"

# Surfaces, their files and how they are compared. `kind` selects the differ.
SURFACES = [
    {"id": "config", "file": "schema/rdock.v1.json", "kind": "schema", "direction": "input"},
    {"id": "api", "file": "schema/openapi.json", "kind": "openapi"},
    {"id": "cli", "file": "schema/compat/cli.json", "kind": "cli"},
    {"id": "metrics", "file": "schema/compat/metrics.json", "kind": "metrics"},
    {"id": "access-log", "file": "schema/compat/access-log.json", "kind": "access-log"},
    {"id": "problems", "file": "schema/compat/problems.json", "kind": "problems"},
    {"id": "env", "file": "schema/compat/env.json", "kind": "env"},
    {"id": "labels", "file": "schema/compat/labels.json", "kind": "labels"},
    {"id": "image", "file": "schema/compat/image.json", "kind": "image"},
    {"id": "helm", "file": "deploy/helm/reversedock/values.schema.json", "kind": "schema", "direction": "input"},
    {"id": "plugin-sdk", "file": None, "kind": "semver"},
]
SURFACE_IDS = [s["id"] for s in SURFACES] + ["traefik"]

# Snapshots the binary prints (`rdock schema --compat <name>`); `labels.json` comes from a test
# and `image.json` from this script.
BINARY_SNAPSHOTS = ["metrics", "cli", "access-log", "problems", "env", "deprecations"]


# --- Versions -----------------------------------------------------------------------------------


def parse_version(text):
    """SemVer 2.0.0 precedence key of `1.2.3-rc.1` (a leading `v` and a missing patch are fine)."""
    text = text.strip()
    if text.startswith("v"):
        text = text[1:]
    text = text.split("+", 1)[0]
    core, _, pre = text.partition("-")
    parts = core.split(".")
    if not 1 <= len(parts) <= 3 or not all(p.isdigit() for p in parts):
        raise ValueError(f"not a version: {text!r}")
    nums = tuple(int(p) for p in parts) + (0,) * (3 - len(parts))
    if not pre:
        return nums + ((1,),)
    ids = []
    for ident in pre.split("."):
        ids.append((0, int(ident), "") if ident.isdigit() else (1, 0, ident))
    return nums + ((0, tuple(ids)),)


def version_ge(a, b):
    return parse_version(a) >= parse_version(b)


def version_lt(a, b):
    return parse_version(a) < parse_version(b)


# --- Findings -----------------------------------------------------------------------------------


class Finding:
    """One change. `kind` is `breaking` or `review`; `exempt` says why it does not count."""

    def __init__(self, surface, element, rule, detail, kind="breaking"):
        self.surface = surface
        self.element = element
        self.rule = rule
        self.detail = detail
        self.kind = kind
        self.exempt = None
        self.excepted = None
        self.hint = None
        self.also_at = []

    def counts(self):
        return self.exempt is None and self.excepted is None

    def rule_text(self):
        if self.kind == "review":
            return REVIEW_RULE
        row = "traefik" if self.surface == "traefik" else self.surface
        return RULES.get(row, {}).get(self.rule, self.rule)

    def as_dict(self):
        out = {
            "surface": self.surface,
            "element": self.element,
            "rule": self.rule,
            "kind": self.kind,
            "detail": self.detail,
            "stability_row": ROWS.get(self.surface, self.surface),
            "stability_rule": self.rule_text(),
        }
        for key in ("exempt", "excepted", "hint"):
            if getattr(self, key):
                out[key] = getattr(self, key)
        if self.also_at:
            out["also_at"] = self.also_at
        return out


# --- Maturity and deprecations ------------------------------------------------------------------


def segments(element):
    """Dotted path segments; `a.*.type=wasm.b` → ['a', '*', 'type=wasm', 'b']."""
    return [s for s in element.split(".") if s != ""] if element else []


def location_matches(location, element):
    loc = segments(location)
    seg = segments(element)
    return len(loc) <= len(seg) and seg[: len(loc)] == loc


class Context:
    """What the differs consult: the maturity registry, the deprecations and the versions."""

    def __init__(self, features=None, deprecations=None, tree_version="0.0.0"):
        # [(location, level, feature id)] for features below stable.
        self.locations = []
        self.levels = {}
        for feature in features or []:
            level = feature.get("level", "stable")
            self.levels[feature.get("id")] = level
            if level != "stable":
                for loc in feature.get("locations", []):
                    self.locations.append((loc, level, feature.get("id")))
        self.deprecations = deprecations or []
        self.tree_version = tree_version

    def level_of_location(self, element):
        for loc, level, fid in self.locations:
            if location_matches(loc, element):
                return level, fid
        return None

    def feature_level(self, feature_id):
        return self.levels.get(feature_id, "stable")

    def deprecation_for(self, kinds, element):
        for entry in self.deprecations:
            if entry.get("kind") not in kinds:
                continue
            if element == entry.get("element") or location_matches(entry.get("element", ""), element):
                return entry
        return None


DEPRECATION_KINDS = {
    "config": {"config_key", "config_value"},
    "api": {"api_operation", "api_field"},
    "cli": {"cli_command", "cli_flag"},
    "metrics": {"metric"},
    "labels": {"label"},
    "traefik": {"label"},
}


def apply_policy(findings, ctx):
    """Marks findings exempt by deprecation (removal release reached) and adds hints."""
    for f in findings:
        if f.exempt:
            continue
        kinds = DEPRECATION_KINDS.get(f.surface, set())
        # An API finding names `METHOD /path` first; the registry names operations that way.
        element = " ".join(f.element.split(" ")[:2]) if f.surface == "api" else f.element
        entry = ctx.deprecation_for(kinds, element)
        if entry is None:
            continue
        removal = entry.get("removal", "")
        try:
            reached = version_ge(ctx.tree_version, removal)
        except ValueError:
            reached = False
        if reached:
            f.exempt = f"deprecated since {entry.get('since')}, removed in {removal} as announced"
        else:
            f.hint = f"deprecated since {entry.get('since')}; it may go in {removal}, not before"


# --- JSON Schema differ -------------------------------------------------------------------------

INT_FORMATS = {
    "int8": (-(2**7), 2**7 - 1),
    "int16": (-(2**15), 2**15 - 1),
    "int32": (-(2**31), 2**31 - 1),
    "int64": (-(2**63), 2**63 - 1),
    "int": (-(2**63), 2**63 - 1),
    "uint8": (0, 2**8 - 1),
    "uint16": (0, 2**16 - 1),
    "uint32": (0, 2**32 - 1),
    "uint64": (0, 2**64 - 1),
    "uint": (0, 2**64 - 1),
}
FLOAT_FORMATS = {"float": 1, "double": 2}
LOWER_BOUNDS = ("minimum", "exclusiveMinimum", "minLength", "minItems", "minProperties")
UPPER_BOUNDS = ("maximum", "exclusiveMaximum", "maxLength", "maxItems", "maxProperties")
UNHANDLED = (
    "not",
    "if",
    "then",
    "else",
    "dependentRequired",
    "dependentSchemas",
    "contains",
    "minContains",
    "maxContains",
    "propertyNames",
    "unevaluatedProperties",
    "unevaluatedItems",
    "prefixItems",
    "multipleOf",
    "dependencies",
)


def canon(value):
    return json.dumps(value, sort_keys=True)


def json_type(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    return "object"


def covers(wide, narrow):
    """Whether type set `wide` accepts every value of type set `narrow` (empty = anything)."""
    if not wide:
        return True
    if not narrow:
        return False
    for t in narrow:
        if t in wide or (t == "integer" and "number" in wide):
            continue
        return False
    return True


class SchemaDiff:
    """Compares two JSON Schemas (2020-12 or draft-07, as schemars and utoipa write them).

    `direction` is `input` (the user writes a document that we read: we must keep accepting
    everything we accepted) or `output` (we write, the user reads: we must keep writing every
    field with a type the user expects). `skip_ref` names refs not to follow.
    """

    def __init__(self, surface, old_root, new_root, ctx, direction="input", skip_ref=None):
        self.surface = surface
        self.old_root = old_root
        self.new_root = new_root
        self.ctx = ctx
        self.direction = direction
        self.skip_ref = skip_ref or (lambda ref: False)
        self.findings = []
        self.memo = {}
        self.active = set()

    # Resolution -------------------------------------------------------------------------------

    def lookup(self, root, ref):
        if not ref.startswith("#"):
            return None
        node = root
        for part in ref[1:].split("/")[1:]:
            part = part.replace("~1", "/").replace("~0", "~")
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                return None
        return node

    def resolve(self, node, root):
        """Follows `$ref`s; sibling keywords (description, default…) win over the target's."""
        refs = []
        seen = 0
        while isinstance(node, dict) and "$ref" in node and seen < 64:
            ref = node["$ref"]
            refs.append(ref)
            target = self.lookup(root, ref)
            if not isinstance(target, dict):
                break
            merged = dict(target)
            for k, v in node.items():
                if k != "$ref":
                    merged[k] = v
            node = merged
            seen += 1
        if isinstance(node, bool):
            node = {} if node else {"not": {}}
        if not isinstance(node, dict):
            node = {}
        return node, refs

    def normalize(self, node, root):
        node, refs = self.resolve(node, root)
        unsure = False
        if "allOf" in node:
            merged = {k: v for k, v in node.items() if k != "allOf"}
            for branch in node["allOf"]:
                branch, _ = self.resolve(branch, root)
                for k, v in branch.items():
                    if k == "properties":
                        merged.setdefault("properties", {}).update(v)
                    elif k == "required":
                        merged["required"] = sorted(set(merged.get("required", [])) | set(v))
                    elif k in merged and canon(merged[k]) != canon(v) and k not in ("description", "title"):
                        unsure = True
                    else:
                        merged.setdefault(k, v)
            node = merged
        for key in ("oneOf", "anyOf"):
            if key not in node:
                continue
            raw = node[key]
            branches = [self.resolve(b, root)[0] for b in raw]
            is_null = [b.get("type") == "null" or ("const" in b and b["const"] is None) for b in branches]
            nulls = [b for b, null in zip(branches, is_null) if null]
            others = [b for b, null in zip(branches, is_null) if not null]
            raw_others = [r for r, null in zip(raw, is_null) if not null]
            outer = {k: v for k, v in node.items() if k not in ("oneOf", "anyOf")}
            if len(others) == 1:
                inner = self.normalize(others[0], root)[0]
                merged = dict(inner)
                for k, v in outer.items():
                    if k not in ("type",):
                        merged[k] = v
                if nulls:
                    merged["x-nullable"] = True
                node = merged
            elif others and all(enum_branch(b) for b in others):
                node = enum_node(others, outer, bool(nulls))
            else:
                # Constants among other alternatives form one alternative, a list of values.
                consts = [b for b in others if enum_branch(b)]
                union = [r for r, b in zip(raw_others, others) if not enum_branch(b)]
                if consts:
                    union.insert(0, enum_node(consts, {}, False))
                merged = dict(outer)
                merged["x-union"] = union
                if nulls:
                    merged["x-nullable"] = True
                node = merged
            break
        if unsure:
            node = dict(node)
            node["x-unsure"] = True
        return node, refs

    @staticmethod
    def types(node):
        t = node.get("type")
        out = set()
        if isinstance(t, str):
            out.add(t)
        elif isinstance(t, list):
            out.update(t)
        elif "const" in node:
            out.add(json_type(node["const"]))
        elif "enum" in node:
            out.update(json_type(v) for v in node["enum"])
        elif "properties" in node or "additionalProperties" in node:
            out.add("object")
        elif "items" in node:
            out.add("array")
        if node.get("x-nullable") or node.get("nullable") is True:
            if out:
                out.add("null")
        return out

    @staticmethod
    def enum_values(node):
        if "const" in node:
            return {canon(node["const"]): node["const"]}
        if "enum" in node:
            return {canon(v): v for v in node["enum"]}
        return None

    @staticmethod
    def maturity(node):
        level = node.get("x-rdock-maturity")
        if level and level != "stable":
            return level, node.get("x-rdock-feature")
        return None

    # Findings ---------------------------------------------------------------------------------

    def emit(self, path, rule, detail, kind="breaking", exempt=None):
        element = ".".join(path) if path else "(root)"
        f = Finding(self.surface, element, rule, detail, kind)
        if exempt:
            f.exempt = exempt
        self.findings.append(f)
        return f

    def exempt_for(self, path, *nodes, inherited=None):
        if inherited:
            return inherited
        for node in nodes:
            m = self.maturity(node)
            if m:
                return f"{m[0]} ({m[1] or 'below stable'})"
        if self.surface in ("config", "labels"):
            hit = self.ctx.level_of_location(".".join(path))
            if hit:
                return f"{hit[0]} ({hit[1]})"
        return None

    # Comparison -------------------------------------------------------------------------------

    def compare(self, old, new, path=(), exempt=None):
        path = list(path)
        o, orefs = self.normalize(old, self.old_root)
        n, nrefs = self.normalize(new, self.new_root)
        exempt = self.exempt_for(path, o, n, inherited=exempt)
        if any(self.skip_ref(r) for r in orefs + nrefs):
            return
        key = None
        if orefs and nrefs:
            # Keywords next to a `$ref` (a default, a bound) differ per use, so they are part of
            # what is compared.
            key = (orefs[-1], nrefs[-1], self.direction, exempt is not None, siblings(old), siblings(new))
            if key in self.active:
                return
            if key in self.memo:
                start, end, first = self.memo[key]
                here = ".".join(path) if path else "(root)"
                for f in self.findings[start:end]:
                    if f.element.startswith(first):
                        f.also_at.append(here + f.element[len(first):])
                return
            self.active.add(key)
        start = len(self.findings)
        try:
            self._compare(o, n, path, exempt)
        finally:
            if key is not None:
                self.active.discard(key)
                self.memo[key] = (start, len(self.findings), ".".join(path) if path else "(root)")

    def _compare(self, o, n, path, exempt):
        inp = self.direction == "input"
        if o.get("x-unsure") or n.get("x-unsure"):
            if canon(o) != canon(n):
                self.emit(path, "review", "an `allOf` whose parts disagree changed", "review", exempt)
            return
        if inp:
            self.compare_default(o, n, path, exempt)
        if "x-union" in o or "x-union" in n:
            self.compare_union(o, n, path, exempt)
            return
        ot, nt = self.types(o), self.types(n)
        if inp:
            if not covers(nt, ot):
                self.emit(path, "type", f"type {fmt_types(ot)} → {fmt_types(nt)}", exempt=exempt)
                return
        else:
            if not covers(ot, nt):
                self.emit(path, "type", f"type {fmt_types(ot)} → {fmt_types(nt)}", exempt=exempt)
                return
        oe, ne = self.enum_values(o), self.enum_values(n)
        if inp:
            if oe is not None and ne is not None:
                for k in sorted(set(oe) - set(ne)):
                    value = oe[k]
                    label = value if isinstance(value, str) else canon(value)
                    leaf = path[:-1] + [f"{path[-1]}={label}"] if path else [f"={label}"]
                    ex = exempt or o.get("x-enum-maturity", {}).get(k) or self.exempt_for(leaf)
                    self.emit(leaf, "enum", f"value {canon(value)} no longer accepted", exempt=ex)
            elif oe is None and ne is not None:
                self.emit(path, "refused", f"restricted to {sorted(ne)}", exempt=exempt)
        self.compare_formats(o, n, path, exempt)
        if inp:
            self.compare_bounds(o, n, path, exempt)
        for kw in UNHANDLED:
            if kw in o or kw in n:
                if canon(o.get(kw)) != canon(n.get(kw)):
                    self.emit(path, "review", f"`{kw}` changed", "review", exempt)
        if "object" in (ot | nt) or "properties" in o or "properties" in n:
            self.compare_object(o, n, path, exempt)
        if "items" in o or "items" in n:
            oi = o.get("items", {})
            ni = n.get("items", {})
            if isinstance(oi, dict) and isinstance(ni, dict):
                self.compare(oi, ni, path + ["*"], exempt)
            elif canon(oi) != canon(ni):
                self.emit(path, "review", "tuple `items` changed", "review", exempt)

    def compare_default(self, o, n, path, exempt):
        od, nd = self.own_default(o, self.old_root), self.own_default(n, self.new_root)
        if "default" in o and "default" in n and default_changed(od, nd):
            self.emit(path, "default", f"default {canon(o['default'])} → {canon(n['default'])}", exempt=exempt)
        elif "default" in o and "default" not in n and o["default"] is not None:
            self.emit(path, "review", f"the default {canon(o['default'])} is no longer stated", "review", exempt)

    def own_default(self, node, root):
        """The default, without the keys of an object whose properties state their own default
        (those are compared at the property)."""
        default = node.get("default")
        props = node.get("properties")
        if not isinstance(default, dict) or not isinstance(props, dict):
            return default
        out = {}
        for k, v in default.items():
            prop = self.resolve(props[k], root)[0] if k in props else {}
            if "default" not in prop:
                out[k] = v
        return out

    def compare_formats(self, o, n, path, exempt):
        of, nf = o.get("format"), n.get("format")
        if of == nf or nf is None and self.direction == "input":
            return
        if of in INT_FORMATS and nf in INT_FORMATS:
            (olo, ohi), (nlo, nhi) = INT_FORMATS[of], INT_FORMATS[nf]
            narrower = nlo > olo or nhi < ohi
            wider = nlo < olo or nhi > ohi
            if (self.direction == "input" and narrower) or (self.direction == "output" and wider):
                self.emit(path, "type" if self.direction == "output" else "refused", f"format {of} → {nf}", exempt=exempt)
            return
        if of in FLOAT_FORMATS and nf in FLOAT_FORMATS:
            if (self.direction == "input") == (FLOAT_FORMATS[nf] < FLOAT_FORMATS[of]):
                self.emit(path, "type" if self.direction == "output" else "refused", f"format {of} → {nf}", exempt=exempt)
            return
        if self.direction == "input":
            if of is None:
                self.emit(path, "refused", f"format `{nf}` added", exempt=exempt)
            else:
                self.emit(path, "review", f"format `{of}` → `{nf}`", "review", exempt)
        elif nf is not None or of is not None:
            if of is not None and nf is None:
                self.emit(path, "review", f"format `{of}` no longer stated", "review", exempt)
            elif of is not None:
                self.emit(path, "review", f"format `{of}` → `{nf}`", "review", exempt)

    def compare_bounds(self, o, n, path, exempt):
        for kw in LOWER_BOUNDS:
            if kw in n and isinstance(n[kw], (int, float)) and (kw not in o or n[kw] > o[kw]):
                self.emit(path, "refused", f"{kw} {o.get(kw, 'none')} → {n[kw]}", exempt=exempt)
        for kw in UPPER_BOUNDS:
            if kw in n and isinstance(n[kw], (int, float)) and (kw not in o or n[kw] < o[kw]):
                self.emit(path, "refused", f"{kw} {o.get(kw, 'none')} → {n[kw]}", exempt=exempt)
        if "pattern" in n and o.get("pattern") != n["pattern"]:
            if "pattern" in o and pattern_loosened(o["pattern"], n["pattern"]):
                pass
            elif "pattern" in o:
                self.emit(path, "review", f"pattern {o['pattern']!r} → {n['pattern']!r}", "review", exempt)
            else:
                self.emit(path, "refused", f"pattern {n['pattern']!r} added", exempt=exempt)
        if n.get("uniqueItems") is True and o.get("uniqueItems") is not True:
            self.emit(path, "refused", "uniqueItems added", exempt=exempt)

    def compare_object(self, o, n, path, exempt):
        inp = self.direction == "input"
        op, np_ = o.get("properties", {}), n.get("properties", {})
        oreq, nreq = set(o.get("required", [])), set(n.get("required", []))
        na = n.get("additionalProperties", True)
        oa = o.get("additionalProperties", True)
        for key in sorted(op):
            child = path + [key]
            if key in np_:
                self.compare(op[key], np_[key], child, exempt)
                if not inp and key in oreq and key not in nreq:
                    self.emit(child, "removed", "no longer always present", exempt=self.exempt_for(child, op[key], inherited=exempt))
                continue
            node, _ = self.normalize(op[key], self.old_root)
            ex = self.exempt_for(child, node, inherited=exempt)
            if inp and isinstance(na, dict) and na:
                self.emit(child, "review", "the key is gone but other keys are now accepted", "review", ex)
            else:
                self.emit(child, "removed", "removed (or renamed)", exempt=ex)
        if inp:
            for key in sorted(nreq - oreq):
                child = path + [key]
                node, _ = self.normalize(np_.get(key, {}), self.new_root)
                self.emit(child, "required", "now required", exempt=self.exempt_for(child, node, inherited=exempt))
            if na is False and oa is not False:
                self.emit(path, "refused", "keys not listed are now refused (`additionalProperties: false`)", exempt=exempt)
        if isinstance(oa, dict) and isinstance(na, dict):
            self.compare(oa, na, path + ["*"], exempt)
        elif inp and isinstance(oa, dict) and oa and na is False:
            pass  # reported above
        opp, npp = o.get("patternProperties", {}), n.get("patternProperties", {})
        for pat in sorted(opp):
            if pat == "^x-":
                continue
            if pat in npp:
                self.compare(opp[pat], npp[pat], path + ["*"], exempt)
            elif inp and na is False:
                self.emit(path, "refused", f"keys matching {pat!r} are no longer accepted", exempt=exempt)

    def compare_union(self, o, n, path, exempt):
        inp = self.direction == "input"
        plain = lambda node: {k: v for k, v in node.items() if k not in ("x-nullable", "x-union")}
        ob = [self.branch(b, self.old_root) for b in o.get("x-union", [])] or [(plain(o), None)]
        nb = [self.branch(b, self.new_root) for b in n.get("x-union", [])] or [(plain(n), None)]
        ob = [b for b in ob if self.types(b[0]) != {"null"}]
        nb = [b for b in nb if self.types(b[0]) != {"null"}]
        onull, nnull = bool(o.get("x-nullable")), bool(n.get("x-nullable"))
        if inp and onull and not nnull:
            self.emit(path, "type", "`null` no longer accepted", exempt=exempt)
        if not inp and nnull and not onull:
            self.emit(path, "type", "may now be `null`", exempt=exempt)
        otag, ntag = discriminator([b for b, _ in ob]), discriminator([b for b, _ in nb])
        if otag and ntag and otag[0] == ntag[0]:
            prop, omap = otag
            _, nmap = ntag
            for value in sorted(omap):
                leaf = path + [f"{prop}={value}"]
                ex = self.exempt_for(leaf, omap[value], nmap.get(value, {}), inherited=exempt)
                if value in nmap:
                    self.compare(omap[value], nmap[value], leaf, ex)
                elif inp:
                    self.emit(leaf, "enum", f"`{prop}: {value}` no longer accepted", exempt=ex)
            return
        # Untagged: pair each alternative with its counterpart, by definition name first, then
        # by kind (types, a list of values or not, the keys of an object).
        sources, targets = (ob, nb) if inp else (nb, ob)
        for node, name in sources:
            bt = self.types(node)
            match = None
            if name is not None:
                same = [t for t in targets if t[1] == name]
                if len(same) == 1:
                    match = same[0]
            if match is None:
                shape = branch_shape(node, bt)
                same = [t for t in targets if branch_shape(t[0], self.types(t[0])) == shape]
                cover = [t for t in targets if covers(self.types(t[0]), bt)]
                if len(same) == 1:
                    match = same[0]
                elif len(cover) == 1:
                    match = cover[0]
                elif not cover:
                    what = "an alternative is no longer accepted" if inp else "a new alternative may be written"
                    self.emit(path, "type", f"{what}: {name or fmt_types(bt)}", exempt=exempt)
                    continue
                else:
                    self.emit(path, "review", f"cannot tell which alternative of {fmt_types(bt)} corresponds", "review", exempt)
                    continue
            pair = (node, match[0]) if inp else (match[0], node)
            self.compare(pair[0], pair[1], path, exempt)

    def branch(self, node, root):
        """A union alternative, normalized, with the name of the definition it refers to."""
        resolved, refs = self.normalize(node, root)
        name = refs[0].rsplit("/", 1)[-1] if refs else None
        return resolved, name


def branch_shape(node, types):
    return (
        frozenset(types),
        "enum" in node or "const" in node,
        frozenset(node.get("properties", {})),
        "x-union" in node,
    )


def discriminator(branches):
    """The property every branch fixes to a different constant (`type` first), with the map."""
    if len(branches) < 2:
        return None
    common = None
    for b in branches:
        consts = set()
        for k, v in b.get("properties", {}).items():
            if isinstance(v, dict) and ("const" in v or (isinstance(v.get("enum"), list) and len(v["enum"]) == 1)):
                consts.add(k)
        common = consts if common is None else common & consts
    if not common:
        return None
    for prop in (["type"] if "type" in common else []) + sorted(common - {"type"}):
        mapping = {}
        for b in branches:
            v = b["properties"][prop]
            value = v["const"] if "const" in v else v["enum"][0]
            mapping[value if isinstance(value, str) else canon(value)] = b
        if len(mapping) == len(branches):
            return prop, mapping
    return None


def siblings(node):
    if not isinstance(node, dict):
        return canon(node)
    ignored = ("$ref", "description", "title", "examples", "$defs", "definitions", "$schema", "$id")
    return canon({k: v for k, v in node.items() if k not in ignored})


def default_changed(old, new):
    """Whether a default changed. Keys a default object gains are new settings with their own
    defaults (checked where they are declared), so only the old keys are compared."""
    if isinstance(old, dict) and isinstance(new, dict):
        return any(k not in new or default_changed(v, new[k]) for k, v in old.items())
    return canon(old) != canon(new)


def alternatives(pattern):
    """The top-level alternatives of `^(a|b|c)$`, or None for any other form."""
    if not (pattern.startswith("^(") and pattern.endswith(")$")):
        return None
    body = pattern[2:-2]
    out, depth, current, i, in_class = [], 0, "", 0, False
    while i < len(body):
        c = body[i]
        if c == "\\" and i + 1 < len(body):
            current += body[i : i + 2]
            i += 2
            continue
        if in_class:
            in_class = c != "]"
        elif c == "[":
            in_class = True
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth < 0:
                return None
        elif c == "|" and depth == 0:
            out.append(current)
            current = ""
            i += 1
            continue
        current += c
        i += 1
    if depth != 0 or in_class:
        return None
    out.append(current)
    return out


def pattern_loosened(old, new):
    """Whether `new` only adds top-level alternatives to `old` (`^(a|b)$` → `^(a|b|c)$`)."""
    a, b = alternatives(old), alternatives(new)
    return a is not None and b is not None and set(a) <= set(b)


def enum_node(branches, outer, nullable):
    """One node listing the values of constant alternatives, with the maturity of each value."""
    values, meta = [], {}
    for b in branches:
        vals = [b["const"]] if "const" in b else b["enum"]
        values.extend(vals)
        level = b.get("x-rdock-maturity")
        if level and level != "stable":
            for v in vals:
                meta[canon(v)] = f"{level} ({b.get('x-rdock-feature', 'below stable')})"
    merged = dict(outer)
    merged["enum"] = values + ([None] if nullable else [])
    types = {json_type(v) for v in values}
    merged["type"] = sorted(types | ({"null"} if nullable else set()))
    if meta:
        merged["x-enum-maturity"] = meta
    return merged


def enum_branch(branch):
    """A branch that is one value or a list of values (with texts and our annotations)."""
    keys = {k for k in branch if not k.startswith("x-")} - {"description", "title", "type", "deprecated"}
    return keys in ({"const"}, {"enum"})


def fmt_types(types):
    return "|".join(sorted(types)) if types else "any"


def diff_schema(surface, old, new, ctx, direction="input", skip_ref=None):
    d = SchemaDiff(surface, old, new, ctx, direction, skip_ref)
    d.compare(old, new, [])
    return d.findings


# --- OpenAPI differ -----------------------------------------------------------------------------

METHODS = ("get", "put", "post", "delete", "patch", "head", "options", "trace")


def is_model_ref(ref):
    """The configuration model inside the API document is checked as the configuration schema."""
    return ref.startswith("#/components/schemas/rdock.")


def diff_openapi(old, new, ctx):
    findings = []
    schema = SchemaDiff("api", old, new, ctx, "input", is_model_ref)

    def resolve(node, root):
        return schema.resolve(node, root)[0]

    for path in sorted(old.get("paths", {})):
        oitem = old["paths"][path]
        nitem = new.get("paths", {}).get(path, {})
        for method in METHODS:
            if method not in oitem:
                continue
            oop = oitem[method]
            element = f"{method.upper()} {path}"
            nop = nitem.get(method)
            exempt = None
            for op in (oop, nop or {}):
                level = op.get("x-rdock-maturity")
                if level and level != "stable":
                    exempt = f"{level} ({op.get('x-rdock-feature', 'below stable')})"
            if nop is None:
                f = Finding("api", element, "removed", "operation removed" if nitem else "path removed")
                f.exempt = exempt
                findings.append(f)
                continue
            # Parameters, keyed by (in, name).
            opar = parameters(schema, oop, oitem, old)
            npar = parameters(schema, nop, nitem, new)
            for key in sorted(opar, key=str):
                where = f"{element} {key[0]}:{key[1]}"
                if key not in npar:
                    f = Finding("api", where, "removed", "parameter removed")
                    f.exempt = exempt
                    findings.append(f)
                    continue
                if npar[key].get("required") and not opar[key].get("required"):
                    f = Finding("api", where, "required", "parameter now required")
                    f.exempt = exempt
                    findings.append(f)
                schema.compare(opar[key].get("schema", {}), npar[key].get("schema", {}), [where], exempt)
            for key in sorted(set(npar) - set(opar), key=str):
                if npar[key].get("required"):
                    f = Finding("api", f"{element} {key[0]}:{key[1]}", "required", "new required parameter")
                    f.exempt = exempt
                    findings.append(f)
            # Request body (input).
            obody = resolve(oop.get("requestBody", {}), old)
            nbody = resolve(nop.get("requestBody", {}), new)
            if nbody.get("required") and not obody.get("required"):
                f = Finding("api", f"{element} request", "required", "a request body is now required")
                f.exempt = exempt
                findings.append(f)
            for media in sorted(obody.get("content", {})):
                ncontent = nbody.get("content", {})
                if media not in ncontent:
                    f = Finding("api", f"{element} request {media}", "removed", "media type no longer accepted")
                    f.exempt = exempt
                    findings.append(f)
                    continue
                schema.direction = "input"
                schema.compare(obody["content"][media].get("schema", {}), ncontent[media].get("schema", {}), [f"{element} request"], exempt)
            # Responses (output).
            oresp, nresp = oop.get("responses", {}), nop.get("responses", {})
            for status in sorted(oresp):
                if status not in nresp:
                    f = Finding("api", f"{element} {status}", "status", f"status {status} no longer answered")
                    f.exempt = exempt
                    findings.append(f)
                    continue
                ores, nres = resolve(oresp[status], old), resolve(nresp[status], new)
                for media in sorted(ores.get("content", {})):
                    ncontent = nres.get("content", {})
                    if media not in ncontent:
                        f = Finding("api", f"{element} {status} {media}", "removed", "media type no longer answered")
                        f.exempt = exempt
                        findings.append(f)
                        continue
                    schema.direction = "output"
                    schema.compare(ores["content"][media].get("schema", {}), ncontent[media].get("schema", {}), [f"{element} {status}"], exempt)
                    schema.direction = "input"
            # Security: every old way to call it must still work with no more than it needed.
            osec = security_sets(oop, old)
            nsec = security_sets(nop, new)
            for alternative in osec:
                if not any(n <= alternative for n in nsec):
                    names = ", ".join(sorted(alternative)) or "no authentication"
                    f = Finding("api", element, "security", f"a caller using {names} is no longer accepted")
                    f.exempt = exempt
                    findings.append(f)
    findings.extend(schema.findings)
    return findings


def parameters(schema, op, item, root):
    out = {}
    for p in item.get("parameters", []) + op.get("parameters", []):
        p = schema.resolve(p, root)[0]
        out[(p.get("in"), p.get("name"))] = p
    return out


def security_sets(op, root):
    sec = op.get("security", root.get("security", []))
    if not sec:
        return [frozenset()]
    out = []
    for requirement in sec:
        names = set()
        for scheme, scopes in requirement.items():
            names.add(scheme)
            names.update(f"{scheme}:{s}" for s in scopes)
        out.append(frozenset(names))
    return out


# --- Snapshot differs ---------------------------------------------------------------------------


def below_stable(entry):
    level = (entry or {}).get("maturity", "stable")
    if level != "stable":
        return f"{level} ({entry.get('feature', 'below stable')})"
    return None


def diff_metrics(old, new, ctx):
    findings = []
    om, nm = old.get("metrics", {}), new.get("metrics", {})
    for name in sorted(om):
        o = om[name]
        n = nm.get(name)
        exempt = below_stable(n) or below_stable(o)
        fs = []
        if n is None:
            fs.append(Finding("metrics", name, "removed", "metric removed (or renamed)"))
        else:
            for key, what in (("type", "type"), ("unit", "unit"), ("buckets", "buckets")):
                if canon(o.get(key)) != canon(n.get(key)):
                    fs.append(Finding("metrics", name, "type", f"{what} {canon(o.get(key))} → {canon(n.get(key))}"))
            olab, nlab = set(o.get("labels", [])), set(n.get("labels", []))
            for label in sorted(olab - nlab):
                fs.append(Finding("metrics", f"{name}{{{label}}}", "label", "label removed (or renamed)"))
            for label in sorted(nlab - olab):
                fs.append(Finding("metrics", f"{name}{{{label}}}", "label", "label added to an existing metric"))
        for f in fs:
            f.exempt = exempt
        findings.extend(fs)
    return findings


def diff_cli(old, new, ctx):
    findings = []
    oc, nc = old.get("commands", {}), new.get("commands", {})
    for path in sorted(oc):
        o, n = oc[path], nc.get(path)
        exempt = below_stable(n) or below_stable(o)
        if n is None:
            f = Finding("cli", path, "removed", "command removed (or renamed)")
            f.exempt = exempt
            findings.append(f)
            continue
        oargs, nargs = o.get("args", {}), n.get("args", {})
        fs = []
        for name in sorted(oargs):
            a, b = oargs[name], nargs.get(name)
            element = f"{path} {name}"
            if b is None:
                fs.append(Finding("cli", element, "removed", "flag removed (or renamed)"))
                continue
            if a.get("env") and a.get("env") != b.get("env"):
                fs.append(Finding("cli", element, "removed", f"no longer reads {a['env']}" + (f" (reads {b['env']})" if b.get("env") else "")))
            if a.get("defaults") != b.get("defaults"):
                fs.append(Finding("cli", element, "default", f"default {a.get('defaults')} → {b.get('defaults')}"))
            if a.get("short") and a.get("short") != b.get("short"):
                fs.append(Finding("cli", element, "removed", f"short form {a['short']} removed"))
            if a.get("takes_value") != b.get("takes_value"):
                fs.append(Finding("cli", element, "refused", "takes a value" if b.get("takes_value") else "no longer takes a value"))
            if b.get("required") and not a.get("required"):
                fs.append(Finding("cli", element, "required", "now required"))
            if a.get("multiple") and not b.get("multiple"):
                fs.append(Finding("cli", element, "refused", "no longer repeatable"))
            oldp, newp = set(a.get("possible_values", [])), set(b.get("possible_values", []))
            if oldp and newp:
                for value in sorted(oldp - newp):
                    fs.append(Finding("cli", f"{element}={value}", "enum", "value no longer accepted"))
            elif not oldp and newp:
                fs.append(Finding("cli", element, "refused", f"restricted to {sorted(newp)}"))
            for alias in sorted(set(a.get("aliases", [])) - set(b.get("aliases", []))):
                fs.append(Finding("cli", f"{path} {alias}", "removed", "alias removed"))
        for name in sorted(set(nargs) - set(oargs)):
            if nargs[name].get("required"):
                fs.append(Finding("cli", f"{path} {name}", "required", "new required argument"))
        for f in fs:
            f.exempt = exempt
        findings.extend(fs)
    oe, ne = old.get("exit_codes", {}), new.get("exit_codes", {})
    for code in sorted(oe):
        if code not in ne:
            findings.append(Finding("cli", f"exit code {code}", "exit", "no longer documented"))
        elif oe[code] != ne[code]:
            findings.append(Finding("cli", f"exit code {code}", "exit", f"meaning {oe[code]!r} → {ne[code]!r}", "review"))
    oo, no = old.get("json_outputs", {}), new.get("json_outputs", {})
    for name in sorted(oo):
        if name not in no:
            findings.append(Finding("cli", name, "type", "JSON output removed"))
            continue
        a, b = oo[name], no[name]
        if "x-rdock-openapi" in a or "x-rdock-openapi" in b:
            if a.get("x-rdock-openapi") != b.get("x-rdock-openapi"):
                findings.append(Finding("cli", name, "review", f"prints {a.get('x-rdock-openapi')} → {b.get('x-rdock-openapi')}", "review"))
            continue
        for f in diff_schema("cli", a, b, ctx, "output"):
            f.element = f"{name}: {f.element}"
            findings.append(f)
    return findings


def diff_access_log(old, new, ctx):
    return diff_schema("access-log", old.get("schema", {}), new.get("schema", {}), ctx, "output")


def diff_problems(old, new, ctx):
    findings = []
    op, np_ = old.get("problems", {}), new.get("problems", {})
    for uri in sorted(op):
        exempt = below_stable(np_.get(uri)) or below_stable(op[uri])
        if uri not in np_:
            f = Finding("problems", uri, "removed", "problem type removed")
        elif op[uri].get("status") != np_[uri].get("status"):
            f = Finding("problems", uri, "status", f"status {op[uri].get('status')} → {np_[uri].get('status')}")
        else:
            continue
        f.exempt = exempt
        findings.append(f)
    return findings


def diff_env(old, new, ctx):
    findings = []
    ov, nv = old.get("variables", {}), new.get("variables", {})
    for name in sorted(ov):
        if name not in nv:
            f = Finding("env", name, "removed", "variable no longer read (or renamed)")
            f.exempt = below_stable(ov[name])
            findings.append(f)
    return findings


def diff_labels(old, new, ctx):
    findings = []
    on, nn = old.get("native", {}), new.get("native", {})
    for key in ("labels", "sections"):
        for item in sorted(set(on.get(key, [])) - set(nn.get(key, []))):
            label = item if key == "labels" else f"rdock.{item}.<name>.<field>"
            findings.append(Finding("labels", label, "removed", "label no longer read"))
    ot = set(old.get("traefik", {}).get("labels", []))
    nt = set(new.get("traefik", {}).get("labels", []))
    for label in sorted(ot - nt):
        findings.append(Finding("traefik", label, "removed", "no longer translated without a warning (or no fixture covers it)"))
    return findings


def diff_image(old, new, ctx):
    findings = []
    for key in ("entrypoint", "cmd", "user", "uid", "data_path", "healthcheck", "stopsignal", "workdir"):
        if canon(old.get(key)) != canon(new.get(key)):
            findings.append(Finding("image", key, "changed", f"{canon(old.get(key))} → {canon(new.get(key))}"))
    for port in sorted(set(old.get("exposed_ports", [])) - set(new.get("exposed_ports", []))):
        findings.append(Finding("image", f"exposed_ports {port}", "changed", "port no longer exposed"))
    return findings


SNAPSHOT_DIFFERS = {
    "cli": diff_cli,
    "metrics": diff_metrics,
    "access-log": diff_access_log,
    "problems": diff_problems,
    "env": diff_env,
    "labels": diff_labels,
    "image": diff_image,
}


# --- The image contract -------------------------------------------------------------------------


def dockerfile_contract(text):
    """The final stage's contract: entrypoint, command, user, ports, health check, data path."""
    lines = []
    current = ""
    for raw in text.splitlines():
        stripped = raw.strip()
        if not current and (not stripped or stripped.startswith("#")):
            continue
        if stripped.endswith("\\"):
            current += stripped[:-1] + " "
            continue
        lines.append((current + stripped).strip())
        current = ""
    stage = []
    for line in lines:
        if line.split(" ", 1)[0].upper() == "FROM":
            stage = []
        stage.append(line)
    out = {"exposed_ports": [], "user": None, "uid": None, "entrypoint": None, "cmd": None, "healthcheck": None, "data_path": None}
    for line in stage:
        word, _, rest = line.partition(" ")
        word = word.upper()
        rest = rest.strip()
        if word == "USER":
            out["user"] = rest
        elif word == "EXPOSE":
            out["exposed_ports"].extend(sorted(rest.split()))
        elif word in ("ENTRYPOINT", "CMD"):
            out["entrypoint" if word == "ENTRYPOINT" else "cmd"] = exec_form(rest)
        elif word == "HEALTHCHECK":
            options, _, command = rest.partition(" CMD ")
            out["healthcheck"] = {
                "options": sorted(options.split()),
                "cmd": exec_form(command.strip()),
            }
        elif word == "STOPSIGNAL":
            out["stopsignal"] = rest
        elif word == "WORKDIR":
            out["workdir"] = rest
        elif word == "COPY" and "--chown=" in rest:
            m = re.search(r"--chown=(\d+):(\d+)", rest)
            if m:
                out["uid"] = int(m.group(1))
                out["data_path"] = shlex.split(rest)[-1]
    out["exposed_ports"] = sorted(set(out["exposed_ports"]), key=lambda p: (len(p), p))
    return out


def exec_form(text):
    try:
        value = json.loads(text)
        if isinstance(value, list):
            return value
    except json.JSONDecodeError:
        pass
    return ["/bin/sh", "-c", text]


def image_snapshot(root):
    with open(os.path.join(root, "Dockerfile.release"), encoding="utf-8") as fh:
        contract = dockerfile_contract(fh.read())
    doc = {
        "generated_by": "python3 -I scripts/compat.py snapshot image (just compat)",
        "source": "Dockerfile.release, final stage; Dockerfile's final stage must state the same contract",
        "stability": "docs/10-stability.md; compared with the last release tag by scripts/compat.py",
        "surface": "image",
    }
    doc.update(contract)
    return dump(doc)


def dump(value):
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


# --- Git and the baseline -----------------------------------------------------------------------


class GateError(Exception):
    """The gate cannot run (exit 2)."""


def git(root, *args, check=True):
    proc = subprocess.run(["git", "-C", root, *args], capture_output=True, text=True)
    if check and proc.returncode != 0:
        raise GateError(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc


def find_baseline(root, explicit=None):
    if explicit:
        if git(root, "rev-parse", "--verify", "--quiet", f"{explicit}^{{commit}}", check=False).returncode != 0:
            raise GateError(f"the baseline {explicit!r} is not a tag or commit in this clone; fetch tags with `git fetch --tags`")
        return explicit
    proc = git(root, "describe", "--tags", "--abbrev=0", "--match", "v*", "HEAD", check=False)
    if proc.returncode == 0 and proc.stdout.strip():
        return proc.stdout.strip()
    shallow = git(root, "rev-parse", "--is-shallow-repository", check=False).stdout.strip() == "true"
    if shallow:
        raise GateError(
            "this clone is shallow and no release tag (v*) is reachable, so there is nothing to compare with. "
            "Fetch the history and tags: in GitHub Actions `actions/checkout` with `fetch-depth: 0` and `fetch-tags: true`; "
            "locally `git fetch --tags --unshallow`. Or name the baseline with --baseline."
        )
    raise GateError(
        "no release tag matching v* is reachable from HEAD; fetch tags (`git fetch --tags`) or name the baseline with --baseline"
    )


def read_at(root, rev, path):
    proc = git(root, "show", f"{rev}:{path}", check=False)
    if proc.returncode != 0:
        return None
    return proc.stdout


def tree_version(root):
    import tomllib

    with open(os.path.join(root, "Cargo.toml"), "rb") as fh:
        data = tomllib.load(fh)
    version = data.get("workspace", {}).get("package", {}).get("version") or data.get("package", {}).get("version")
    if not version:
        raise GateError("Cargo.toml has no [workspace.package] version")
    return version


# --- Exceptions ---------------------------------------------------------------------------------


def load_exceptions(root):
    """The exceptions file, validated. Returns (entries, errors)."""
    path = os.path.join(root, EXCEPTIONS)
    if not os.path.exists(path):
        return [], []
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        return [], [f"{EXCEPTIONS}: not valid JSON: {exc}"]
    errors = []
    entries = data.get("exceptions") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        return [], [f"{EXCEPTIONS}: needs an `exceptions` list"]
    for i, e in enumerate(entries):
        where = f"{EXCEPTIONS}: exceptions[{i}]"
        if not isinstance(e, dict):
            errors.append(f"{where}: not an object")
            continue
        for key in ("surface", "element", "rule", "reason", "release"):
            if not isinstance(e.get(key), str) or not e.get(key).strip():
                errors.append(f"{where}: `{key}` is missing or empty" + (" (an exception needs a reason a reviewer can check)" if key == "reason" else ""))
        if isinstance(e.get("surface"), str) and e["surface"] and e["surface"] not in SURFACE_IDS:
            errors.append(f"{where}: unknown surface {e['surface']!r} (one of {', '.join(SURFACE_IDS)})")
        if isinstance(e.get("release"), str) and e["release"].strip():
            try:
                parse_version(e["release"])
            except ValueError:
                errors.append(f"{where}: `release` {e['release']!r} is not a version")
        unknown = set(e) - {"surface", "element", "rule", "reason", "release", "reviewed_by", "pr"}
        if unknown:
            errors.append(f"{where}: unknown keys {sorted(unknown)}")
    return (entries if not errors else []), errors


def apply_exceptions(findings, entries, baseline_version):
    """Marks findings an exception accepts; returns (expired entries, unused entries)."""
    expired, used = [], set()
    for i, e in enumerate(entries):
        if not version_lt(baseline_version, e["release"]):
            expired.append(e)
            continue
        for f in findings:
            if f.counts() and f.surface == e["surface"] and f.rule == e["rule"] and (f.element == e["element"] or e["element"] in f.also_at):
                f.excepted = f"exception for {e['release']}: {e['reason']}"
                used.add(i)
    unused = [e for i, e in enumerate(entries) if i not in used and e not in expired]
    return expired, unused


# --- Running the surfaces -----------------------------------------------------------------------


def load_json(text, what):
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise GateError(f"{what}: not valid JSON: {exc}") from exc


def build_context(current_files, baseline_files, version):
    features, deprecations = [], []
    for files in (current_files, baseline_files):
        config = files.get("schema/rdock.v1.json")
        if config:
            doc = json.loads(config)
            if not features:
                features = doc.get("x-rdock-features", [])
            deprecations.extend(doc.get("x-rdock-deprecations", []))
        snap = files.get("schema/compat/deprecations.json")
        if snap:
            deprecations.extend(json.loads(snap).get("deprecations", []))
    return Context(features, deprecations, version)


def run_semver_checks(root, baseline, require):
    """`cargo semver-checks` for rdock-plugin-api against the baseline tag."""
    tool = shutil.which("cargo-semver-checks")
    if tool is None:
        if require:
            raise GateError("cargo-semver-checks is not installed (CI installs it with taiki-e/install-action)")
        return None, "skipped: cargo-semver-checks is not installed"
    proc = subprocess.run(
        ["cargo", "semver-checks", "check-release", "--package", "rdock-plugin-api", "--baseline-rev", baseline],
        cwd=root,
        capture_output=True,
        text=True,
    )
    output = (proc.stdout + proc.stderr).strip()
    if proc.returncode == 0:
        return [], output
    failed = re.findall(r"^\s*--- failure ([a-z0-9_]+): (.*)$", output, flags=re.M)
    if not failed and "no such" in output.lower():
        return None, f"skipped: the baseline has no rdock-plugin-api ({output.splitlines()[-1] if output else ''})"
    findings = [Finding("plugin-sdk", name, "semver", text.rstrip(" -")) for name, text in failed]
    if not findings:
        findings = [Finding("plugin-sdk", "rdock-plugin-api", "review", "cargo-semver-checks failed; see its output", "review")]
    return findings, output


def gather(root, baseline, args):
    """Compares every surface; returns (results, ctx, errors). A result is (surface, findings, note)."""
    errors = []
    current, base = {}, {}
    for s in SURFACES:
        if s["file"]:
            path = os.path.join(root, s["file"])
            if os.path.exists(path):
                with open(path, encoding="utf-8") as fh:
                    current[s["file"]] = fh.read()
            else:
                errors.append(f"{s['file']}: missing; run `just compat` (snapshots) or `just schema`")
            text = read_at(root, baseline, s["file"])
            if text is not None:
                base[s["file"]] = text
    dep = "schema/compat/deprecations.json"
    if os.path.exists(os.path.join(root, dep)):
        with open(os.path.join(root, dep), encoding="utf-8") as fh:
            current[dep] = fh.read()
    else:
        errors.append(f"{dep}: missing; run `just compat`")
    text = read_at(root, baseline, dep)
    if text is not None:
        base[dep] = text
    version = tree_version(root)
    ctx = build_context(current, base, version)
    results = []
    only = set(args.only or [])
    for s in SURFACES:
        if only and s["id"] not in only:
            continue
        if s["kind"] == "semver":
            if args.skip_semver_checks:
                results.append((s, [], "skipped (--skip-semver-checks)"))
                continue
            findings, note = run_semver_checks(root, baseline, args.require_tools)
            if findings is None:
                results.append((s, [], note))
                continue
            level = ctx.feature_level("native-plugins")
            for f in findings:
                if level != "stable":
                    f.exempt = f"{level} (native-plugins)"
            summary = [line.strip() for line in note.splitlines() if " checks: " in line]
            text = "cargo-semver-checks against the baseline: " + (summary[-1] if summary else "see its output")
            results.append((s, findings, text if not findings else None))
            continue
        old_text = base.get(s["file"])
        new_text = current.get(s["file"])
        if new_text is None:
            continue
        if old_text is None and s["id"] == "image":
            # Releases before the snapshot existed: the contract is read from their Dockerfile.
            dockerfile = read_at(root, baseline, "Dockerfile.release")
            if dockerfile is not None:
                old_text = json.dumps(dockerfile_contract(dockerfile))
        if old_text is None:
            results.append((s, [], f"not compared: {baseline} has no {s['file']} (the first release that ships it becomes its baseline)"))
            continue
        old = load_json(old_text, f"{baseline}:{s['file']}")
        new = load_json(new_text, s["file"])
        if s["kind"] == "schema":
            findings = diff_schema(s["id"], old, new, ctx, s["direction"])
        elif s["kind"] == "openapi":
            findings = diff_openapi(old, new, ctx)
        else:
            findings = SNAPSHOT_DIFFERS[s["kind"]](old, new, ctx)
        apply_policy(findings, ctx)
        results.append((s, findings, None))
    return results, ctx, errors


def check_drift(root, rdock=None):
    """Snapshots generated here (and, with `rdock`, by the binary) must match the committed ones."""
    problems = []
    try:
        generated = image_snapshot(root)
    except OSError as exc:
        return [f"schema/compat/image.json: cannot generate: {exc}"]
    path = os.path.join(root, "schema/compat/image.json")
    committed = open(path, encoding="utf-8").read() if os.path.exists(path) else None
    if committed != generated:
        problems.append("schema/compat/image.json is stale; run `just compat` and commit the result")
    dev = os.path.join(root, "Dockerfile")
    if os.path.exists(dev):
        with open(dev, encoding="utf-8") as fh:
            dev_contract = dockerfile_contract(fh.read())
        with open(os.path.join(root, "Dockerfile.release"), encoding="utf-8") as fh:
            release_contract = dockerfile_contract(fh.read())
        if dev_contract != release_contract:
            problems.append(f"Dockerfile and Dockerfile.release state different image contracts: {canon(dev_contract)} vs {canon(release_contract)}")
    if rdock:
        for name in BINARY_SNAPSHOTS:
            proc = subprocess.run([rdock, "schema", "--compat", name], capture_output=True, text=True)
            target = os.path.join(root, "schema/compat", f"{name}.json")
            committed = open(target, encoding="utf-8").read() if os.path.exists(target) else None
            if proc.returncode != 0:
                problems.append(f"{rdock} schema --compat {name} failed: {proc.stderr.strip()}")
            elif proc.stdout != committed:
                problems.append(f"schema/compat/{name}.json is stale; run `just compat` and commit the result")
    return problems


# --- The report ---------------------------------------------------------------------------------


def exception_snippet(f, version):
    return json.dumps(
        {"surface": f.surface, "element": f.element, "rule": f.rule, "reason": "<why this break is acceptable>", "release": next_release(version)},
        ensure_ascii=False,
    )


def next_release(version):
    """The release a change in this tree ships in: the version without its pre-release part."""
    return version.split("-", 1)[0]


def render(results, ctx, baseline, mode, version, errors, expired, unused, verbose=False, forced=False):
    lines = []
    reason = "forced by --mode or RDOCK_COMPAT_MODE" if forced else (
        f"the promise is in force from {ENFORCE_FROM}" if mode == "report" else f"the tree is at or past {ENFORCE_FROM}"
    )
    lines.append(f"compat: baseline {baseline}, tree {version}, mode {mode} ({reason})")
    lines.append("")
    failing = []
    for s, findings, note in results:
        counted = [f for f in findings if f.counts()]
        exempt = [f for f in findings if f.exempt]
        excepted = [f for f in findings if f.excepted]
        title = f"{s['id']}" + (f" ({s['file']})" if s["file"] else "")
        if note and not findings:
            lines.append(f"{title}: {note}")
            continue
        breaking = sum(1 for f in counted if f.kind == "breaking")
        review = sum(1 for f in counted if f.kind == "review")
        lines.append(
            f"{title}: {breaking} breaking, {review} need review, {len(exempt)} exempt (below stable or deprecated), {len(excepted)} accepted by exceptions"
        )
        for f in counted:
            failing.append(f)
            label = "BREAKING" if f.kind == "breaking" else "REVIEW  "
            lines.append(f"  {label} {f.element}")
            lines.append(f"           {f.detail}")
            lines.append(f"           breaks {STABILITY} §2, {ROWS.get(f.surface, f.surface)}: \"{f.rule_text()}\"")
            if f.also_at:
                shown = ", ".join(f.also_at[:3]) + (f" and {len(f.also_at) - 3} more" if len(f.also_at) > 3 else "")
                lines.append(f"           also at {shown}")
            if f.hint:
                lines.append(f"           note: {f.hint}")
        if verbose:
            for f in exempt + excepted:
                lines.append(f"  ok       {f.element}: {f.detail} [{f.exempt or f.excepted}]")
    for e in expired:
        lines.append(f"note: the exception for {e['surface']} {e['element']} ({e['rule']}, release {e['release']}) has expired with baseline {baseline}; remove it")
    for e in unused:
        lines.append(f"note: the exception for {e['surface']} {e['element']} ({e['rule']}) matches no finding; remove it if the change is gone")
    if errors:
        lines.append("")
        lines.append("errors (fail in every mode):")
        lines.extend(f"  {e}" for e in errors)
    if failing:
        lines.append("")
        lines.append(f"{len(failing)} finding(s) break the stability promise ({STABILITY}). How to proceed:")
        lines.append("  1. Keep the old form working: add the new element next to the old one instead of changing it.")
        lines.append("  2. Or deprecate first: add the old element to crates/rdock-model/src/deprecation.rs (REGISTRY) with its")
        lines.append("     replacement; it may be removed in the next major once its period is over (§4).")
        lines.append("  3. Or, when the break is intended and reviewed (a security fix under §5, a beta feature mislabelled),")
        lines.append(f"     record an exception in {EXCEPTIONS} with a reason, for example:")
        for f in failing[:3]:
            lines.append(f"       {exception_snippet(f, version)}")
        if mode == "report":
            lines.append(f"  Report mode: this does not fail the job until the tree reaches {ENFORCE_FROM}.")
    return "\n".join(lines) + "\n", failing


def write_summary(text):
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    try:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write("## Compatibility gate\n\n```text\n" + text + "```\n")
    except OSError:
        pass


def cmd_check(args):
    root = os.path.abspath(args.root)
    try:
        version = tree_version(root)
        baseline = find_baseline(root, args.baseline or os.environ.get("RDOCK_COMPAT_BASELINE"))
        forced = args.mode or os.environ.get("RDOCK_COMPAT_MODE")
        if forced and forced not in ("report", "enforce"):
            raise GateError(f"mode {forced!r} is not `report` or `enforce`")
        mode = forced or ("enforce" if version_ge(version, ENFORCE_FROM) else "report")
        try:
            baseline_version = baseline
            parse_version(baseline_version)
        except ValueError:
            baseline_version = "0.0.0"
        entries, errors = load_exceptions(root)
        errors = list(errors) + check_drift(root, args.rdock)
        results, ctx, gather_errors = gather(root, baseline, args)
        errors.extend(gather_errors)
    except GateError as exc:
        print(f"compat: error: {exc}", file=sys.stderr)
        return 2
    all_findings = [f for _, fs, _ in results for f in fs]
    expired, unused = apply_exceptions(all_findings, entries, baseline_version)
    text, failing = render(results, ctx, baseline, mode, version, errors, expired, unused, args.verbose, bool(forced))
    sys.stdout.write(text)
    write_summary(text)
    if args.json:
        report = {
            "baseline": baseline,
            "tree_version": version,
            "mode": mode,
            "errors": errors,
            "surfaces": [
                {"surface": s["id"], "file": s["file"], "note": note, "findings": [f.as_dict() for f in fs]} for s, fs, note in results
            ],
        }
        with open(args.json, "w", encoding="utf-8") as fh:
            fh.write(dump(report))
    if errors:
        return 1
    if failing and mode == "enforce":
        return 1
    return 0


def cmd_snapshot(args):
    root = os.path.abspath(args.root)
    if args.surface == "image":
        sys.stdout.write(image_snapshot(root))
        return 0
    print(f"compat: unknown snapshot {args.surface!r}", file=sys.stderr)
    return 2


def cmd_diff(args):
    with open(args.old, encoding="utf-8") as fh:
        old = json.load(fh)
    with open(args.new, encoding="utf-8") as fh:
        new = json.load(fh)
    ctx = Context(new.get("x-rdock-features", []) or old.get("x-rdock-features", []), [], "0.0.0")
    findings = diff_openapi(old, new, ctx) if "openapi" in old else diff_schema(args.surface, old, new, ctx, args.direction)
    for f in findings:
        status = f"[{f.exempt}]" if f.exempt else ""
        print(f"{f.kind:9} {f.element}: {f.detail} {status}".rstrip())
    return 1 if any(f.counts() for f in findings) else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--root", default=os.path.dirname(os.path.dirname(os.path.abspath(__file__))), help="repository root")
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check", help="compare every surface with the baseline tag")
    check.add_argument("--baseline", help="tag or commit to compare with (default: newest v* tag reachable from HEAD)")
    check.add_argument("--mode", choices=["report", "enforce"], help="force a mode (also RDOCK_COMPAT_MODE)")
    check.add_argument("--rdock", help="an rdock binary: also check the snapshots it prints for drift")
    check.add_argument("--only", action="append", choices=[s["id"] for s in SURFACES], help="compare only this surface (repeatable)")
    check.add_argument("--require-tools", action="store_true", help="fail when cargo-semver-checks is missing (CI)")
    check.add_argument("--skip-semver-checks", action="store_true", help="do not run cargo-semver-checks")
    check.add_argument("--json", help="also write the findings as JSON to this file")
    check.add_argument("--verbose", action="store_true", help="also list exempt and accepted findings")
    check.set_defaults(func=cmd_check)
    snap = sub.add_parser("snapshot", help="print a snapshot generated by this script")
    snap.add_argument("surface", choices=["image"])
    snap.set_defaults(func=cmd_snapshot)
    diff = sub.add_parser("diff", help="compare two JSON Schema (or OpenAPI) files")
    diff.add_argument("old")
    diff.add_argument("new")
    diff.add_argument("--direction", choices=["input", "output"], default="input")
    diff.add_argument("--surface", default="config", choices=SURFACE_IDS)
    diff.set_defaults(func=cmd_diff)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
