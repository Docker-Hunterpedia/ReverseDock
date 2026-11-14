#!/usr/bin/env python3
"""Tests of scripts/compat.py: every differ on small before/after documents, the exceptions,
the modes, and the whole gate end to end in a temporary git repository.

Run: python3 -I scripts/test_compat.py   (standard library only; needs git)
"""

import copy
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "compat.py")
_spec = importlib.util.spec_from_file_location("compat", SCRIPT)
compat = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(compat)

CTX = compat.Context([], [], "1.2.0")


def schema(props, required=(), **extra):
    node = {"type": "object", "properties": props, "additionalProperties": False}
    if required:
        node["required"] = list(required)
    node.update(extra)
    return node


def diff(old, new, direction="input", ctx=CTX, surface="config"):
    findings = compat.diff_schema(surface, old, new, ctx, direction)
    compat.apply_policy(findings, ctx)
    return findings


def counted(findings):
    return [(f.element, f.rule, f.kind) for f in findings if f.counts()]


class SchemaInputTests(unittest.TestCase):
    """The configuration file, Helm values and API requests: the user writes, we read."""

    base = schema(
        {
            "name": {"type": "string"},
            "port": {"type": "integer", "minimum": 1, "maximum": 65535, "default": 80},
            "mode": {"type": "string", "enum": ["a", "b"]},
            "tags": {"type": "array", "items": {"type": "string"}},
        },
        required=["name"],
    )

    def changed(self, mutate, direction="input"):
        new = copy.deepcopy(self.base)
        mutate(new)
        return counted(diff(self.base, new, direction))

    def test_identical_documents_have_no_findings(self):
        self.assertEqual(counted(diff(self.base, copy.deepcopy(self.base))), [])

    def test_a_removed_or_renamed_key_is_breaking(self):
        def rename(n):
            n["properties"]["label"] = n["properties"].pop("name")
            n["required"] = ["label"]

        found = self.changed(rename)
        self.assertIn(("name", "removed", "breaking"), found)
        self.assertIn(("label", "required", "breaking"), found)

    def test_a_changed_type_is_breaking_and_a_wider_one_is_not(self):
        self.assertEqual(self.changed(lambda n: n["properties"]["port"].update(type="string")), [("port", "type", "breaking")])
        self.assertEqual(self.changed(lambda n: n["properties"]["port"].update(type=["integer", "string"])), [])
        self.assertEqual(self.changed(lambda n: n["properties"]["port"].update(type="number")), [])

    def test_a_newly_required_key_is_breaking_and_a_new_optional_key_is_not(self):
        self.assertEqual(self.changed(lambda n: n["required"].append("port")), [("port", "required", "breaking")])
        self.assertEqual(self.changed(lambda n: n["properties"].update(extra={"type": "boolean"})), [])

        def new_required(n):
            n["properties"]["token"] = {"type": "string"}
            n["required"].append("token")

        self.assertEqual(self.changed(new_required), [("token", "required", "breaking")])

    def test_a_removed_enum_value_is_breaking_and_a_new_one_is_not(self):
        self.assertEqual(self.changed(lambda n: n["properties"]["mode"].update(enum=["a"])), [("mode=b", "enum", "breaking")])
        self.assertEqual(self.changed(lambda n: n["properties"]["mode"].update(enum=["a", "b", "c"])), [])
        self.assertEqual(self.changed(lambda n: n["properties"]["name"].update(enum=["x"])), [("name", "refused", "breaking")])

    def test_one_of_constants_is_an_enumeration(self):
        old = schema({"m": {"oneOf": [{"type": "string", "const": "a", "description": "A"}, {"type": "string", "const": "b"}]}})
        new = schema({"m": {"oneOf": [{"type": "string", "const": "a", "description": "changed"}]}})
        self.assertEqual(counted(diff(old, new)), [("m=b", "enum", "breaking")])
        newer = schema({"m": {"oneOf": [{"type": "string", "const": "a"}, {"type": "string", "const": "b"}, {"type": "string", "const": "c"}]}})
        self.assertEqual(counted(diff(old, newer)), [])

    def test_tightened_bounds_are_breaking_and_loosened_ones_are_not(self):
        self.assertEqual(self.changed(lambda n: n["properties"]["port"].update(minimum=1024)), [("port", "refused", "breaking")])
        self.assertEqual(self.changed(lambda n: n["properties"]["port"].update(maximum=1000)), [("port", "refused", "breaking")])
        self.assertEqual(self.changed(lambda n: n["properties"]["name"].update(maxLength=10)), [("name", "refused", "breaking")])
        self.assertEqual(self.changed(lambda n: n["properties"]["tags"].update(minItems=1)), [("tags", "refused", "breaking")])
        self.assertEqual(self.changed(lambda n: n["properties"]["port"].update(minimum=0, maximum=70000)), [])
        self.assertEqual(self.changed(lambda n: n["properties"]["port"].pop("maximum")), [])

    def test_patterns_and_formats(self):
        self.assertEqual(self.changed(lambda n: n["properties"]["name"].update(pattern="^[a-z]+$")), [("name", "refused", "breaking")])
        self.assertEqual(self.changed(lambda n: n["properties"]["name"].update(format="uri")), [("name", "refused", "breaking")])
        old = schema({"k": {"type": "string", "pattern": "^(a|b)$"}, "n": {"type": "integer", "format": "uint32"}})
        loosened = schema({"k": {"type": "string", "pattern": "^(a|b|c)$"}, "n": {"type": "integer", "format": "uint64"}})
        self.assertEqual(counted(diff(old, loosened)), [])
        changed = schema({"k": {"type": "string", "pattern": "^[ab]$"}, "n": {"type": "integer", "format": "uint16"}})
        self.assertEqual(
            sorted(counted(diff(old, changed))),
            [("k", "review", "review"), ("n", "refused", "breaking")],
        )

    def test_additional_properties_becoming_false_is_breaking(self):
        old = {"type": "object", "properties": {"a": {"type": "string"}}}
        new = {"type": "object", "properties": {"a": {"type": "string"}}, "additionalProperties": False}
        self.assertEqual(counted(diff(old, new)), [("(root)", "refused", "breaking")])
        self.assertEqual(counted(diff(new, old)), [])

    def test_a_changed_default_is_breaking(self):
        self.assertEqual(self.changed(lambda n: n["properties"]["port"].update(default=8080)), [("port", "default", "breaking")])

    def test_a_default_object_that_gains_keys_is_not_breaking(self):
        old = schema({"s": {"type": "object", "properties": {"a": {"type": "integer"}}, "default": {"a": 1}}})
        new = schema({"s": {"type": "object", "properties": {"a": {"type": "integer"}, "b": {"type": "integer"}}, "default": {"a": 1, "b": 2}}})
        self.assertEqual(counted(diff(old, new)), [])
        changed = copy.deepcopy(new)
        changed["properties"]["s"]["default"]["a"] = 5
        self.assertEqual(counted(diff(old, changed)), [("s", "default", "breaking")])

    def test_descriptions_and_a_new_deprecation_are_not_breaking(self):
        def doc(n):
            n["properties"]["name"]["description"] = "a new text"
            n["properties"]["mode"]["deprecated"] = True
            n["description"] = "root"

        self.assertEqual(self.changed(doc), [])

    def test_refs_are_resolved_and_siblings_count_per_use(self):
        old = {
            "type": "object",
            "properties": {
                "a": {"$ref": "#/$defs/Size", "default": "1KiB"},
                "b": {"$ref": "#/$defs/Size", "default": "2KiB"},
            },
            "$defs": {"Size": {"type": "string"}},
        }
        new = copy.deepcopy(old)
        new["properties"]["b"]["default"] = "4KiB"
        self.assertEqual(counted(diff(old, new)), [("b", "default", "breaking")])
        new = copy.deepcopy(old)
        new["$defs"]["Size"]["type"] = "integer"
        found = diff(old, new)
        self.assertEqual(counted(found), [("a", "type", "breaking"), ("b", "type", "breaking")])

    def test_recursive_definitions_terminate(self):
        old = {"$ref": "#/$defs/Node", "$defs": {"Node": {"type": "object", "properties": {"child": {"$ref": "#/$defs/Node"}, "v": {"type": "string"}}}}}
        new = copy.deepcopy(old)
        new["$defs"]["Node"]["properties"]["v"]["type"] = "integer"
        self.assertEqual(counted(diff(old, new)), [("v", "type", "breaking")])

    def test_tagged_unions_compare_by_variant(self):
        def variant(tag, **props):
            return {"type": "object", "properties": {"type": {"type": "string", "const": tag}, **props}, "required": ["type"], "additionalProperties": False}

        old = {"type": "object", "additionalProperties": {"oneOf": [variant("redirect", to={"type": "string"}), variant("headers")]}}
        new = copy.deepcopy(old)
        new["additionalProperties"]["oneOf"].append(variant("compress"))
        self.assertEqual(counted(diff(old, new)), [])
        new = copy.deepcopy(old)
        del new["additionalProperties"]["oneOf"][1]
        new["additionalProperties"]["oneOf"].append(variant("other"))
        self.assertEqual(counted(diff(old, new)), [("*.type=headers", "enum", "breaking")])
        new = copy.deepcopy(old)
        new["additionalProperties"]["oneOf"][0]["properties"]["to"]["type"] = "integer"
        self.assertEqual(counted(diff(old, new)), [("*.type=redirect.to", "type", "breaking")])

    def test_unclear_unions_need_review(self):
        old = schema({"v": {"anyOf": [{"type": "string", "format": "duration"}, {"type": "string", "format": "uri"}]}})
        new = schema({"v": {"anyOf": [{"type": "string", "format": "date"}, {"type": "string", "pattern": "x"}]}})
        self.assertIn(("v", "review", "review"), counted(diff(old, new)))

    def test_nullable_options(self):
        old = schema({"v": {"anyOf": [{"$ref": "#/$defs/T"}, {"type": "null"}]}}, **{"$defs": {"T": {"type": "string"}}})
        new = schema({"v": {"$ref": "#/$defs/T"}}, **{"$defs": {"T": {"type": "string"}}})
        self.assertEqual(counted(diff(old, new)), [("v", "type", "breaking")])
        self.assertEqual(counted(diff(new, old)), [])

    def test_unhandled_keywords_need_review(self):
        old = schema({"v": {"type": "string"}})
        new = schema({"v": {"type": "string", "not": {"const": "x"}}})
        self.assertEqual(counted(diff(old, new)), [("v", "review", "review")])

    def test_elements_below_stable_are_exempt(self):
        old = schema({"cache": {"type": "object", "x-rdock-maturity": "beta", "x-rdock-feature": "http-cache", "properties": {"size": {"type": "integer"}}}})
        new = schema({"cache": {"type": "object", "x-rdock-maturity": "beta", "x-rdock-feature": "http-cache", "properties": {}}})
        found = diff(old, new)
        self.assertEqual(counted(found), [])
        self.assertEqual(found[0].exempt, "beta (http-cache)")

    def test_the_registry_exempts_locations_the_old_schema_did_not_mark(self):
        ctx = compat.Context([{"id": "wasm", "level": "experimental", "locations": ["middlewares.*.type=wasm"]}], [], "1.2.0")
        variant = {"type": "object", "properties": {"type": {"const": "wasm"}, "module": {"type": "string"}}}
        other = {"type": "object", "properties": {"type": {"const": "headers"}}}
        old = schema({"middlewares": {"type": "object", "additionalProperties": {"oneOf": [variant, other]}}})
        new = schema({"middlewares": {"type": "object", "additionalProperties": {"oneOf": [other, {"type": "object", "properties": {"type": {"const": "x"}}}]}}})
        found = diff(old, new, ctx=ctx)
        self.assertEqual(counted(found), [])
        self.assertTrue(found[0].exempt.startswith("experimental"))

    def test_deprecated_elements_go_only_when_their_removal_release_is_reached(self):
        deprecations = [{"kind": "config_key", "element": "old", "since": "1.0", "removal": "2.0"}]
        old = schema({"old": {"type": "string"}, "new": {"type": "string"}})
        new = schema({"new": {"type": "string"}})
        early = compat.Context([], deprecations, "1.4.0")
        found = diff(old, new, ctx=early)
        self.assertEqual(counted(found), [("old", "removed", "breaking")])
        self.assertIn("may go in 2.0", found[0].hint)
        major = compat.Context([], deprecations, "2.0.0")
        self.assertEqual(counted(diff(old, new, ctx=major)), [])


class SchemaOutputTests(unittest.TestCase):
    """Access log, API responses, JSON output: we write, the user reads."""

    base = schema({"status": {"type": "integer"}, "route": {"type": ["string", "null"]}, "kind": {"type": "string", "enum": ["a"]}}, required=["status", "kind"])

    def changed(self, mutate):
        new = copy.deepcopy(self.base)
        mutate(new)
        return counted(diff(self.base, new, "output", surface="access-log"))

    def test_a_removed_field_is_breaking(self):
        self.assertEqual(self.changed(lambda n: n["properties"].pop("route")), [("route", "removed", "breaking")])

    def test_a_field_that_may_be_absent_now_is_breaking(self):
        self.assertEqual(self.changed(lambda n: n.update(required=["kind"])), [("status", "removed", "breaking")])

    def test_a_wider_type_is_breaking_and_a_narrower_one_is_not(self):
        self.assertEqual(self.changed(lambda n: n["properties"]["status"].update(type="number")), [("status", "type", "breaking")])
        self.assertEqual(self.changed(lambda n: n["properties"]["route"].update(type="string")), [])

    def test_new_fields_and_new_enum_values_are_not_breaking(self):
        def add(n):
            n["properties"]["upstream"] = {"type": "string"}
            n["properties"]["kind"]["enum"].append("b")

        self.assertEqual(self.changed(add), [])


def openapi(paths, schemas=None):
    return {"openapi": "3.1.0", "paths": paths, "components": {"schemas": schemas or {}}}


def op(**extra):
    base = {
        "responses": {"200": {"description": "ok", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Item"}}}}},
        "security": [{"token": []}, {"session": []}],
    }
    base.update(extra)
    return base


class OpenApiTests(unittest.TestCase):
    item = {"type": "object", "properties": {"name": {"type": "string"}, "role": {"type": "string", "enum": ["viewer", "admin"]}}, "required": ["name"]}
    request = {"type": "object", "properties": {"name": {"type": "string"}, "note": {"type": "string"}}, "required": ["name"], "additionalProperties": False}

    def doc(self):
        return openapi(
            {
                "/api/v1/items": {
                    "get": op(parameters=[{"in": "query", "name": "limit", "schema": {"type": "integer"}}]),
                    "post": op(requestBody={"required": True, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ItemRequest"}}}}),
                },
                "/api/v1/cache": {"get": op(**{"x-rdock-maturity": "beta", "x-rdock-feature": "http-cache"})},
            },
            {"Item": copy.deepcopy(self.item), "ItemRequest": copy.deepcopy(self.request), "rdock.Config": {"type": "object"}},
        )

    def changed(self, mutate):
        old, new = self.doc(), self.doc()
        mutate(new)
        findings = compat.diff_openapi(old, new, CTX)
        compat.apply_policy(findings, CTX)
        return counted(findings)

    def test_identical(self):
        self.assertEqual(self.changed(lambda d: None), [])

    def test_removed_paths_and_methods_are_breaking(self):
        self.assertEqual(self.changed(lambda d: d["paths"]["/api/v1/items"].pop("post")), [("POST /api/v1/items", "removed", "breaking")])

        def drop(d):
            del d["paths"]["/api/v1/items"]

        self.assertEqual(sorted(self.changed(drop)), [("GET /api/v1/items", "removed", "breaking"), ("POST /api/v1/items", "removed", "breaking")])

    def test_parameters(self):
        self.assertEqual(self.changed(lambda d: d["paths"]["/api/v1/items"]["get"].update(parameters=[])), [("GET /api/v1/items query:limit", "removed", "breaking")])
        self.assertEqual(
            self.changed(lambda d: d["paths"]["/api/v1/items"]["get"]["parameters"][0].update(required=True)),
            [("GET /api/v1/items query:limit", "required", "breaking")],
        )
        self.assertEqual(
            self.changed(lambda d: d["paths"]["/api/v1/items"]["get"]["parameters"].append({"in": "query", "name": "x", "required": True, "schema": {"type": "string"}})),
            [("GET /api/v1/items query:x", "required", "breaking")],
        )
        self.assertEqual(
            self.changed(lambda d: d["paths"]["/api/v1/items"]["get"]["parameters"].append({"in": "query", "name": "x", "schema": {"type": "string"}})),
            [],
        )

    def test_request_fields(self):
        self.assertEqual(self.changed(lambda d: d["components"]["schemas"]["ItemRequest"]["required"].append("note")), [("POST /api/v1/items request.note", "required", "breaking")])
        self.assertEqual(
            self.changed(lambda d: d["components"]["schemas"]["ItemRequest"]["properties"].update(extra={"type": "string"})),
            [],
        )
        self.assertEqual(self.changed(lambda d: d["components"]["schemas"]["ItemRequest"]["properties"].pop("note")), [("POST /api/v1/items request.note", "removed", "breaking")])

    def test_response_fields_status_codes_and_enums(self):
        found = self.changed(lambda d: d["components"]["schemas"]["Item"]["properties"].pop("role"))
        self.assertEqual(found, [("GET /api/v1/items 200.role", "removed", "breaking")])
        self.assertEqual(self.changed(lambda d: d["components"]["schemas"]["Item"]["properties"]["role"]["enum"].append("operator")), [])
        self.assertEqual(self.changed(lambda d: d["components"]["schemas"]["Item"]["properties"]["name"].update(type="integer")), [("GET /api/v1/items 200.name", "type", "breaking")])

        def status(d):
            r = d["paths"]["/api/v1/items"]["get"]["responses"]
            r["201"] = r.pop("200")

        self.assertEqual(self.changed(status), [("GET /api/v1/items 200", "status", "breaking")])

    def test_security(self):
        self.assertEqual(
            sorted(self.changed(lambda d: d["paths"]["/api/v1/items"]["get"].update(security=[{"token": []}]))),
            [("GET /api/v1/items", "security", "breaking")],
        )
        self.assertEqual(self.changed(lambda d: d["paths"]["/api/v1/items"]["get"].update(security=[])), [])

    def test_operations_below_stable_are_exempt(self):
        self.assertEqual(self.changed(lambda d: d["paths"].pop("/api/v1/cache")), [])

    def test_the_configuration_model_is_left_to_the_schema_check(self):
        def model(d):
            d["components"]["schemas"]["ItemRequest"]["properties"]["config"] = {"$ref": "#/components/schemas/rdock.Config"}

        old, new = self.doc(), self.doc()
        model(old)
        model(new)
        new["components"]["schemas"]["rdock.Config"]["type"] = "string"
        self.assertEqual(counted(compat.diff_openapi(old, new, CTX)), [])


class SnapshotTests(unittest.TestCase):
    def test_metrics(self):
        old = {
            "metrics": {
                "rdock_a_total": {"type": "counter", "unit": "", "help": "A.", "labels": ["route"], "maturity": "stable"},
                "rdock_d_seconds": {"type": "histogram", "unit": "seconds", "help": "D.", "labels": [], "buckets": [0.1, 1.0], "maturity": "stable"},
                "rdock_cache_total": {"type": "counter", "unit": "", "help": "C.", "labels": [], "maturity": "beta", "feature": "http-cache"},
            }
        }

        def run(mutate):
            new = copy.deepcopy(old)
            mutate(new["metrics"])
            return counted(compat.diff_metrics(old, new, CTX))

        self.assertEqual(run(lambda m: m.pop("rdock_a_total")), [("rdock_a_total", "removed", "breaking")])
        self.assertEqual(run(lambda m: m["rdock_a_total"].update(type="gauge")), [("rdock_a_total", "type", "breaking")])
        self.assertEqual(run(lambda m: m["rdock_d_seconds"].update(buckets=[0.5])), [("rdock_d_seconds", "type", "breaking")])
        self.assertEqual(run(lambda m: m["rdock_d_seconds"].update(unit="")), [("rdock_d_seconds", "type", "breaking")])
        self.assertEqual(run(lambda m: m["rdock_a_total"].update(labels=[])), [("rdock_a_total{route}", "label", "breaking")])
        self.assertEqual(run(lambda m: m["rdock_a_total"].update(labels=["route", "service"])), [("rdock_a_total{service}", "label", "breaking")])
        self.assertEqual(run(lambda m: m["rdock_a_total"].update(help="Other words.")), [])
        self.assertEqual(run(lambda m: m.update(rdock_new_total={"type": "counter", "labels": []})), [])
        self.assertEqual(run(lambda m: m.pop("rdock_cache_total")), [])

    def test_cli(self):
        flag = {"takes_value": True, "value_names": ["CONFIG"], "defaults": ["/etc/rdock/rdock.yaml"], "required": False, "multiple": False, "possible_values": [], "env": "RDOCK_CONFIG", "short": "-c"}
        old = {
            "commands": {
                "run": {"args": {"--config": flag, "--format": dict(flag, env=None, short=None, possible_values=["text", "json"], defaults=["text"])}},
                "control": {"args": {}, "maturity": "beta", "feature": "cluster"},
                "control run": {"args": {"--x": flag}, "maturity": "beta", "feature": "cluster"},
            },
            "exit_codes": {"0": "success", "1": "a failed check", "2": "an error"},
            "json_outputs": {"version --json": {"type": "object", "properties": {"version": {"type": "string"}}, "required": ["version"]}},
        }

        def run(mutate):
            new = copy.deepcopy(old)
            mutate(new)
            return counted(compat.diff_cli(old, new, CTX))

        args = lambda d: d["commands"]["run"]["args"]
        self.assertEqual(run(lambda d: d["commands"].pop("run")), [("run", "removed", "breaking")])
        self.assertEqual(run(lambda d: args(d).pop("--config")), [("run --config", "removed", "breaking")])
        self.assertEqual(run(lambda d: args(d)["--config"].update(defaults=["/etc/rdock.yaml"])), [("run --config", "default", "breaking")])
        self.assertEqual(run(lambda d: args(d)["--config"].pop("env")), [("run --config", "removed", "breaking")])
        self.assertEqual(run(lambda d: args(d)["--config"].pop("short")), [("run --config", "removed", "breaking")])
        self.assertEqual(run(lambda d: args(d)["--format"].update(possible_values=["text"])), [("run --format=json", "enum", "breaking")])
        self.assertEqual(run(lambda d: args(d)["--config"].update(value_names=["FILE"])), [])
        self.assertEqual(run(lambda d: args(d).update({"--new": dict(flag, required=False)})), [])
        self.assertEqual(run(lambda d: args(d).update({"--new": dict(flag, required=True)})), [("run --new", "required", "breaking")])
        self.assertEqual(run(lambda d: d["commands"].update(new={"args": {}})), [])
        self.assertEqual(run(lambda d: d["commands"].pop("control run")), [])
        self.assertEqual(run(lambda d: d["exit_codes"].pop("2")), [("exit code 2", "exit", "breaking")])
        self.assertEqual(run(lambda d: d["json_outputs"]["version --json"]["properties"].pop("version")), [("version --json: version", "removed", "breaking")])

    def test_problems_env_labels_image(self):
        old = {"problems": {"u#a": {"status": 400, "maturity": "stable"}, "u#b": {"status": 403, "maturity": "beta"}}}
        new = {"problems": {"u#a": {"status": 422, "maturity": "stable"}}}
        self.assertEqual(counted(compat.diff_problems(old, new, CTX)), [("u#a", "status", "breaking")])
        self.assertEqual(counted(compat.diff_env({"variables": {"RDOCK_LOG": {}}}, {"variables": {}}, CTX)), [("RDOCK_LOG", "removed", "breaking")])
        labels_old = {"native": {"labels": ["rdock.host"], "sections": ["routes"]}, "traefik": {"labels": ["traefik.enable"]}}
        labels_new = {"native": {"labels": [], "sections": ["routes", "udp_routes"]}, "traefik": {"labels": []}}
        self.assertEqual(
            counted(compat.diff_labels(labels_old, labels_new, CTX)),
            [("rdock.host", "removed", "breaking"), ("traefik.enable", "removed", "breaking")],
        )
        image = compat.dockerfile_contract(
            'FROM a AS build\nUSER root\nFROM b\nCOPY --chown=65532:65532 x /var/lib/rdock\nUSER nonroot:nonroot\nEXPOSE 80 443\n'
            'HEALTHCHECK --interval=10s \\\n  CMD ["/usr/local/bin/rdock", "healthcheck"]\nENTRYPOINT ["/usr/local/bin/rdock"]\nCMD ["run"]\n'
        )
        self.assertEqual(image["user"], "nonroot:nonroot")
        self.assertEqual(image["uid"], 65532)
        self.assertEqual(image["exposed_ports"], ["80", "443"])
        self.assertEqual(image["data_path"], "/var/lib/rdock")
        self.assertEqual(image["healthcheck"]["cmd"], ["/usr/local/bin/rdock", "healthcheck"])
        changed = dict(image, exposed_ports=["443"], cmd=["serve"])
        self.assertEqual(
            sorted(counted(compat.diff_image(image, changed, CTX))),
            [("cmd", "changed", "breaking"), ("exposed_ports 80", "changed", "breaking")],
        )


class VersionAndExceptionTests(unittest.TestCase):
    def test_semver_precedence(self):
        order = ["0.8.0-alpha.1", "0.9.0-alpha.1", "0.9.0", "1.0.0-alpha.1", "1.0.0-rc.1", "1.0.0-rc.2", "1.0.0", "1.0.1", "2.0"]
        for a, b in zip(order, order[1:]):
            self.assertTrue(compat.version_lt(a, b), f"{a} < {b}")
        self.assertTrue(compat.version_ge("v1.0.0", "1.0.0"))
        with self.assertRaises(ValueError):
            compat.parse_version("main")

    def finding(self):
        return compat.Finding("config", "listeners.*.tls", "removed", "removed")

    def test_an_exception_accepts_its_finding_until_the_baseline_reaches_its_release(self):
        entry = {"surface": "config", "element": "listeners.*.tls", "rule": "removed", "reason": "security fix", "release": "1.1.0"}
        f = self.finding()
        expired, unused = compat.apply_exceptions([f], [entry], "1.0.0")
        self.assertFalse(f.counts())
        self.assertEqual((expired, unused), ([], []))
        f = self.finding()
        expired, _ = compat.apply_exceptions([f], [entry], "1.1.0")
        self.assertTrue(f.counts())
        self.assertEqual(expired, [entry])
        other = dict(entry, rule="type")
        f = self.finding()
        _, unused = compat.apply_exceptions([f], [other], "1.0.0")
        self.assertTrue(f.counts())
        self.assertEqual(unused, [other])

    def test_an_exception_without_a_reason_is_an_error(self):
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, "schema/compat"))
            with open(os.path.join(root, compat.EXCEPTIONS), "w") as fh:
                json.dump({"exceptions": [{"surface": "config", "element": "x", "rule": "removed", "reason": " ", "release": "1.1.0"}, {"surface": "nope", "element": "x", "rule": "removed", "reason": "r", "release": "soon"}]}, fh)
            entries, errors = compat.load_exceptions(root)
        self.assertEqual(entries, [])
        self.assertTrue(any("`reason` is missing or empty" in e for e in errors), errors)
        self.assertTrue(any("unknown surface" in e for e in errors), errors)
        self.assertTrue(any("is not a version" in e for e in errors), errors)


# --- End to end ---------------------------------------------------------------------------------

CONFIG_V1 = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "listeners": {"type": "object", "additionalProperties": {"$ref": "#/$defs/Listener"}},
        "experimental": {"type": "array", "items": {"type": "string"}},
    },
    "$defs": {
        "Listener": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "address": {"type": "string"},
                "proxy_timeout": {"type": "string", "default": "5s"},
                "http3": {"type": "object", "x-rdock-maturity": "experimental", "x-rdock-feature": "http3", "properties": {"port": {"type": "integer"}}},
            },
            "required": ["address"],
        }
    },
    "x-rdock-features": [{"id": "http3", "level": "experimental", "locations": ["listeners.*.http3"]}],
    "x-rdock-deprecations": [],
}

DOCKERFILE = 'FROM scratch\nCOPY --chown=65532:65532 data /var/lib/rdock\nUSER nonroot:nonroot\nEXPOSE 80 443\nENTRYPOINT ["/usr/local/bin/rdock"]\nCMD ["run"]\n'


def snapshot(surface, **body):
    return compat.dump(dict(surface=surface, **body))


class EndToEndTests(unittest.TestCase):
    """The whole gate in a temporary repository with a tagged baseline."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = os.path.join(self.tmp.name, "repo")
        os.makedirs(self.root)
        self.git("init", "-q", "-b", "main")
        files = {
            "Cargo.toml": '[workspace.package]\nversion = "1.0.0"\n',
            "Dockerfile.release": DOCKERFILE,
            "Dockerfile": "FROM builder AS build\nRUN true\n" + DOCKERFILE,
            "schema/rdock.v1.json": compat.dump(CONFIG_V1),
            "schema/openapi.json": compat.dump(openapi({"/api/v1/status": {"get": op()}}, {"Item": {"type": "object", "properties": {"version": {"type": "string"}}}})),
            "schema/compat/cli.json": snapshot("cli", commands={"run": {"args": {}}}, exit_codes={"0": "success"}, json_outputs={}),
            "schema/compat/metrics.json": snapshot("metrics", metrics={"rdock_http_requests_total": {"type": "counter", "unit": "", "help": "x", "labels": ["route"], "maturity": "stable"}}),
            "schema/compat/access-log.json": snapshot("access-log", schema={"type": "object", "properties": {"status": {"type": "integer"}}, "required": ["status"]}),
            "schema/compat/problems.json": snapshot("problems", problems={}),
            "schema/compat/env.json": snapshot("env", variables={"RDOCK_CONFIG": {"maturity": "stable"}}),
            "schema/compat/labels.json": snapshot("labels", native={"labels": ["rdock.host"], "sections": ["routes"]}, traefik={"labels": ["traefik.enable"]}),
            "schema/compat/deprecations.json": snapshot("deprecations", deprecations=[]),
            "deploy/helm/reversedock/values.schema.json": compat.dump({"type": "object", "properties": {"image": {"type": "string"}}}),
        }
        for path, text in files.items():
            self.write(path, text)
        self.write("schema/compat/image.json", compat.image_snapshot(self.root))
        self.commit("release 1.0.0")
        self.git("tag", "v1.0.0")
        self.write("Cargo.toml", '[workspace.package]\nversion = "1.1.0-dev"\n')

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, path, text):
        full = os.path.join(self.root, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8") as fh:
            fh.write(text)

    def git(self, *args, cwd=None):
        env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.com", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.com", GIT_CONFIG_NOSYSTEM="1", HOME=self.tmp.name)
        return subprocess.run(["git", "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false", *args], cwd=cwd or self.root, env=env, capture_output=True, text=True, check=True)

    def commit(self, message):
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message)

    def gate(self, *extra, mode="enforce", root=None):
        env = {k: v for k, v in os.environ.items() if not k.startswith("RDOCK_COMPAT")}
        if mode:
            env["RDOCK_COMPAT_MODE"] = mode
        env.pop("GITHUB_STEP_SUMMARY", None)
        return subprocess.run(
            [sys.executable, "-I", SCRIPT, "--root", root or self.root, "check", "--skip-semver-checks", *extra],
            capture_output=True,
            text=True,
            env=env,
        )

    def break_the_schema(self):
        config = copy.deepcopy(CONFIG_V1)
        del config["$defs"]["Listener"]["properties"]["proxy_timeout"]
        config["$defs"]["Listener"]["properties"]["http3"]["properties"] = {}
        config["$defs"]["Listener"]["properties"]["upstream_timeout"] = {"type": "string", "default": "5s"}
        self.write("schema/rdock.v1.json", compat.dump(config))
        self.commit("rename proxy_timeout")

    def test_an_unchanged_tree_passes_in_enforce_mode(self):
        self.commit("no change to any surface")
        proc = self.gate()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("baseline v1.0.0", proc.stdout)
        self.assertIn("mode enforce", proc.stdout)

    def test_a_breaking_change_fails_with_a_readable_report(self):
        self.break_the_schema()
        proc = self.gate()
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        out = proc.stdout
        # The element, the rule of docs/10-stability.md it breaks, and how to proceed.
        self.assertIn("BREAKING listeners.*.proxy_timeout", out)
        self.assertIn('Configuration file (schema v1): "Removing or renaming a key"', out)
        self.assertIn("docs/10-stability.md", out)
        self.assertIn("deprecate first", out)
        self.assertIn("crates/rdock-model/src/deprecation.rs", out)
        self.assertIn('"surface": "config", "element": "listeners.*.proxy_timeout", "rule": "removed"', out)
        # The experimental part changed too and does not count.
        self.assertNotIn("BREAKING listeners.*.http3", out)
        self.assertIn("1 exempt", out)

    def test_report_mode_prints_and_passes(self):
        self.break_the_schema()
        proc = self.gate(mode="report")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("BREAKING listeners.*.proxy_timeout", proc.stdout)
        self.assertIn("Report mode", proc.stdout)

    def test_the_mode_follows_the_version(self):
        self.break_the_schema()
        self.write("Cargo.toml", '[workspace.package]\nversion = "0.9.0"\n')
        self.assertEqual(self.gate(mode=None).returncode, 0)
        self.write("Cargo.toml", '[workspace.package]\nversion = "1.0.0-rc.1"\n')
        self.assertEqual(self.gate(mode=None).returncode, 1)

    def test_a_recorded_exception_accepts_the_break(self):
        self.break_the_schema()
        exception = {"surface": "config", "element": "listeners.*.proxy_timeout", "rule": "removed", "reason": "renamed to upstream_timeout; issue #1", "release": "1.1.0"}
        self.write(compat.EXCEPTIONS, compat.dump({"exceptions": [exception]}))
        proc = self.gate()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("1 accepted by exceptions", proc.stdout)
        # Without a reason the file is refused, in report mode too.
        self.write(compat.EXCEPTIONS, compat.dump({"exceptions": [dict(exception, reason="")]}))
        proc = self.gate(mode="report")
        self.assertEqual(proc.returncode, 1, proc.stdout)
        self.assertIn("`reason` is missing or empty", proc.stdout)
        # An exception for a release the baseline has reached has expired.
        self.write(compat.EXCEPTIONS, compat.dump({"exceptions": [dict(exception, release="1.0.0")]}))
        proc = self.gate()
        self.assertEqual(proc.returncode, 1, proc.stdout)
        self.assertIn("has expired", proc.stdout)

    def test_a_stale_snapshot_fails_in_report_mode(self):
        self.write("Dockerfile.release", DOCKERFILE.replace("EXPOSE 80 443", "EXPOSE 443"))
        proc = self.gate(mode="report")
        self.assertEqual(proc.returncode, 1, proc.stdout)
        self.assertIn("schema/compat/image.json is stale", proc.stdout)

    def test_a_shallow_clone_without_tags_is_an_error(self):
        self.commit("work")
        clone = os.path.join(self.tmp.name, "clone")
        self.git("clone", "-q", "--depth", "1", "--no-tags", f"file://{self.root}", clone, cwd=self.tmp.name)
        proc = self.gate(root=clone)
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertIn("shallow", proc.stderr)
        self.assertIn("fetch-depth: 0", proc.stderr)

    def test_the_baseline_is_the_newest_reachable_tag(self):
        self.commit("work")
        self.git("tag", "v1.1.0")
        self.break_the_schema()
        self.git("tag", "v9.0.0", "HEAD")
        self.git("checkout", "-q", "HEAD~1")
        proc = self.gate()
        self.assertIn("baseline v1.1.0", proc.stdout)
        proc = self.gate("--baseline", "v1.0.0")
        self.assertIn("baseline v1.0.0", proc.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=1)
