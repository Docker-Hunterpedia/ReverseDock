# HTTP cache conformance (cache-tests)

[`http-tests/cache-tests`](https://github.com/http-tests/cache-tests) is a public test suite for
HTTP caching ([RFC 9111](https://www.rfc-editor.org/rfc/rfc9111)) by Mark Nottingham. It is a
Node.js project with a test origin server and a client that drives a cache in front of it. It runs
against browsers, CDNs and proxies (nginx, Squid, Varnish, Caddy, HAProxy, Apache, Traffic
Server). This directory runs it against ReverseDock's `cache` middleware
([ADR-0030](../../../docs/decisions/0030-v0-8-cache-extensibility-gateway.md),
[the guide](../../../apps/website/src/content/docs/docs/guides/caching.mdx)).

It is **gated** but **not a required check** yet: the job `http-cache` in
`.github/workflows/cache.yml` fails when a test of kind *required* fails that is not on
[`allowlist.json`](allowlist.json), and when an allow-listed test passes (the entry is stale). A
maintainer adds `http-cache` to the required checks of the "Protect main" ruleset once it has
been stable; until then a red job is a signal, not a merge blocker. The suite describes itself as
not a conformance test suite: besides tests of what RFC 9111 requires it has tests of behaviour
that is merely better (`optimal`) and tests that only record what a cache does (`check`), and no
cache passes all of them. Those, and setup, harness and dependency failures, are printed and
never fail the job. rdock's safe defaults (no default lifetime, no heuristic freshness,
`Set-Cookie` and `Authorization` refused, ADR-0030) make many optional tests fail by design: the
suite's authors expect caches to store responses without explicit freshness. The job also fails
when it cannot run: the build, `rdock validate`, the origin server or rdock not starting, or no
results.

## The gate and the allow-list

[`allowlist.json`](allowlist.json) maps a required test id to the reason it may fail at the safe
defaults: a documented design decision, a test that does not apply, or a known defect (said so,
with where it is tracked). Adding an entry needs that reason in the same pull request; a fix that
makes a listed test pass must remove its entry, or the job fails. An entry whose test is not in
the pinned revision, or is not of kind *required*, also fails the job.

The list on 2026-11-12 (first gated revision): `other-date-update` and
`other-date-update-expires`, a known defect. Pingora 0.9.1 replaces the `Date` header of every
response it writes to a client (`pingora-core` `protocols/http/v1/server.rs` and `v2/server.rs`,
with no setting to turn it off), so a stored response goes out with the current time instead of
the origin's `Date`. It needs an upstream change; `docs/07-roadmap.md` tracks it.

## What the job does

1. Builds `rdock` and validates [`rdock.yaml`](rdock.yaml).
2. Checks out the suite at the pinned revision (below) and installs it with
   `npm install --ignore-scripts` on Node.js 24 (the suite asks for 22.19.0 or later, but its
   command exited with status 13 and no results on 22.19.0).
3. Starts the suite's origin server (`npm run server`, port 8000) and rdock (port 8002, a
   `PathPrefix(`/`)` route with the `cache` middleware at its defaults and a memory store, admin
   listener on loopback), waiting until both answer.
4. Runs `npm run --silent cli --base=http://127.0.0.1:8002/`, which writes the results as JSON to
   standard output, into `results.json`. The exit status is recorded, not propagated.
5. Runs [`summarize.mjs`](summarize.mjs): a table per section (pass, failed required, optional
   fail, check yes/no, setup, harness and dependency failures), the failed required tests outside
   and on the allow-list, stale entries, and the setup, harness and dependency failures, written
   to the step summary. It exits 1 when the gate fails (above) or cannot be applied: no or
   malformed results, suite definitions or allow-list.
6. Uploads the artifact `http-cache-results`: `results.json` (with the suite's `_traces`, the
   requests and responses of every test), `rdock.log`, `origin.log`, `cli.err`, `cli.exit` and
   `summary.md`.

It runs on pull requests that touch the cache, proxy or middleware crates, this directory or the
workflow, weekly, and on demand (`workflow_dispatch`).

## The pinned revision

`CACHE_TESTS_REV` in the `env` block of `.github/workflows/cache.yml` is the full commit of the
suite that was reviewed (the head of `main` on 2026-11-12, "update results"). The suite changes
without releases; move the pin in a pull request after looking at what changed in `tests/`.

## Run it locally

Needs Node.js 24 and a built `rdock` (`cargo build --locked -p rdock`).

```sh
git clone https://github.com/http-tests/cache-tests.git /tmp/cache-tests
git -C /tmp/cache-tests checkout <the revision from the workflow>
(cd /tmp/cache-tests && npm install --ignore-scripts && npm run --silent server &)
RDOCK_DATA_DIR="$(mktemp -d)" target/debug/rdock run --no-watch \
  --config tests/conformance/http-cache/rdock.yaml &
(cd /tmp/cache-tests && npm run --silent cli --base=http://127.0.0.1:8002/ > /tmp/results.json)
node tests/conformance/http-cache/summarize.mjs /tmp/results.json /tmp/cache-tests
echo "gate: $?"
```

One test, with the requests and responses both sides saw (for debugging):
`npm run cli --base=http://127.0.0.1:8002/ --id=<test id>` in the suite's directory. Test ids are
the keys of `results.json`. Results in the suite's own format can be compared with the files in
its `results/` directory (nginx, Varnish, Squid and others).

## Reading the results

Each key of `results.json` is a test id; `_traces` holds what was sent and received.
Kinds of test: **required** (a failure is a likely RFC 9111 problem), **optimal** (a failure is
suboptimal, not a conformance problem), **check** (yes or no, information). A test that depends
on another one shows as a dependency failure when that one did not pass; a setup failure means
the test could not be arranged (often the cache did not store what the test needed stored).
The suite's own FAQ: many grey results usually mean the cache refuses to store responses without
explicit freshness or validators; many blue ones that it refuses `PUT`. Both are rdock's
documented defaults.

A failed required test is a lead, not a verdict: open its trace, compare with the RFC section
the test names, and decide whether it is a bug (fix it, with an e2e test in
`crates/rdock/tests/e2e_cache.rs` that reproduces the suite's case), a documented safe default
(the guide says so, and it goes on the allow-list with that reason) or a test of the suite that
does not apply (allow-list it with the reason).

The tests of RFC 9213 (`CDN-Cache-Control`) apply at the defaults: rdock honours
`CDN-Cache-Control` as its targeted field (`targeted`, see the guide).

## Assumptions the summary makes

`summarize.mjs` reads the format of the suite's `test-engine/lib/results.mjs` as of 2026-11-12: an
object of test id to `true`, `false` or `[value, detail]`, plus `_traces`; it takes sections and
test kinds from the checkout's `tests/index.mjs` and mirrors the suite's `determineTestResult`.
If the checkout cannot be imported it prints raw counts and the gate fails (it cannot tell which
tests are required). Result values it does not understand are counted as `unknown` and listed,
never fatal by themselves.
