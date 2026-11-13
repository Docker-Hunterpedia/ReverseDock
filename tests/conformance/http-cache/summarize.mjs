// Summarises a result file of http-tests/cache-tests and applies the gate of ADR-0030 (see
// README.md). It prints a Markdown report to standard output and, when set, appends it to
// $GITHUB_STEP_SUMMARY.
//
//   node summarize.mjs <results.json> <cache-tests checkout> [<suite exit code>] [<allowlist.json>]
//
// Exit status: 0 when every required test passed or is on the allow-list (allowlist.json next to
// this file by default) and no allow-listed test passed; 1 otherwise: a required test failed that
// is not on the list, an entry is stale (its test passed, is not a required test or is not in this
// revision of the suite), or the gate could not be applied (no or malformed result file, suite
// definitions or allow-list). Setup, harness and dependency failures, optional tests and checks
// are printed and never fail the gate.
//
// Format assumptions (read from the suite's test-engine/lib/results.mjs and cli.mjs on 2026-11-12,
// never run here; the first CI run, 2026-11-12, confirmed them):
//  1. The file is one JSON object: test id -> result, plus a reserved "_traces" key.
//  2. A result is `true`, or an array `[name, detail]` for a test that did not pass: "Setup"
//     (detail "retry" for a retried request), "Assertion" for a failed expectation, or another
//     error name such as "AbortError" for a request the harness could not complete.
//  3. The checkout's tests/index.mjs default-exports the list of suites, each `{ name, tests }`
//     and each test `{ id, name, kind, depends_on }`; kind is "required" (also when unset),
//     "optimal" or "check". The classification below mirrors determineTestResult().
import { appendFileSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const [file, suiteDir, exitCode, allowFile] = process.argv.slice(2)
const ALLOWLIST = allowFile ?? fileURLToPath(new URL('allowlist.json', import.meta.url))
const MAX_LISTED = 300

// Set by build(): whether the gate passed, and why not.
const gate = { ok: false, problems: [] }

function loadAllowlist () {
  const parsed = JSON.parse(readFileSync(ALLOWLIST, 'utf8'))
  const tests = parsed?.tests
  if (tests === null || typeof tests !== 'object' || Array.isArray(tests)) {
    throw new Error('no "tests" object')
  }
  for (const [id, reason] of Object.entries(tests)) {
    if (typeof reason !== 'string' || reason.trim() === '') throw new Error(`no reason for ${id}`)
  }
  return tests
}

function cell (value) {
  return String(value ?? '').replace(/\|/g, '\\|').replace(/\r?\n/g, ' ')
}

function normalise (raw) {
  const value = Array.isArray(raw) ? raw[0] : raw
  const detail = Array.isArray(raw) ? raw[1] : undefined
  return { value, detail }
}

// pass | fail | optional_fail | yes | no | setup_fail | retry | harness_fail | dependency_fail
// | untested | unknown
function classify (test, results) {
  const raw = results[test.id]
  if (raw === undefined) return 'untested'
  for (const dep of test.depends_on ?? []) {
    if (normalise(results[dep]).value !== true) return 'dependency_fail'
  }
  let { value, detail } = normalise(raw) // eslint-disable-line prefer-const
  if (value === 'Setup') return detail === 'retry' ? 'retry' : 'setup_fail'
  // A failed test is `[<error name>, <message>]`: "Assertion" for a failed expectation, anything
  // else (for example "AbortError") for a request the harness could not complete.
  if (typeof value === 'string') {
    if (value !== 'Assertion') return 'harness_fail'
    value = false
  }
  if (value !== true && value !== false) return 'unknown'
  const kind = test.kind ?? 'required'
  if (kind === 'check') return value ? 'yes' : 'no'
  if (kind === 'optimal') return value ? 'pass' : 'optional_fail'
  if (kind === 'required') return value ? 'pass' : 'fail'
  return 'unknown'
}

const COLUMNS = [
  ['pass', 'pass'], ['fail', 'FAIL (required)'], ['optional_fail', 'optional fail'],
  ['yes', 'check yes'], ['no', 'check no'],
  ['setup_fail', 'setup fail'], ['harness_fail', 'harness fail'], ['dependency_fail', 'dependency'],
  ['retry', 'retry'], ['untested', 'untested'], ['unknown', 'unknown']
]

function table (rows) {
  const used = COLUMNS.filter(([key]) => rows.some((row) => row.counts[key]))
  const head = ['Section', ...used.map(([, title]) => title)]
  const lines = [`| ${head.join(' | ')} |`, `|${head.map((_, i) => (i ? '---:' : '---')).join('|')}|`]
  for (const row of rows) {
    lines.push(`| ${[cell(row.name), ...used.map(([key]) => row.counts[key] || 0)].join(' | ')} |`)
  }
  return lines
}

async function loadSuites () {
  if (!suiteDir) return null
  try {
    const url = pathToFileURL(resolve(suiteDir, 'tests/index.mjs')).href
    const suites = (await import(url)).default
    if (!Array.isArray(suites) || !suites.every((s) => Array.isArray(s?.tests))) return null
    return suites
  } catch (error) {
    console.error(`summarize: cannot import the suite definitions: ${error?.message ?? error}`)
    return null
  }
}

async function build () {
  const out = ['## HTTP cache conformance (http-tests/cache-tests)', '']
  if (exitCode !== undefined && exitCode !== '0') {
    out.push(`The suite's command exited with status ${cell(exitCode)} (information; the gate reads the results).`, '')
  }
  let allowed
  try {
    allowed = loadAllowlist()
  } catch (error) {
    gate.problems.push(`the allow-list ${ALLOWLIST} is unusable: ${error?.message ?? error}`)
    out.push(`The allow-list (${cell(ALLOWLIST)}) is unusable: ${cell(error?.message ?? error)}.`)
    return out
  }
  let text
  try {
    text = readFileSync(file, 'utf8')
  } catch (error) {
    out.push(`No result file (${cell(file)}): ${cell(error?.message)}.`)
    gate.problems.push('no result file')
    return out
  }
  let all
  try {
    all = JSON.parse(text)
  } catch (error) {
    out.push(`The result file is not JSON: ${cell(error?.message)}.`)
    gate.problems.push('the result file is not JSON')
    return out
  }
  if (all === null || typeof all !== 'object' || Array.isArray(all)) {
    out.push('The result file is not a JSON object.')
    gate.problems.push('the result file is not a JSON object')
    return out
  }
  const { _traces: traces, ...results } = all
  void traces

  const suites = await loadSuites()
  if (!suites) {
    const values = Object.values(results).map((raw) => normalise(raw).value)
    out.push(
      `Suite definitions unavailable: raw counts only (${Object.keys(results).length} results; ` +
      `${values.filter((v) => v === true).length} true, ${values.filter((v) => v === false).length} false, ` +
      `${values.filter((v) => v !== true && v !== false).length} other).`
    )
    gate.problems.push('the suite definitions are unavailable, so required tests are unknown')
    return out
  }

  const rows = []
  const total = { name: 'Total', counts: {} }
  const listed = { fail: [], setup_fail: [], harness_fail: [], dependency_fail: [], retry: [], unknown: [] }
  const tests = new Map()
  const outcome = new Map()
  suites.forEach((suite, index) => {
    const row = { name: suite.name ?? suite.id ?? `suite ${index + 1}`, counts: {} }
    for (const test of suite.tests) {
      const result = classify(test, results)
      tests.set(test.id, test)
      outcome.set(test.id, result)
      row.counts[result] = (row.counts[result] || 0) + 1
      total.counts[result] = (total.counts[result] || 0) + 1
      if (listed[result]) listed[result].push({ section: row.name, id: test.id, name: test.name })
    }
    rows.push(row)
  })
  const stray = Object.keys(results).filter((id) => !tests.has(id)).length
  out.push(...table([...rows, total]), '')
  if (stray) out.push(`${stray} result keys match no test of this revision of the suite.`, '')
  out.push(
    '`FAIL (required)` is a test of kind "required" that failed (a likely RFC 9111 conformance ' +
    'problem). `optional fail` is behaviour the RFC does not require. `check` tests only record ' +
    'what the cache does. Setup, harness and dependency failures are information.', ''
  )

  const unexpected = listed.fail.filter((item) => !(item.id in allowed))
  const expected = listed.fail.filter((item) => item.id in allowed)
  const stale = []
  for (const id of Object.keys(allowed)) {
    const test = tests.get(id)
    if (!test) stale.push({ id, why: 'not a test of this revision of the suite' })
    else if ((test.kind ?? 'required') !== 'required') stale.push({ id, why: `of kind "${test.kind}", not required` })
    else if (outcome.get(id) === 'pass') stale.push({ id, why: 'passes now: remove the entry' })
  }

  const list = (title, items, line) => {
    out.push(`### ${title} (${items.length})`, '')
    if (items.length === 0) out.push('None.')
    for (const item of items.slice(0, MAX_LISTED)) out.push(line(item))
    if (items.length > MAX_LISTED) out.push(`- ... and ${items.length - MAX_LISTED} more (see the artifact).`)
    out.push('')
  }
  const plain = (item) => `- ${cell(item.section)}: \`${cell(item.id)}\` ${cell(item.name)}`
  list('Failed required tests not on the allow-list (fail the gate)', unexpected, plain)
  list('Stale allow-list entries (fail the gate)', stale, (item) => `- \`${cell(item.id)}\`: ${cell(item.why)}`)
  list('Failed required tests on the allow-list', expected,
    (item) => `${plain(item)}<br>${cell(allowed[item.id])}`)
  const notRun = Object.keys(allowed)
    .filter((id) => tests.has(id) && !['pass', 'fail'].includes(outcome.get(id)))
    .map((id) => ({ id, result: outcome.get(id) }))
  if (notRun.length) {
    list('Allow-listed tests that did not run to a result', notRun,
      (item) => `- \`${cell(item.id)}\`: ${cell(item.result)}`)
  }
  list('Harness failures (information)', listed.harness_fail, plain)
  list('Setup failures (information)', listed.setup_fail, plain)
  list('Dependency failures (information)', listed.dependency_fail, plain)
  if (listed.retry.length) list('Retried (information)', listed.retry, plain)
  if (listed.unknown.length) list('Unknown results (information)', listed.unknown, plain)

  gate.ok = unexpected.length === 0 && stale.length === 0
  if (unexpected.length) gate.problems.push(`${unexpected.length} required test(s) failed that are not on the allow-list`)
  if (stale.length) gate.problems.push(`${stale.length} stale allow-list entr${stale.length === 1 ? 'y' : 'ies'}`)
  out.push(gate.ok
    ? '**Gate: passed.** Every required test passed or is on the allow-list with a reason.'
    : `**Gate: FAILED.** ${gate.problems.join('; ')}.`)
  return out
}

let report
try {
  report = (await build()).join('\n') + '\n'
} catch (error) {
  gate.ok = false
  gate.problems.push(`the summary failed: ${error?.message ?? error}`)
  report = `## HTTP cache conformance\n\nThe summary failed: ${cell(error?.message ?? error)}\n`
}
if (!gate.ok && gate.problems.length && !report.includes('**Gate: FAILED.**')) {
  report += `\n**Gate: FAILED.** ${gate.problems.join('; ')}.\n`
}
process.stdout.write(report)
if (process.env.GITHUB_STEP_SUMMARY) {
  try { appendFileSync(process.env.GITHUB_STEP_SUMMARY, report) } catch { /* the report is on stdout too */ }
}
if (!gate.ok) console.error(`summarize: gate failed: ${gate.problems.join('; ')}`)
process.exitCode = gate.ok ? 0 : 1
