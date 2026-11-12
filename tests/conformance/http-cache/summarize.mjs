// Summarises a result file of http-tests/cache-tests (see README.md). Informational: it prints a
// Markdown report to standard output and, when set, appends it to $GITHUB_STEP_SUMMARY, and it
// always exits 0 (a malformed or missing file is reported, not failed).
//
//   node summarize.mjs <results.json> [<cache-tests checkout>] [<suite exit code>]
//
// Format assumptions (read from the suite's test-engine/lib/results.mjs and cli.mjs on 2026-11-12,
// never run here; only CI confirms them):
//  1. The file is one JSON object: test id -> result, plus a reserved "_traces" key.
//  2. A result is `true`, or an array `[name, detail]` for a test that did not pass: "Setup"
//     (detail "retry" for a retried request), "Assertion" for a failed expectation, or another
//     error name such as "AbortError" for a request the harness could not complete (seen in the
//     first CI run, 2026-11-12).
//  3. The checkout's tests/index.mjs default-exports the list of suites, each `{ name, tests }`
//     and each test `{ id, name, kind, depends_on }`; kind is "required" (also when unset),
//     "optimal" or "check". The classification below mirrors determineTestResult(); when the
//     checkout cannot be imported the report falls back to raw counts without sections.
import { appendFileSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { pathToFileURL } from 'node:url'

const [file, suiteDir, exitCode] = process.argv.slice(2)
const MAX_LISTED = 300

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
    out.push(`The suite's command exited with status ${cell(exitCode)}. Informational only.`, '')
  }
  let text
  try {
    text = readFileSync(file, 'utf8')
  } catch (error) {
    out.push(`No result file (${cell(file)}): ${cell(error?.message)}.`)
    return out
  }
  let all
  try {
    all = JSON.parse(text)
  } catch (error) {
    out.push(`The result file is not JSON: ${cell(error?.message)}.`)
    return out
  }
  if (all === null || typeof all !== 'object' || Array.isArray(all)) {
    out.push('The result file is not a JSON object.')
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
    return out
  }

  const rows = []
  const total = { name: 'Total', counts: {} }
  const failed = []
  const known = new Set()
  suites.forEach((suite, index) => {
    const row = { name: suite.name ?? suite.id ?? `suite ${index + 1}`, counts: {} }
    for (const test of suite.tests) {
      known.add(test.id)
      const result = classify(test, results)
      row.counts[result] = (row.counts[result] || 0) + 1
      total.counts[result] = (total.counts[result] || 0) + 1
      if (result === 'fail') failed.push({ section: row.name, id: test.id, name: test.name })
    }
    rows.push(row)
  })
  const stray = Object.keys(results).filter((id) => !known.has(id)).length
  out.push(...table([...rows, total]), '')
  if (stray) out.push(`${stray} result keys match no test of this revision of the suite.`, '')
  out.push(
    '`FAIL (required)` is a test of kind "required" that failed (a likely RFC 9111 conformance ' +
    'problem). `optional fail` is behaviour the RFC does not require. `check` tests only record ' +
    'what the cache does. This report never fails the job.', ''
  )
  out.push(`### Failed required tests (${failed.length})`, '')
  if (failed.length === 0) out.push('None.')
  for (const item of failed.slice(0, MAX_LISTED)) {
    out.push(`- ${cell(item.section)}: \`${cell(item.id)}\` ${cell(item.name)}`)
  }
  if (failed.length > MAX_LISTED) out.push(`- ... and ${failed.length - MAX_LISTED} more (see the artifact).`)
  return out
}

let report
try {
  report = (await build()).join('\n') + '\n'
} catch (error) {
  report = `## HTTP cache conformance\n\nThe summary failed: ${cell(error?.message ?? error)}\n`
}
process.stdout.write(report)
if (process.env.GITHUB_STEP_SUMMARY) {
  try { appendFileSync(process.env.GITHUB_STEP_SUMMARY, report) } catch { /* informational */ }
}
process.exitCode = 0
