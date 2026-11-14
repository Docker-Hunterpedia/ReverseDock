// Open-model load: requests start at a constant rate whatever the latency, so a slow proxy
// cannot hide its tail by slowing the load down (coordinated omission; see README.md).
import http from 'k6/http';
import { Counter } from 'k6/metrics';

const RATE = Number(__ENV.RATE || 1000);
const DURATION = __ENV.DURATION || '30s';

const HOSTS = Number(__ENV.HOSTS || 0); // `routes` scenario: a different host per request
// `tls-ramped`: reach RATE over RAMP, then hold it for DURATION. Without RAMP the scenario is the
// constant rate the other scenarios use, unchanged.
const RAMP = __ENV.RAMP || '';
// TLS parity check (README "TLS parity"): what the proxy negotiated, read from the response on a
// VU's first iteration and every SAMPLE-th after it, so the cost to the generator stays small.
// EXPECT_PROTO is the HTTP version the scenario must run on ("HTTP/1.1" or "HTTP/2.0"); with
// EXPECT_TLS=1.3 set, the TLS version must be k6's http.TLS_1_3 and the cipher suite
// EXPECT_CIPHER, in Go's naming as k6 reports it (k6 docs "SSL/TLS version and ciphers").
const EXPECT_PROTO = __ENV.EXPECT_PROTO || '';
const EXPECT_TLS = __ENV.EXPECT_TLS === '1.3' ? http.TLS_1_3 : '';
const EXPECT_CIPHER = __ENV.EXPECT_CIPHER || '';
const SAMPLE = 50;
const checked = new Counter('negotiated_checked');
const wrongProto = new Counter('negotiated_wrong_proto');
const wrongTls = new Counter('negotiated_wrong_tls');
const wrongCipher = new Counter('negotiated_wrong_cipher');

const params = { timeout: '10s' };
const VUS = Math.min(2000, Math.max(50, RATE / 20));
const constant = {
  executor: 'constant-arrival-rate',
  rate: RATE,
  timeUnit: '1s',
  duration: DURATION,
  preAllocatedVUs: VUS,
  maxVUs: 4000,
};
const ramped = {
  executor: 'ramping-arrival-rate',
  startRate: Math.ceil(RATE / 100),
  timeUnit: '1s',
  stages: [
    { target: RATE, duration: RAMP },
    { target: RATE, duration: DURATION },
  ],
  preAllocatedVUs: VUS,
  maxVUs: 4000,
};

export const options = {
  discardResponseBodies: true,
  insecureSkipTLSVerify: true, // the `tls` scenarios use a throwaway certificate
  noConnectionReuse: __ENV.NEW_CONNECTIONS === '1', // `tls-new`: a handshake for every request
  scenarios: { constant: RAMP ? ramped : constant },
  summaryTrendStats: ['min', 'med', 'p(90)', 'p(99)', 'p(99.9)', 'max'],
};

export default function () {
  if (HOSTS > 0) params.headers = { Host: `site${__ITER % HOSTS}.test` };
  const res = http.get(__ENV.TARGET, params);
  if (EXPECT_PROTO && res.status !== 0 && __ITER % SAMPLE === 0) {
    checked.add(1);
    if (res.proto !== EXPECT_PROTO) wrongProto.add(1);
    if (EXPECT_TLS && res.tls_version !== EXPECT_TLS) wrongTls.add(1);
    if (EXPECT_CIPHER && res.tls_cipher_suite !== EXPECT_CIPHER) wrongCipher.add(1);
  }
}

function count(data, name) {
  return data.metrics[name] ? data.metrics[name].values.count : 0;
}

export function handleSummary(data) {
  // http_req_duration leaves out connecting and the TLS handshake, which `tls-new` is there to
  // measure; a whole iteration includes them.
  const d = (__ENV.NEW_CONNECTIONS === '1' ? data.metrics.iteration_duration : data.metrics.http_req_duration).values;
  const out = {
    proxy: __ENV.PROXY,
    rate: RATE,
    duration: DURATION,
    requests: data.metrics.http_reqs.values.count,
    achieved_rps: data.metrics.http_reqs.values.rate,
    failed: data.metrics.http_req_failed.values.rate,
    dropped: data.metrics.dropped_iterations ? data.metrics.dropped_iterations.values.count : 0,
    ms: { p50: d.med, p90: d['p(90)'], p99: d['p(99)'], p999: d['p(99.9)'], max: d.max },
  };
  if (EXPECT_PROTO) {
    out.negotiated = {
      expected: { proto: EXPECT_PROTO, tls: EXPECT_TLS || null, cipher: EXPECT_CIPHER || null },
      checked: count(data, 'negotiated_checked'),
      wrong_proto: count(data, 'negotiated_wrong_proto'),
      wrong_tls: count(data, 'negotiated_wrong_tls'),
      wrong_cipher: count(data, 'negotiated_wrong_cipher'),
    };
  }
  return { [`${__ENV.OUT || '/results'}/${__ENV.PROXY}-${RATE}.json`]: JSON.stringify(out, null, 2) };
}
