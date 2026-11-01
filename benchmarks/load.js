// Open-model load: requests start at a constant rate whatever the latency, so a slow proxy
// cannot hide its tail by slowing the load down (coordinated omission; see README.md).
import http from 'k6/http';

const RATE = Number(__ENV.RATE || 1000);
const DURATION = __ENV.DURATION || '30s';

const HOSTS = Number(__ENV.HOSTS || 0); // `routes` scenario: a different host per request
const params = { timeout: '10s' };

export const options = {
  discardResponseBodies: true,
  insecureSkipTLSVerify: true, // the `tls` scenarios use a throwaway certificate
  noConnectionReuse: __ENV.NEW_CONNECTIONS === '1', // `tls-new`: a handshake for every request
  scenarios: {
    constant: {
      executor: 'constant-arrival-rate',
      rate: RATE,
      timeUnit: '1s',
      duration: DURATION,
      preAllocatedVUs: Math.min(2000, Math.max(50, RATE / 20)),
      maxVUs: 4000,
    },
  },
  summaryTrendStats: ['min', 'med', 'p(90)', 'p(99)', 'p(99.9)', 'max'],
};

export default function () {
  if (HOSTS > 0) params.headers = { Host: `site${__ITER % HOSTS}.test` };
  http.get(__ENV.TARGET, params);
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
  return { [`${__ENV.OUT || '/results'}/${__ENV.PROXY}-${RATE}.json`]: JSON.stringify(out, null, 2) };
}
