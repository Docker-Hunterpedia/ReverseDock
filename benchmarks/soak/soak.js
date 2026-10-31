// One window of the soak: a constant rate, alternating plain HTTP and HTTPS, so both listeners
// and TLS handshakes stay busy. run.sh runs consecutive windows to get a time series.
import http from 'k6/http';

const RATE = Number(__ENV.RATE || 1000);
const TARGETS = ['http://rdock:8080/', 'https://rdock:8443/'];

export const options = {
  discardResponseBodies: true,
  insecureSkipTLSVerify: true,
  scenarios: {
    constant: {
      executor: 'constant-arrival-rate',
      rate: RATE,
      timeUnit: '1s',
      duration: __ENV.DURATION || '600s',
      preAllocatedVUs: Math.max(50, RATE / 20),
      maxVUs: 2000,
    },
  },
  summaryTrendStats: ['med', 'p(99)', 'p(99.9)', 'max'],
};

export default function () {
  http.get(TARGETS[__ITER % 2], { timeout: '10s' });
}

export function handleSummary(data) {
  const d = data.metrics.http_req_duration.values;
  const out = {
    window: Number(__ENV.WINDOW_N),
    end: Math.floor(Date.now() / 1000),
    requests: data.metrics.http_reqs.values.count,
    achieved_rps: data.metrics.http_reqs.values.rate,
    failed: data.metrics.http_req_failed.values.rate,
    dropped: data.metrics.dropped_iterations ? data.metrics.dropped_iterations.values.count : 0,
    ms: { p50: d.med, p99: d['p(99)'], p999: d['p(99.9)'], max: d.max },
  };
  return { [`/windows/${String(__ENV.WINDOW_N).padStart(4, '0')}.json`]: JSON.stringify(out, null, 2) };
}
