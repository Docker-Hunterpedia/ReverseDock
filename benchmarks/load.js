// Open-model load: requests start at a constant rate whatever the latency, so a slow proxy
// cannot hide its tail by slowing the load down (coordinated omission; see README.md).
import http from 'k6/http';

const RATE = Number(__ENV.RATE || 1000);
const DURATION = __ENV.DURATION || '30s';

export const options = {
  discardResponseBodies: true,
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
  http.get(__ENV.TARGET, { timeout: '10s' });
}

export function handleSummary(data) {
  const d = data.metrics.http_req_duration.values;
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
