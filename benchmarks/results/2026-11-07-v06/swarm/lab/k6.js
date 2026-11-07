// Steady load across the swarm nodes; every non-200 counts.
import http from "k6/http";
import { Counter } from "k6/metrics";
const bad = new Counter("bad_status");
const targets = __ENV.TARGETS.split(",");
export const options = {
  discardResponseBodies: true,
  scenarios: { steady: { executor: "constant-arrival-rate", rate: Number(__ENV.RATE || 300), timeUnit: "1s",
    duration: __ENV.DURATION || "60s", preAllocatedVUs: 50, maxVUs: 400 } },
};
export default function () {
  const t = targets[__ITER % targets.length];
  const r = http.get(`http://${t}/`, { headers: { Host: "shop.test" }, timeout: "5s" });
  if (r.status !== 200) bad.add(1, { status: String(r.status), node: t });
}
