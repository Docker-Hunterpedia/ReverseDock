# Grafana dashboard

A Grafana dashboard for ReverseDock: traffic, latency, backends, certificates, reloads and
alerts, built only from the metrics rdock exports at `/metrics`
([reference](../../apps/website/src/content/docs/docs/reference/metrics.mdx)).

| File | What it is |
|---|---|
| `dashboards/rdock.json` | The dashboard, in Grafana's classic JSON model. Uid `rdock-overview`. |
| `provisioning/` | Grafana provisioning: the dashboard folder and, for the example, a Prometheus data source. |
| `prometheus/prometheus.yml` | The scrape job with an API token. |
| `compose.yaml`, `config/` | A local example: rdock, a test backend, Prometheus and Grafana. |

## Import into your Grafana

1. In Grafana: **Dashboards → New → Import**, upload `dashboards/rdock.json`.
2. Pick your Prometheus data source in the dashboard's **Data source** menu. Every panel uses
   that menu, so the dashboard works with any data source name.
3. Filter by **Job**, **Instance**, **Listener**, **Route** and **Service** at the top.

Or provision it: copy `provisioning/dashboards/rdock.yaml` to Grafana's provisioning
directory and the JSON file to the path it names. The fixed uid keeps links stable across
imports. Works with Grafana 11 and later.

Prometheus needs an API token with the `metrics` role to scrape `/metrics`; see
[Scrape with Prometheus](../../apps/website/src/content/docs/docs/guides/logs-and-metrics.mdx).

## Try it with Docker Compose

```sh
cd deploy/grafana
docker compose up -d --build
docker compose exec rdock rdock tokens create prometheus --role metrics --days 365 \
  | head -n 1 > secrets/rdock-token
for i in $(seq 200); do curl -s -o /dev/null http://localhost/; done
```

Open <http://localhost:3000>, log in as `admin` / `admin` and set a new password. The
dashboard is the home page; data appears after the next scrape (15 s).

Prometheus shares rdock's network namespace, so it reaches the admin listener on loopback
(`127.0.0.1:2080`) and the listener needs no TLS. Grafana and Prometheus listen on
`127.0.0.1` only. `secrets/` is ignored by Git. `docker compose down -v` removes everything.

## Changing the dashboard

Edit it in Grafana, export it (**Share → Export**, without "Export for sharing externally"),
and replace `dashboards/rdock.json`. Keep the uid and the `${datasource}` references. A test
(`cargo nextest run -p rdock-observability --test grafana_dashboard`) checks that every
queried metric and label exists in rdock and that no panel names a fixed data source.
