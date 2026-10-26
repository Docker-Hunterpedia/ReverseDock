import zipfile, re, sys, collections
import xml.etree.ElementTree as ET
path, out = sys.argv[1], sys.argv[2]
z = zipfile.ZipFile(path)
NS = '{http://schemas.openxmlformats.org/spreadsheetml/2006/main}'
ss = [''.join(t.text or '' for t in si.iter(NS+'t')) for si in ET.fromstring(z.read('xl/sharedStrings.xml')).findall(NS+'si')]
def col_idx(ref):
    n = 0
    for ch in re.match(r'[A-Z]+', ref).group(0): n = n*26 + ord(ch)-64
    return n
def rows(sheet):
    sh = ET.fromstring(z.read(f'xl/worksheets/{sheet}.xml'))
    for row in sh.iter(NS+'row'):
        cells = {}
        for c in row.findall(NS+'c'):
            v = c.find(NS+'v'); t = c.get('t'); val = ''
            if v is not None: val = ss[int(v.text)] if t == 's' else v.text
            cells[col_idx(c.get('r'))] = val
        if cells:
            mx = max(cells); yield [cells.get(k,'') for k in range(1, mx+1)]
SYM = {'Native':'✅','Partial':'◐','External':'🔌','Experimental':'🧪','Not native':'—','Build needed':'🛠️'}
def sym(s): return SYM.get(s.strip(), s)
CRATE = {
 'proxy-core':'rdock-proxy','proxy-routing':'rdock-rules + rdock-proxy (router)','proxy-tls':'rdock-tls','proxy-acme':'rdock-acme',
 'proxy-balancer':'rdock-balancer','proxy-health':'rdock-balancer (health)','proxy-retry':'rdock-balancer (retry)',
 'proxy-reliability':'rdock-balancer / rdock-limits','proxy-cache':'rdock-cache (P2)','proxy-middleware':'rdock-middleware',
 'proxy-limits':'rdock-limits','proxy-compression':'rdock-middleware (compress)','proxy-auth':'rdock-middleware (auth)',
 'proxy-security':'rdock-proxy (security) / rdock-limits','proxy-observability':'rdock-observability','proxy-admin':'rdock-admin',
 'proxy-api':'rdock-admin (api)','dashboard':'apps/dashboard','proxy-config':'rdock-config','proxy-cli':'rdock (binary)',
 'proxy-migration':'rdock-migrate','proxy-discovery':'rdock-balancer (dns discovery)','proxy-static':'rdock-middleware (static)',
 'proxy-secrets':'rdock-config (secrets)','proxy-quic':'rdock-proxy (http3 feature)','proxy-plugins':'rdock-plugins (P2/P3)',
 'proxy-l4':'rdock-proxy (l4)','proxy-forward':'unscheduled (F-WEB-05)','proxy-mail':'out of scope (F-WEB-06)',
 'proxy-waf':'external agent via rdock-plugins (P3)','proxy-cloudflare':'rdock-cloudflare','proxy-distributed':'rdock-control (P3)',
 'provider-file':'rdock-provider-file','provider-docker':'rdock-provider-docker','provider-swarm':'rdock-provider-swarm',
 'provider-kubernetes':'rdock-provider-kubernetes','provider-kv':'unscheduled (W-PLAT-07)','provider-nomad':'unscheduled (W-PLAT-06)',
 'provider-consul':'unscheduled (W-PLAT-06)','provider-ecs':'unscheduled (W-PLAT-08)','deployments':'deploy/','benchmarks':'benchmarks/',
 'tests':'tests/','architecture':'workspace','governance':'repo governance','middleware-grpc-web':'rdock-middleware (grpc-web)',
}
def mod(m):
    m = m.strip()
    return CRATE.get(m, m)
feat = list(rows('sheet1'))[3:]  # skip title rows + header
groups = collections.OrderedDict()
phase_count = collections.Counter(); mod_count = collections.defaultdict(collections.Counter)
for r in feat:
    r = (r + ['']*14)[:14]
    cat, name, ng, tr, ca, ha, en, pa, pi, ph, mo, ef, note, url = r
    if not name: continue
    groups.setdefault(cat, []).append(r)
    phase_count[ph] += 1; mod_count[mod(mo)][ph] += 1
lines = []
lines.append(f"\n<!-- GENERATED from docs/research/feature-parity-matrix-2026-10-26.xlsx by scripts/xlsx2md.py — edit the workbook, not this section -->\n")
lines.append("## Legend\n")
lines.append("| Symbol | Meaning | Engineering implication |\n|---|---|---|")
lines.append("| ✅ Native | Official built-in / packaged support | Still requires config and tests |")
lines.append("| ◐ Partial | Limited features or different semantics | Read notes; cannot claim full parity |")
lines.append("| 🔌 External | Plugin / controller / other process | Extra dependencies / maintenance |")
lines.append("| 🧪 Experimental | Documented experimental feature | Not a stable compatibility guarantee |")
lines.append("| — Not native | No documented built-in support in this scope | May be possible via custom code |")
lines.append("| 🛠️ Build needed | Pingora gives building blocks, product feature absent | ReverseDock must implement it |")
lines.append("\nScope rules: free/open-source distributions only (NGINX Plus and Traefik Hub do not count). Running inside Docker ≠ Docker service discovery. HTTP/3 downstream ≠ HTTP/3 upstream. P0–P3 are **requirements for ReverseDock, not implementation claims**.\n")
tot = sum(phase_count.values())
lines.append(f"## Counts by phase ({tot} capabilities)\n")
lines.append("| Phase | Count | Milestones |\n|---|---|---|")
ms = {'P0':'v0.1 – v0.3 (Foundations: protocols, routing, TLS + ACME, Docker labels)','P1':'v0.4 – v0.6 (Production: LB & health, observability, management, Swarm, L4)','P2':'v0.7 – v0.8 (Advanced: Kubernetes, cache, extensibility)','P3':'v0.9 + (Scale: clustering, HTTP/3, specialised edge policy)'}
for p in ['P0','P1','P2','P3']:
    lines.append(f"| {p} | {phase_count[p]} | {ms[p]} |")
lines.append("\n## Full matrix\n")
lines.append("Columns: NGINX OSS · Traefik OSS · Caddy · HAProxy CE · Envoy · Pingap · Pingora framework · target phase (workbook) · ReverseDock crate/module · effort. Phases in **04-requirements.md win** where they differ (see Phase overrides above).\n")
for cat, rs in groups.items():
    lines.append(f"### {cat}\n")
    lines.append("| Capability | NGINX | Traefik | Caddy | HAProxy | Envoy | Pingap | Pingora | Phase | Crate / module | Effort | Build notes |")
    lines.append("|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|---|---|---|")
    for r in rs:
        cat_, name, ng, tr, ca, ha, en, pa, pi, ph, mo, ef, note, url = r
        n = f"[{name}]({url})" if url else name
        lines.append(f"| {n} | {sym(ng)} | {sym(tr)} | {sym(ca)} | {sym(ha)} | {sym(en)} | {sym(pa)} | {sym(pi)} | {ph} | `{mod(mo)}` | {ef} | {note} |")
    lines.append("")
lines.append("## Backlog by crate / module\n")
lines.append("| Crate / module | Total | P0 | P1 | P2 | P3 |\n|---|:-:|:-:|:-:|:-:|:-:|")
for m in sorted(mod_count):
    c = mod_count[m]; lines.append(f"| `{m}` | {sum(c.values())} | {c['P0']} | {c['P1']} | {c['P2']} | {c['P3']} |")
lines.append("\n## Workbook sheet \"20 Critical Decisions\" (as authored, phase-ordered)\n")
lines.append("| # | Capability | Phase | Crate / module | Build note |\n|:-:|---|:-:|---|---|")
for r in list(rows('sheet5'))[2:]:
    r = (r + ['']*6)[:6]
    if r[1]: lines.append(f"| {r[0]} | [{r[1]}]({r[5]}) | {r[2]} | `{mod(r[3])}` | {r[4]} |")
lines.append("\n## Source library (official references used for the matrix)\n")
lines.append("| Ref | Document | What it substantiates |\n|---|---|---|")
for r in list(rows('sheet4'))[2:]:
    r = (r + ['']*4)[:4]
    if r[1]: lines.append(f"| {r[0]} | [{r[1]}]({r[2]}) | {r[3]} |")
open(out, 'w').write('\n'.join(lines) + '\n')
print(f"wrote {out}: {tot} features, phases={dict(phase_count)}, modules={len(mod_count)}")
