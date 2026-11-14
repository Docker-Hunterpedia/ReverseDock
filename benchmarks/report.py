"""Turns results/<proxy>-<rate>.json into a Markdown table per rate.

TLS scenarios add a Negotiated column (README "TLS parity"): "ok" when every sampled response used
the expected HTTP version, TLS version and cipher suite, "parity mismatch: ..." otherwise, which
makes run.sh exit 3.
"""
import json
import pathlib
import sys


def negotiated_cell(run):
    n = run.get("negotiated")
    if n is None:
        return ""
    if not n["checked"]:
        return "parity mismatch: nothing checked"
    wrong = [
        f"{n[key]}/{n['checked']} not {n['expected'][what]}"
        for key, what in (("wrong_proto", "proto"), ("wrong_tls", "tls"), ("wrong_cipher", "cipher"))
        if n[key]
    ]
    if wrong:
        return "parity mismatch: " + ", ".join(wrong)
    return f"ok ({n['checked']} checked)"


def render(results):
    rates = sorted({r["rate"] for r in results})
    parity = any("negotiated" in r for r in results)
    head = "| Proxy | Target req/s | Achieved req/s | p50 ms | p90 ms | p99 ms | p99.9 ms | max ms | Failed | Dropped |"
    rule = "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|"
    lines = [head + (" Negotiated |" if parity else ""), rule + ("---|" if parity else "")]
    for rate in rates:
        for r in sorted((r for r in results if r["rate"] == rate), key=lambda r: r["ms"]["p99"]):
            ms = r["ms"]
            line = (
                f"| {r['proxy']} | {rate} | {r['achieved_rps']:.0f} | {ms['p50']:.2f} | {ms['p90']:.2f} | "
                f"{ms['p99']:.2f} | {ms['p999']:.2f} | {ms['max']:.1f} | {r['failed'] * 100:.2f} % | {r['dropped']} |"
            )
            if parity:
                line += f" {negotiated_cell(r)} |"
            lines.append(line)
    return "\n".join(lines)


def main(directory):
    results = [json.loads(p.read_text()) for p in sorted(pathlib.Path(directory).glob("*.json"))]
    print(render(results))


if __name__ == "__main__":
    main(sys.argv[1])
