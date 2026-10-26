#!/usr/bin/env python3
"""Docs checks run in CI: relative links resolve, the feature matrix matches the workbook, GitHub YAML parses."""
import glob
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)
errors = []

# 1. Relative links in Markdown resolve to files in the repo.
md_files = glob.glob("*.md") + glob.glob("docs/**/*.md", recursive=True) + glob.glob(".github/**/*.md", recursive=True)
for path in md_files:
    text = open(path, encoding="utf-8").read()
    text = re.sub(r"```.*?```", "", text, flags=re.S)  # ignore code blocks
    for match in re.finditer(r"\]\(([^)\s#]+)(#[^)\s]*)?\)", text):
        target = match.group(1)
        if target.startswith(("http://", "https://", "mailto:")):
            continue
        resolved = os.path.normpath(os.path.join(os.path.dirname(path), target))
        if not os.path.exists(resolved):
            errors.append(f"{path}: broken link -> {target}")

# 2. The generated part of the feature matrix matches the workbook.
workbook = "docs/research/feature-parity-matrix-2026-10-26.xlsx"
matrix = "docs/03-feature-matrix.md"
marker = "<!-- GENERATED"
with tempfile.TemporaryDirectory() as tmp:
    out = os.path.join(tmp, "tables.md")
    subprocess.run([sys.executable, "-I", "scripts/xlsx2md.py", workbook, out], check=True, stdout=subprocess.DEVNULL)
    generated = open(out, encoding="utf-8").read()
current = open(matrix, encoding="utf-8").read()
if marker not in current:
    errors.append(f"{matrix}: generated marker missing")
elif current[current.index(marker):] != generated[generated.index(marker):]:
    errors.append(f"{matrix}: generated section is stale; rerun scripts/xlsx2md.py (see CONTRIBUTING.md)")

# 3. GitHub YAML files parse.
try:
    import yaml
except ImportError:
    yaml = None
    print("warning: PyYAML not installed, skipping YAML parse check")
if yaml:
    for path in glob.glob(".github/**/*.yml", recursive=True):
        try:
            yaml.safe_load(open(path, encoding="utf-8"))
        except yaml.YAMLError as exc:
            errors.append(f"{path}: invalid YAML: {exc}")

if errors:
    print("\n".join(errors))
    sys.exit(1)
print(f"docs ok: {len(md_files)} markdown files, matrix in sync")
