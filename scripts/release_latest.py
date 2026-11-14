#!/usr/bin/env python3
"""Decide whether a release takes the `latest` image tag and GitHub's "Latest release" mark.

The rule (ADR-0033, "Release integrity"): `latest` never moves backwards.

* A pre-release (`1.0.0-rc.1`, `0.9.0-alpha.1`) never takes it.
* A stable release takes it only if no other stable release in the tag list is higher by SemVer
  precedence. A patch for an older minor (`1.3.5` after `1.4.0`) therefore leaves it alone.
* Build metadata (`+...`) never counts. Tags that are not SemVer are ignored (and named on stderr).
* The version being decided is itself in the tag list (the tag was pushed before the workflow
  ran); equal versions are skipped.

Usage:
    python3 -I scripts/release_latest.py VERSION [--tags-file FILE]

VERSION is `1.4.0` or `v1.4.0`. The tags come from FILE or standard input, one per line; a line may
be a bare tag (`v1.2.3`), a ref (`refs/tags/v1.2.3`) or `git ls-remote --tags` output. It prints
`true` or `false` on standard output and the reason on standard error. Exit status 2: VERSION is not
SemVer. Standard library only; tests in scripts/test_release_latest.py.
"""

import re
import sys

# Semantic Versioning 2.0.0, the regular expression the specification gives (semver.org).
SEMVER = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?"
    r"(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$"
)


def parse(text):
    """Return (major, minor, patch, prerelease identifiers) or None when `text` is not SemVer."""
    text = text.strip()
    if text.startswith("v"):
        text = text[1:]
    match = SEMVER.match(text)
    if not match:
        return None
    major, minor, patch, pre, _build = match.groups()
    return (int(major), int(minor), int(patch), tuple(pre.split(".")) if pre else ())


def _identifier_key(ident):
    # SemVer 2.0.0 section 11: numeric identifiers compare as numbers and rank below alphanumeric
    # ones, which compare in ASCII order.
    if ident.isdigit():
        return (0, int(ident), "")
    return (1, 0, ident)


def precedence(version):
    """A sort key: higher means a later release. A release outranks its own pre-releases."""
    major, minor, patch, pre = version
    if not pre:
        return (major, minor, patch, 1, ())
    return (major, minor, patch, 0, tuple(_identifier_key(i) for i in pre))


def tag_names(lines):
    """Extract tag names from bare tags, refs and `git ls-remote --tags` lines."""
    for line in lines:
        line = line.strip()
        if not line:
            continue
        name = line.split()[-1]
        if name.endswith("^{}"):
            name = name[:-3]
        yield name[len("refs/tags/"):] if name.startswith("refs/tags/") else name


def decide(version, tags):
    """Return (takes_latest, reason). `version` is a string, `tags` an iterable of tag names."""
    parsed = parse(version)
    if parsed is None:
        raise ValueError(f"{version!r} is not a Semantic Versioning 2.0.0 version")
    if parsed[3]:
        return False, f"{version} is a pre-release; pre-releases never take latest"
    mine = precedence(parsed)
    ignored = []
    highest = None
    for name in tag_names(tags):
        other = parse(name)
        if other is None:
            ignored.append(name)
            continue
        if other[3]:
            continue  # a pre-release never holds latest, so it cannot hold it back
        key = precedence(other)
        if key == mine:
            continue  # the release being decided
        if key > mine and (highest is None or key > highest[0]):
            highest = (key, name)
    note = f" (ignored non-SemVer tags: {', '.join(sorted(ignored))})" if ignored else ""
    if highest is not None:
        return False, f"{version} is below the released {highest[1]}; latest does not move backwards{note}"
    return True, f"{version} is the highest stable release{note}"


def main(argv):
    args = argv[1:]
    tags_file = None
    if "--tags-file" in args:
        i = args.index("--tags-file")
        try:
            tags_file = args[i + 1]
        except IndexError:
            print("--tags-file needs a file name", file=sys.stderr)
            return 2
        del args[i : i + 2]
    if len(args) != 1 or args[0].startswith("-"):
        print(__doc__.split("Usage:")[1].split("VERSION is")[0].strip(), file=sys.stderr)
        return 2
    if tags_file:
        with open(tags_file, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
    else:
        lines = sys.stdin.read().splitlines()
    try:
        takes, reason = decide(args[0], lines)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(reason, file=sys.stderr)
    print("true" if takes else "false")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
