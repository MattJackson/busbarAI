#!/usr/bin/env python3
"""Promote CHANGELOG [Unreleased] to a dated [version] section, add a fresh empty
[Unreleased] above it. Used by .github/workflows/cut-release.yml."""
import sys, re, datetime

def main(version: str, path: str) -> None:
    today = datetime.date.today().isoformat()
    s = open(path).read()
    m = re.search(r'^## \[Unreleased\]\s*\n(.*?)(?=^## \[)', s, re.S | re.M)
    if not m:
        sys.exit("roll_changelog: no [Unreleased] section found")
    body = m.group(1).strip('\n')
    if not body.strip():
        body = "### Changed\n\n- Maintenance and dependency updates."
    new = f"## [Unreleased]\n\n## [{version}], {today}\n\n{body}\n\n"
    open(path, "w").write(s[:m.start()] + new + s[m.end():])
    print(f"rolled CHANGELOG: [Unreleased] -> [{version}] {today}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: roll_changelog.py <version> <CHANGELOG.md>")
    main(sys.argv[1], sys.argv[2])
