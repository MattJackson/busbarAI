#!/usr/bin/env python3
"""Set the [package] version in a Cargo.toml (only the package version, never a
dependency's). Portable (no GNU-sed-only address ranges). Used by cut-release.yml."""
import sys, re

def main(version: str, path: str) -> None:
    s = open(path).read()
    # Match the version line inside the [package] table only: from "[package]" up to the
    # next "[" table header, replace the first `version = "..."`.
    def repl(m):
        head, body = m.group(1), m.group(2)
        new_body, n = re.subn(r'(?m)^version\s*=\s*"[^"]+"', f'version = "{version}"', body, count=1)
        if n != 1:
            sys.exit("bump_cargo: no version line under [package]")
        return head + new_body
    s2, n = re.subn(r'(?s)(\[package\]\n)(.*?)(?=\n\[)', repl, s, count=1)
    if n != 1:
        sys.exit("bump_cargo: no [package] table found")
    open(path, "w").write(s2)
    print(f"bumped [package] version -> {version}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: bump_cargo.py <version> <Cargo.toml>")
    main(sys.argv[1], sys.argv[2])
