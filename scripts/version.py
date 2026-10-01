#!/usr/bin/env python3
"""The SDK has one version, in the VERSION file at the repo root. This keeps every copy of it in step.

    python3 scripts/version.py check        # exit 1 if any copy differs from VERSION (CI runs this)
    python3 scripts/version.py set 0.2.0    # write 0.2.0 to VERSION and every copy

Go has no copy: its version is the go/vX.Y.Z tag that release.yml creates.
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SEMVER = r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?"

# (file, regex with one group around the version). Each pattern must match exactly once, except where
# count says otherwise.
COPIES = [
    ("python/pyproject.toml", rf'(?m)^version = "({SEMVER})"$', 1),
    ("python/src/client_attestation_sdk/__init__.py", rf'__version__ = "({SEMVER})"', 1),
    ("python/src/token_validator/__init__.py", rf'__version__ = "({SEMVER})"', 1),
    ("python/src/authz_challenge/__init__.py", rf'__version__ = "({SEMVER})"', 1),
    ("typescript/package.json", rf'(?m)^  "version": "({SEMVER})"', 1),
    ("typescript/package-lock.json", rf'"name": "@idpartners/client-attestation-sdk",\s*"version": "({SEMVER})"', 2),
    ("typescript/src/index.ts", rf'export const VERSION = "({SEMVER})"', 1),
    ("typescript/src/validator/index.ts", rf'export const VALIDATOR_VERSION = "({SEMVER})"', 1),
    ("java/pom.xml", rf"<artifactId>client-attestation-sdk</artifactId>\s*<version>({SEMVER})</version>", 1),
    ("java/README.md", rf"<artifactId>client-attestation-sdk</artifactId>\s*<version>({SEMVER})</version>", 1),
]


def read(path):
    with open(os.path.join(ROOT, path), encoding="utf-8") as fh:
        return fh.read()


def write(path, text):
    with open(os.path.join(ROOT, path), "w", encoding="utf-8") as fh:
        fh.write(text)


def main():
    args = sys.argv[1:]
    if args[:1] == ["set"] and len(args) == 2:
        new = args[1]
        if not re.fullmatch(SEMVER, new):
            sys.exit(f"not a semver version: {new}")
        write("VERSION", new + "\n")
        for path, pattern, count in COPIES:
            text = read(path)
            text, n = re.subn(pattern, lambda m: m.group(0).replace(m.group(1), new), text)
            if n != count:
                sys.exit(f"{path}: expected {count} match(es), found {n}")
            write(path, text)
        print(f"version set to {new} in VERSION and {len(COPIES)} files")
        return
    if args != ["check"]:
        sys.exit(__doc__)
    want = read("VERSION").strip()
    bad = []
    for path, pattern, count in COPIES:
        found = re.findall(pattern, read(path))
        if len(found) != count or any(v != want for v in found):
            bad.append(f"  {path}: {found or 'no match'}")
    if bad:
        print(f"version copies disagree with VERSION ({want}):\n" + "\n".join(bad))
        print("fix with: python3 scripts/version.py set " + want)
        sys.exit(1)
    print(f"version {want}: all {len(COPIES)} copies agree")


if __name__ == "__main__":
    main()
