"""Confirm every port's token-validation verdicts agree with the expected verdicts in tokens.json.

Each port writes validation/out/<lang>.json (a list of {name, valid, error}); this maps each to a verdict
("valid" or the error code) and checks all ports match the expected verdict for every case."""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

with open(os.path.join(HERE, "tokens.json")) as fh:
    tokens = json.load(fh)
expected = {c["name"]: c["expect"] for c in tokens["cases"]}
names = [c["name"] for c in tokens["cases"]]

outdir = os.path.join(HERE, "out")
langs = {}
if os.path.isdir(outdir):
    for filename in sorted(os.listdir(outdir)):
        if filename.endswith(".json"):
            with open(os.path.join(outdir, filename)) as fh:
                data = json.load(fh)
            langs[data["language"]] = {
                r["name"]: ("valid" if r["valid"] else r["error"]) for r in data["results"]
            }

REQUIRED = {"go", "python", "typescript"}
missing_langs = REQUIRED - set(langs)
if missing_langs:
    print("missing validator output from: " + ", ".join(sorted(missing_langs)) + " (in " + outdir + ")")
    sys.exit(2)

order = sorted(langs)
print("  %-16s %-20s %s" % ("case", "expected", "".join("%-14s" % l for l in order)))
failures = 0
for name in names:
    want = expected[name]
    got = {lang: langs[lang].get(name, "MISSING") for lang in order}
    ok = all(v == want for v in got.values())
    if not ok:
        failures += 1
    print("  %-16s %-20s %s%s" % (
        name, want, "".join("%-14s" % got[lang] for lang in order), "" if ok else "  <-- MISMATCH"))

print("\nVALIDATION AGREEMENT OK — all ports match the expected verdicts on every case" if failures == 0
      else f"\nVALIDATION FAILED — {failures} case(s) disagree")
sys.exit(0 if failures == 0 else 1)
