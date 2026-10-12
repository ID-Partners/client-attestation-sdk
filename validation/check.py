"""Confirm every port's (Go, Java, Python, TypeScript) token-validation verdicts agree with the expected verdicts
in tokens.json, introspection.json and config.json.

Each port writes validation/out/<lang>.json: {"language", "results", "introspection_results",
"guard_results", "config_results"}, each a list of {name, valid, error, description}. guard_results are the
introspection cases run through ProtectedResource.authenticate_active, checked against `expect_guard`. A result maps to a verdict ("valid" or the
error code; an introspection call that failed with the port's error reports error "raises"; a config row is
"accepted", or error "refused"). Every port must return the expected verdict for every case, and must report
every case: a missing or extra row fails the check. A case with an `expect_description` also needs that exact
error description from every port."""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REQUIRED = {"go", "java", "python", "typescript"}


def load(name, expect="expect"):
    with open(os.path.join(HERE, name)) as fh:
        return [{**c, "expect": c[expect]} for c in json.load(fh)["cases"]]


# (label, output key, cases, what a row with valid=true means)
suites = [("tokens.json", "results", load("tokens.json"), "valid"),
          ("introspection.json", "introspection_results", load("introspection.json"), "valid"),
          ("introspection.json (authenticate_active)", "guard_results",
           load("introspection.json", "expect_guard"), "valid"),
          ("config.json", "config_results", load("config.json"), "accepted")]

outdir = os.path.join(HERE, "out")
outputs = {}
if os.path.isdir(outdir):
    for filename in sorted(os.listdir(outdir)):
        if filename.endswith(".json"):
            with open(os.path.join(outdir, filename)) as fh:
                data = json.load(fh)
            outputs[data["language"]] = data

missing_langs = REQUIRED - set(outputs)
if missing_langs:
    print("missing validator output from: " + ", ".join(sorted(missing_langs)) + " (in " + outdir + ")")
    sys.exit(2)

order = sorted(outputs)
failures = 0
total = 0
for source, key, cases, passed in suites:
    names = [c["name"] for c in cases]
    expected = {c["name"]: c["expect"] for c in cases}
    descriptions = {c["name"]: c["expect_description"] for c in cases if "expect_description" in c}
    got_by_lang = {}
    for lang in order:
        rows = outputs[lang].get(key) or []
        got_by_lang[lang] = {r["name"]: (passed if r["valid"] else r["error"]) for r in rows}
        for r in rows:
            want = descriptions.get(r["name"])
            if want is not None and r.get("description") != want:
                failures += 1
                print(f"  {lang} {r['name']}: description {r.get('description')!r}, expected {want!r}  <-- MISMATCH")
        extra = sorted(set(got_by_lang[lang]) - set(names))
        if extra:
            failures += 1
            print(f"  {lang} reported cases {source} doesn't have: {', '.join(extra)}  <-- MISMATCH")
    width = max(len(n) for n in names) + 2
    print(f"\n{source} ({len(cases)} cases)")
    print("  %-*s %-22s %s" % (width, "case", "expected", "".join("%-22s" % lang for lang in order)))
    for name in names:
        total += 1
        want = expected[name]
        got = {lang: got_by_lang[lang].get(name, "MISSING") for lang in order}
        ok = all(v == want for v in got.values())
        if not ok:
            failures += 1
        print("  %-*s %-22s %s%s" % (width, name, want, "".join("%-22s" % got[lang] for lang in order),
                                     "" if ok else "  <-- MISMATCH"))

print(f"\nVALIDATION AGREEMENT OK — all {len(order)} ports match the expected verdicts on all {total} cases"
      if failures == 0 else f"\nVALIDATION FAILED — {failures} case(s) disagree")
sys.exit(0 if failures == 0 else 1)
