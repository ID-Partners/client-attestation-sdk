#!/usr/bin/env python3
"""Render docs/features.json, the one feature matrix, into the two places that show it.

    python3 scripts/features.py          # rewrite README.md and docs/explainer.html
    python3 scripts/features.py --check  # exit 1 if any of them differs from what would be generated (CI)

Each target holds the generated part between `features:begin` and `features:end` markers; everything
outside the markers is left alone.
"""
import html
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "docs", "features.json")


def load():
    with open(DATA, encoding="utf-8") as fh:
        data = json.load(fh)
    for group in data["groups"]:
        for row in group["rows"]:
            unknown = set(row["ports"]) - set(data["ports"])
            if unknown:
                sys.exit(f"features.json: row {row['label']!r} names unknown ports {sorted(unknown)}")
    return data


def _codes(row):
    code = row.get("code", [])
    return [code] if isinstance(code, str) else code


def label_html(row):
    text = html.escape(row["label"])
    for word in _codes(row):
        text = re.sub(rf"\b{re.escape(word)}\b", f"<code>{word}</code>", text, count=1)
    return text


def label_md(row):
    text = row["label"]
    for word in _codes(row):
        text = re.sub(rf"\b{re.escape(word)}\b", f"`{word}`", text, count=1)
    return text


YES_EXPLAINER = '<span class="chip yes">Yes</span>'
NO_EXPLAINER = '<span class="chip no"></span>'


def render_explainer(data, indent="          "):
    lines = []
    for group in data["groups"]:
        for row in group["rows"]:
            cells = "".join(
                f"<td>{YES_EXPLAINER if p in row['ports'] else NO_EXPLAINER}</td>" for p in data["ports"])
            label = html.escape(row["explainer_label"]) if "explainer_label" in row else label_html(row)
            lines.append(f'{indent}<tr class="cap-row"><td>{label}</td>\n{indent}  {cells}</tr>')
    return "\n".join(lines)


def render_readme(data):
    names = [data["port_names"][p] for p in data["ports"]]
    lines = ["| Capability | " + " | ".join(names) + " |", "|---" * (len(names) + 1) + "|"]
    for group in data["groups"]:
        lines.append(f"| **{group['name']}** |" + " |" * len(names))
        for row in group["rows"]:
            cells = " | ".join("✓" if p in row["ports"] else "—" for p in data["ports"])
            lines.append(f"| {label_md(row)} | {cells} |")
    return "\n".join(lines)


TARGETS = [
    ("README.md", "<!-- features:begin -->", "<!-- features:end -->", render_readme),
    ("docs/explainer.html", "<!-- features:begin -->", "<!-- features:end -->", render_explainer),
]


def generated(path, begin, end, body):
    with open(os.path.join(ROOT, path), encoding="utf-8") as fh:
        text = fh.read()
    start, stop = text.find(begin), text.find(end)
    if start < 0 or stop < start:
        sys.exit(f"{path}: missing {begin} / {end} markers")
    return text, text[: start + len(begin)] + "\n" + body + "\n" + text[stop:]


def main():
    check = "--check" in sys.argv[1:]
    data = load()
    stale = []
    for path, begin, end, render in TARGETS:
        current, wanted = generated(path, begin, end, render(data))
        if current != wanted:
            stale.append(path)
            if not check:
                with open(os.path.join(ROOT, path), "w", encoding="utf-8") as fh:
                    fh.write(wanted)
    if check and stale:
        print("feature matrix out of date in: " + ", ".join(stale))
        print("run `python3 scripts/features.py` and commit the result")
        sys.exit(1)
    if check or not stale:
        print("feature matrix: up to date")
    else:
        print("feature matrix: rewrote " + ", ".join(stale))


if __name__ == "__main__":
    main()
