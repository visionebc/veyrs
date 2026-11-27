#!/usr/bin/env python3
"""Pre-render every Mermaid diagram in docs/ to SVG for the Docs Center.

The docs portal builder (site/build.py) has zero third-party dependencies and
runs on the app nodes, which have no Node.js. Rendering Mermaid needs Node, so
it happens HERE, on a development machine, and the SVGs are committed:

    docs/diagrams/rendered/<hash>.svg     hash = sha256(block source)[:16]

The ```mermaid block in the Markdown stays the editable source. Change the
block, run this script, commit the new SVG: the builder links the SVG whose
hash matches the block, so a diagram can never show a stale picture of its
source (tests/test_docs_diagrams.py fails when an SVG is missing).

    python3 scripts/render-diagrams.py            # render missing, prune orphans
    python3 scripts/render-diagrams.py --check    # exit 1 if any block lacks its SVG

Needs (dev machine only): Node.js and @mermaid-js/mermaid-cli (`mmdc`), plus a
Chromium for Puppeteer. Locations are taken from the environment:

    MMDC=/path/to/node_modules/.bin/mmdc
    MMDC_PUPPETEER=/path/to/puppeteer.json   # {"executablePath": "/usr/bin/chromium", "args": ["--no-sandbox"]}

Rendering uses the `neutral` theme on a white background and SVG text labels
(htmlLabels off), so the files display correctly inside <img> and in both
portal themes (diagrams sit on a white card).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
OUT = DOCS / "diagrams" / "rendered"
sys.path.insert(0, str(ROOT / "site"))

from build import mermaid_hash, parse_front_matter  # noqa: E402  (same hash as the builder)

FENCE = re.compile(r"^(\s*)```mermaid\s*$")
CONFIG = {"theme": "neutral", "flowchart": {"htmlLabels": False, "useMaxWidth": False},
          "sequence": {"useMaxWidth": False}, "er": {"useMaxWidth": False},
          "themeVariables": {"fontFamily": "Inter, Helvetica, Arial, sans-serif"}}


def blocks():
    """Yield (doc path, line number, source) for every ```mermaid block."""
    for md in sorted(DOCS.rglob("*.md")):
        lines = parse_front_matter(md.read_text(encoding="utf-8"))[1].split("\n")
        i = 0
        while i < len(lines):
            m = FENCE.match(lines[i])
            if m:
                indent, start, buf = len(m.group(1)), i + 1, []
                i += 1
                while i < len(lines) and not lines[i].lstrip().startswith("```"):
                    ln = lines[i]
                    buf.append(ln[indent:] if ln[:indent].strip() == "" else ln)
                    i += 1
                yield md.relative_to(ROOT), start, "\n".join(buf)
            i += 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true", help="exit 1 if a block has no rendered SVG")
    ap.add_argument("--no-prune", action="store_true", help="keep SVGs no block references")
    args = ap.parse_args()

    found = list(blocks())
    wanted = {mermaid_hash(src): (doc, line, src) for doc, line, src in found}
    missing = {h: v for h, v in wanted.items() if not (OUT / f"{h}.svg").is_file()}
    if args.check:
        for h, (doc, line, _src) in sorted(missing.items(), key=lambda x: (str(x[1][0]), x[1][1])):
            print(f"no SVG for the diagram at {doc}:{line} (hash {h})", file=sys.stderr)
        if missing:
            print("Render them: python3 scripts/render-diagrams.py", file=sys.stderr)
            return 1
        print(f"{len(wanted)} diagrams, every one rendered")
        return 0

    OUT.mkdir(parents=True, exist_ok=True)
    mmdc = os.environ.get("MMDC", "mmdc")
    pptr = os.environ.get("MMDC_PUPPETEER")
    failed = 0
    with tempfile.TemporaryDirectory() as tmp:
        cfg = Path(tmp) / "config.json"
        cfg.write_text(json.dumps(CONFIG), encoding="utf-8")
        for h, (doc, line, src) in sorted(missing.items(), key=lambda x: (str(x[1][0]), x[1][1])):
            inp = Path(tmp) / f"{h}.mmd"
            inp.write_text(src.strip() + "\n", encoding="utf-8")
            cmd = [mmdc, "-i", str(inp), "-o", str(OUT / f"{h}.svg"), "-t", "neutral", "-b", "white", "-c", str(cfg), "-q"]
            if pptr:
                cmd += ["-p", pptr]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            if res.returncode != 0 or not (OUT / f"{h}.svg").is_file():
                failed += 1
                err = (res.stderr or res.stdout).strip().splitlines()
                print(f"FAILED {doc}:{line} ({h}): {' | '.join(err[-3:])}", file=sys.stderr)
            else:
                print(f"rendered {doc}:{line} -> {OUT.relative_to(ROOT)}/{h}.svg")
    pruned = 0
    if not args.no_prune:
        for svg in OUT.glob("*.svg"):
            if svg.stem not in wanted:
                svg.unlink()
                pruned += 1
    print(f"{len(wanted)} diagrams: {len(missing) - failed} rendered now, {failed} failed, {pruned} orphans pruned")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
