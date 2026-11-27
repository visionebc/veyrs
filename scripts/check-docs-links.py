#!/usr/bin/env python3
"""Check every internal link of a built Docs Center.

    python3 site/build.py --out /tmp/veyrs-portal
    python3 scripts/check-docs-links.py /tmp/veyrs-portal

For every *.html page: each href/src that stays on the site must resolve to a
file of the build, and each #fragment must exist as an id on the target page
(or on the same page). External links (http/https/mailto) are not fetched;
they are counted. Exit 1 on any broken link, listing page -> link.
"""
from __future__ import annotations

import html
import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

ATTR = re.compile(r'\s(?:href|src)="([^"]*)"')
ID = re.compile(r'\sid="([^"]+)"')


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    root = Path(argv[1]).resolve()
    pages = sorted(root.rglob("*.html"))
    ids: dict[Path, set[str]] = {}

    def ids_of(p: Path) -> set[str]:
        if p not in ids:
            ids[p] = {html.unescape(i) for i in ID.findall(p.read_text(encoding="utf-8"))}
        return ids[p]

    broken, checked, external = [], 0, 0
    for page in pages:
        text = page.read_text(encoding="utf-8")
        # Ignore URLs inside code samples: only real attributes count.
        for raw in ATTR.findall(text):
            link = html.unescape(raw)
            if not link or link.startswith(("mailto:", "tel:", "javascript:", "data:")):
                continue
            parts = urlsplit(link)
            if parts.scheme in ("http", "https") or parts.netloc:
                external += 1
                continue
            checked += 1
            if parts.path:
                target = (root / unquote(parts.path).lstrip("/")) if parts.path.startswith("/") \
                    else (page.parent / unquote(parts.path))
                target = target.resolve()
                if target.is_dir():
                    target = target / "index.html"
                if not target.is_file():
                    broken.append((page, link, "missing file"))
                    continue
            else:
                target = page
            if parts.fragment and target.suffix == ".html" and unquote(parts.fragment) not in ids_of(target):
                broken.append((page, link, "missing #anchor"))
    for page, link, why in broken:
        print(f"{page.relative_to(root)}: {link} ({why})")
    print(f"{len(pages)} pages, {checked} internal links checked, {external} external not fetched, "
          f"{len(broken)} broken")
    return 1 if broken else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
