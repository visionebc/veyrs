#!/usr/bin/env python3
"""Check the `path:line` references in the hand-written documentation (TD-58).

    python3 scripts/check-docs-refs.py [--root DIR] [--verbose]
                                       [--baseline FILE | --write-baseline FILE]

A release that moves code by a few lines silently turns every citation of it
into a lie. This checker reads each hand-written Markdown document under
`docs/` (the generated trees `docs/reference/`, `docs/api/` and the historical
`docs/CHANGELOG.md` are skipped) plus `README.md` and `INSTALL.md`, finds every
reference of the form

    path/to/file.ext:123        path/to/file.ext:123-140        file.ext:10,20

and verifies two things:

* FAIL  the file exists (a bare file name must match exactly one tracked file);
* FAIL  every cited line is inside the file (1 <= line <= number of lines).

It also reports, without failing, **symbol drift**: when the reference sits next
to a backticked identifier (`` `name()` ``, `` `ClassName` ``), the identifier
should still appear within a few lines of the cited one. If it does not, the
citation probably drifted. This is a heuristic (it cannot know what the sentence
means), so it prints `WARN` lines and never changes the exit status.

A bare file name shared by several files (`auth.py`) passes when ANY candidate
has the cited line; it fails only when none does.

Baseline (ratchet). Documents written against an older tree already contain
broken references. `--write-baseline FILE` records them (one `doc<TAB>ref:spec`
per line, no line numbers of the document, so editing prose does not invalidate
it); with `--baseline FILE` only references NOT in the file fail, and entries
that are fixed now are listed as `FIXED` so the file can shrink. tests/
test_fix_deploy.py runs it that way: new rot fails the suite, old rot is tracked.

Exit status: 0 clean, 1 on a missing file or an out-of-range line (not in the
baseline), 2 on usage.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

SKIP_DIRS = ("docs/reference/", "docs/api/", "docs/diagrams/")
SKIP_FILES = ("docs/CHANGELOG.md",)
EXTS = "py|js|css|html|sh|yaml|yml|conf|service|timer|path|md|sql|toml|json|ini|txt|cfg"
REF = re.compile(
    rf"(?<![\w./-])((?:[\w.@-]+/)*[\w.@-]+\.(?:{EXTS})):(\d+(?:[-–,]\d+)*)(?![\w:])"
)
IDENT = re.compile(r"`([A-Za-z_][A-Za-z0-9_]{3,})(?:\(\))?`")
WINDOW = 12   # lines either side of the cited one in which a named symbol must appear
SKIP_NAMES = {"true", "false", "none", "null", "self", "name", "list", "dict", "type", "path", "file", "text"}


def tracked_files(root: Path) -> list[Path]:
    out = []
    for p in root.rglob("*"):
        rel = p.relative_to(root).as_posix()
        if not p.is_file() or rel.startswith((".git/", "venv/", "node_modules/")) or "/__pycache__/" in rel:
            continue
        out.append(p)
    return out


def doc_files(root: Path) -> list[Path]:
    docs = [p for p in (root / "docs").rglob("*.md")
            if not p.relative_to(root).as_posix().startswith(SKIP_DIRS)
            and p.relative_to(root).as_posix() not in SKIP_FILES]
    docs += [p for p in (root / "README.md", root / "INSTALL.md") if p.is_file()]
    return sorted(docs)


def line_numbers(spec: str) -> list[int]:
    nums: list[int] = []
    for part in spec.split(","):
        bounds = re.split(r"[-–]", part)
        nums.extend(int(b) for b in bounds)
    return nums


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
    ap.add_argument("--verbose", action="store_true", help="list every WARN, not just the first 25")
    ap.add_argument("--baseline", help="file of known-broken references; only others fail")
    ap.add_argument("--write-baseline", help="write the current broken references to FILE and exit 0")
    args = ap.parse_args(argv)
    root = Path(args.root).resolve()
    if not (root / "docs").is_dir():
        print(f"{root} has no docs/ directory", file=sys.stderr)
        return 2

    files = tracked_files(root)
    by_name: dict[str, list[Path]] = {}
    for p in files:
        by_name.setdefault(p.name, []).append(p)
    cache: dict[Path, list[str]] = {}

    def lines_of(p: Path) -> list[str]:
        if p not in cache:
            cache[p] = p.read_text(encoding="utf-8", errors="replace").splitlines()
        return cache[p]

    errors: list[str] = []
    warns: list[str] = []
    checked = 0
    for doc in doc_files(root):
        rel_doc = doc.relative_to(root).as_posix()
        for n, text in enumerate(doc.read_text(encoding="utf-8").splitlines(), 1):
            for m in REF.finditer(text):
                ref, spec = m.group(1), m.group(2)
                target = root / ref
                if not target.is_file():
                    candidates = by_name.get(ref, []) if "/" not in ref else \
                        [p for p in files if p.relative_to(root).as_posix().endswith("/" + ref)]
                    if not candidates:
                        errors.append((rel_doc, f"{ref}:{spec}", f"{rel_doc}:{n}: {ref}:{spec} -> no such file"))
                        continue
                    nums = line_numbers(spec)
                    fits = [c for c in candidates if all(1 <= x <= len(lines_of(c)) for x in nums)]
                    if not fits:
                        errors.append((rel_doc, f"{ref}:{spec}",
                                       f"{rel_doc}:{n}: {ref}:{spec} -> line out of range in all {len(candidates)} files named {ref}"))
                        continue
                    target = fits[0]
                checked += 1
                src = lines_of(target)
                nums = line_numbers(spec)
                bad = [x for x in nums if not 1 <= x <= len(src)]
                if bad:
                    errors.append((rel_doc, f"{ref}:{spec}",
                                   f"{rel_doc}:{n}: {ref}:{spec} -> line {bad[0]} is outside the file ({len(src)} lines)"))
                    continue
                # Symbol drift (heuristic, never fatal): a backticked identifier next to the reference.
                near = text[max(0, m.start() - 60):m.start()] + " " + text[m.end():m.end() + 60]
                names = [i for i in IDENT.findall(near) if i.lower() not in SKIP_NAMES and i not in ref]
                if names:
                    lo, hi = max(1, min(nums) - WINDOW), min(len(src), max(nums) + WINDOW)
                    window = "\n".join(src[lo - 1:hi])
                    if not any(re.search(rf"\b{re.escape(i)}\b", window) for i in names):
                        warns.append(f"{rel_doc}:{n}: {ref}:{spec} -> none of {names[:3]} within {WINDOW} lines (drift?)")

    keys = sorted({f"{d}\t{r}" for d, r, _ in errors})
    if args.write_baseline:
        Path(args.write_baseline).write_text("".join(k + "\n" for k in keys), encoding="utf-8")
        print(f"{len(keys)} broken references written to {args.write_baseline}")
        return 0
    known: set[str] = set()
    if args.baseline:
        known = {ln.rstrip("\n") for ln in Path(args.baseline).read_text(encoding="utf-8").splitlines() if ln.strip()}
        for k in sorted(known - set(keys)):
            print("FIXED (remove from the baseline):", k.replace("\t", "  "))
    new_errors = [e for e in errors if f"{e[0]}\t{e[1]}" not in known]
    for _, _, msg in new_errors:
        print("FAIL", msg)
    shown = warns if args.verbose else warns[:25]
    for w in shown:
        print("WARN", w)
    if len(warns) > len(shown):
        print(f"... {len(warns) - len(shown)} more WARN lines (--verbose)")
    print(f"{checked} references checked, {len(new_errors)} broken"
          f"{f' (+{len(errors) - len(new_errors)} in the baseline)' if known else ''}, "
          f"{len(warns)} possible symbol drift (not fatal)")
    return 1 if new_errors else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
