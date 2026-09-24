#!/usr/bin/env python3
"""VEYRS documentation site generator.

Renders every Markdown file under docs/ into a styled static site.
Zero third-party dependencies on purpose: the docs host must stay trivially
reproducible and auditable (see docs/SECURITY.md, "build toolchain").

Usage:  python3 site/build.py [--out /var/www/veyrs]
"""
import argparse
import html
import os
import re
import shutil

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCS = os.path.join(ROOT, "docs")

# Sidebar grouping. Files not listed here are appended to "Other" so a new
# doc never silently disappears from navigation.
NAV = [
    ("Start here", ["README", "USER_GUIDE", "USER_MANUAL", "ADMIN_GUIDE"]),
    ("Architecture", ["ARCHITECTURE", "DATABASE", "API", "DEPLOYMENT", "DOCKER_COMPOSE_MANUAL", "DEVELOPMENT"]),
    ("Security", ["SECURITY", "THREAT_MODEL", "AI_SECURITY"]),
    ("Operations", ["INTEGRATIONS", "DISASTER_RECOVERY", "CHANGELOG", "CONTRIBUTING"]),
]


# --------------------------------------------------------------------------
# Markdown → HTML. Deliberately a small, predictable subset.
# --------------------------------------------------------------------------
def _inline(text):
    text = html.escape(text, quote=False)
    text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"(?<![*\w])\*([^*\n]+)\*(?!\w)", r"<em>\1</em>", text)
    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r'<a href="\2">\1</a>', text)
    return text


def _table(rows):
    head, body = rows[0], rows[2:]
    cells = lambda r: [c.strip() for c in r.strip().strip("|").split("|")]
    out = ["<table><thead><tr>"]
    out += [f"<th>{_inline(c)}</th>" for c in cells(head)]
    out.append("</tr></thead><tbody>")
    for r in body:
        out.append("<tr>" + "".join(f"<td>{_inline(c)}</td>" for c in cells(r)) + "</tr>")
    out.append("</tbody></table>")
    return "".join(out)


_ITEM = re.compile(r"^\s*(?:[-*]|\d+\.)\s+")


def _continuation(lines, i, items):
    """Fold the indented lines that wrap a list item into that item.

    Without this every wrapped item was cut at its first line break and the
    rest became a stray paragraph, splitting any **bold** that crossed it.
    """
    while (i < len(lines) and re.match(r"^\s{2,}\S", lines[i]) and not _ITEM.match(lines[i])
           and not lines[i].lstrip().startswith(("```", "|"))):
        items[-1] += " " + lines[i].strip()
        i += 1
    return i


def render(md):
    lines, out, i = md.split("\n"), [], 0
    toc = []
    while i < len(lines):
        line = lines[i]

        # Fences and tables may be indented to sit under a list item; the
        # indent is the item's, not part of the code.
        fence = re.match(r"^(\s*)```(.*)$", line)
        if fence:
            indent, lang = len(fence.group(1)), fence.group(2).strip()
            i += 1
            buf = []
            while i < len(lines) and not lines[i].lstrip().startswith("```"):
                ln = lines[i]
                buf.append(ln[indent:] if ln[:indent].strip() == "" else ln)
                i += 1
            code = html.escape("\n".join(buf))
            out.append(f'<pre class="code" data-lang="{html.escape(lang)}"><code>{code}</code></pre>')
            i += 1
            continue

        if (line.lstrip().startswith("|") and i + 1 < len(lines)
                and lines[i + 1].lstrip().startswith("|")
                and set(lines[i + 1].replace("|", "").strip()) <= set("-: ")):
            block = []
            while i < len(lines) and lines[i].lstrip().startswith("|"):
                block.append(lines[i])
                i += 1
            out.append(_table(block))
            continue

        m = re.match(r"^(#{1,4})\s+(.*)$", line)
        if m:
            lvl, txt = len(m.group(1)), m.group(2).strip()
            slug = re.sub(r"[^a-z0-9]+", "-", txt.lower()).strip("-")
            if lvl in (2, 3):
                toc.append((lvl, txt, slug))
            out.append(f'<h{lvl} id="{slug}">{_inline(txt)}</h{lvl}>')
            i += 1
            continue

        if re.match(r"^\s*[-*]\s+", line):
            items = []
            while i < len(lines) and re.match(r"^\s*[-*]\s+", lines[i]):
                items.append(re.sub(r"^\s*[-*]\s+", "", lines[i]))
                i = _continuation(lines, i + 1, items)
            out.append("<ul>" + "".join(f"<li>{_inline(x)}</li>" for x in items) + "</ul>")
            continue

        if re.match(r"^\s*\d+\.\s+", line):
            # Keep the numbering across a code block between items: "3."
            # after a fence must not restart at 1.
            start = int(re.match(r"^\s*(\d+)", line).group(1))
            items = []
            while i < len(lines) and re.match(r"^\s*\d+\.\s+", lines[i]):
                items.append(re.sub(r"^\s*\d+\.\s+", "", lines[i]))
                i = _continuation(lines, i + 1, items)
            ol = "<ol>" if start == 1 else f'<ol start="{start}">'
            out.append(ol + "".join(f"<li>{_inline(x)}</li>" for x in items) + "</ol>")
            continue

        if line.startswith("> "):
            # The quote's contents are Markdown too: a bare ">" separates
            # paragraphs and a quote may hold a fence. Both used to end the
            # quote and leak out as a literal "&gt;" or "```" paragraph.
            buf = []
            while i < len(lines) and (lines[i].startswith("> ") or lines[i].strip() == ">"):
                buf.append(lines[i][2:])
                i += 1
            inner = render("\n".join(buf))[0]
            one = re.fullmatch(r"<p>(.*)</p>", inner, flags=re.S)
            if one and "<p>" not in one.group(1):
                inner = one.group(1)
            out.append(f"<blockquote>{inner}</blockquote>")
            continue

        if line.strip() in ("---", "***"):
            out.append("<hr>")
            i += 1
            continue

        if line.strip():
            # The first line is always taken: a "|" line that is not a table
            # would otherwise match the stop pattern and loop forever.
            buf = [line]
            i += 1
            while i < len(lines) and lines[i].strip() and not re.match(r"^(#{1,4}\s|\s*[-*]\s|\s*\d+\.\s|>\s|\s*\||\s*```)", lines[i]):
                buf.append(lines[i])
                i += 1
            out.append(f"<p>{_inline(' '.join(buf))}</p>")
            continue

        i += 1
    return "\n".join(out), toc


# --------------------------------------------------------------------------
PAGE = """<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>{title} — VEYRS</title>
<link rel="stylesheet" href="/static/veyrs-tokens.css">
<link rel="stylesheet" href="/static/veyrs.css">
<link rel="icon" href="/static/veyrs-favicon.svg" type="image/svg+xml">
</head><body>
<a class="skip" href="#main">Skip to content</a>
<header class="topbar">
  <a class="brand" href="/">{mark}<span class="brand-text"><b>VEYRS</b><i>Unified Cybersecurity Risk Management</i></span></a>
  <button class="navtoggle" aria-label="Toggle navigation" aria-expanded="false">☰</button>
</header>
<div class="shell">
  <nav class="sidebar" aria-label="Documentation">{nav}</nav>
  <main id="main">
    <article class="doc">{body}</article>
    <footer class="docfoot">
      <span>VEYRS · internal documentation</span>
      <span>Source: <a href="https://github.com/visionebc/veyrs">visionebc/veyrs</a></span>
    </footer>
  </main>
  <aside class="toc" aria-label="On this page">{toc}</aside>
</div>
<script src="/static/veyrs.js" defer></script>
</body></html>"""

MARK = (
    '<svg class="mark" viewBox="0 0 32 32" aria-hidden="true">'
    '<defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1">'
    '<stop offset="0" stop-color="#3b82f6"/><stop offset="1" stop-color="#8b5cf6"/>'
    "</linearGradient></defs>"
    '<path d="M16 2 4 7v9c0 7.2 5 12.2 12 14 7-1.8 12-6.8 12-14V7L16 2Z" fill="none" '
    'stroke="url(#g)" stroke-width="2" stroke-linejoin="round"/>'
    '<path d="M10.5 14.5 16 21l6.5-9" fill="none" stroke="url(#g)" stroke-width="2.2" '
    'stroke-linecap="round" stroke-linejoin="round"/></svg>'
)


def build(out_dir):
    names = {f[:-3] for f in os.listdir(DOCS) if f.endswith(".md")}
    grouped, seen = [], set()
    for section, keys in NAV:
        present = [k for k in keys if k in names]
        seen.update(present)
        if present:
            grouped.append((section, present))
    adrs = sorted(f[:-3] for f in os.listdir(os.path.join(DOCS, "ADRs")) if f.endswith(".md")) \
        if os.path.isdir(os.path.join(DOCS, "ADRs")) else []
    other = sorted(names - seen)
    if other:
        grouped.append(("Other", other))

    def nav_html(active):
        parts = []
        for section, keys in grouped:
            parts.append(f'<div class="navgroup"><span class="navtitle">{section}</span><ul>')
            for k in keys:
                cls = ' class="active"' if k == active else ""
                parts.append(f'<li><a href="/{k}.html"{cls}>{k.replace("_", " ").title()}</a></li>')
            parts.append("</ul></div>")
        if adrs:
            parts.append('<div class="navgroup"><span class="navtitle">ADRs</span><ul>')
            for a in adrs:
                cls = ' class="active"' if a == active else ""
                parts.append(f'<li><a href="/adr/{a}.html"{cls}>{a}</a></li>')
            parts.append("</ul></div>")
        return "".join(parts)

    os.makedirs(out_dir, exist_ok=True)
    static_out = os.path.join(out_dir, "static")
    if os.path.isdir(static_out):
        shutil.rmtree(static_out)
    shutil.copytree(os.path.join(ROOT, "site", "static"), static_out)

    written = 0
    targets = [(n, os.path.join(DOCS, n + ".md"), os.path.join(out_dir, n + ".html")) for n in sorted(names)]
    for a in adrs:
        os.makedirs(os.path.join(out_dir, "adr"), exist_ok=True)
        targets.append((a, os.path.join(DOCS, "ADRs", a + ".md"), os.path.join(out_dir, "adr", a + ".html")))

    for name, src, dst in targets:
        body, toc = render(open(src, encoding="utf-8").read())
        toc_html = ""
        if toc:
            toc_html = '<span class="tocTitle">On this page</span><ul>' + "".join(
                f'<li class="l{l}"><a href="#{s}">{html.escape(t)}</a></li>' for l, t, s in toc
            ) + "</ul>"
        title = name.replace("_", " ").title()
        open(dst, "w", encoding="utf-8").write(
            PAGE.format(title=html.escape(title), body=body, nav=nav_html(name), toc=toc_html, mark=MARK)
        )
        written += 1

    if "README" in names:
        shutil.copyfile(os.path.join(out_dir, "README.html"), os.path.join(out_dir, "index.html"))
    return written


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="/var/www/veyrs")
    args = ap.parse_args()
    n = build(args.out)
    print(f"built {n} pages -> {args.out}")
