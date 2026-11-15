#!/usr/bin/env python3
"""VEYRS documentation site generator.

Renders every Markdown file under docs/ into a styled static site.
Zero third-party dependencies on purpose: the docs host must stay trivially
reproducible and auditable (see docs/SECURITY.md, "build toolchain").

Usage:  python3 site/build.py [--out /var/www/veyrs]
"""
import argparse
import hashlib
import html
import json
import os
import re
import shutil

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCS = os.path.join(ROOT, "docs")

# Docs Center categories: (title, one-line purpose, docs). Every doc belongs
# to exactly one; a doc missing here still lands in "Other" so it never
# silently disappears, and tests/test_docs_center.py fails until it is filed.
NAV = [
    ("Start here", "What VEYRS is and how to use it day to day",
     ["README", "USER_GUIDE", "USER_MANUAL", "APP_FLOW", "ADMIN_GUIDE"]),
    ("Requirements & architecture", "What VEYRS needs, how it is built, its data and API",
     ["TECHNICAL_REQUIREMENTS", "ARCHITECTURE", "DATABASE", "DATABASE_SCHEMA", "API", "INTEGRATIONS"]),
    ("Design & brand", "Colours, logo, tokens, components and display formats",
     ["BRAND", "DESIGN_SYSTEM"]),
    ("Install & operate", "Installation, deployment, availability and recovery",
     ["DEPLOYMENT", "DOCKER_COMPOSE_MANUAL", "SYSTEM_MANUAL", "HIGH_AVAILABILITY", "DISASTER_RECOVERY"]),
    ("Security", "Controls, threat model and AI safeguards",
     ["SECURITY", "THREAT_MODEL", "AI_SECURITY"]),
    ("Engineering", "How VEYRS is developed, tested, planned and released",
     ["DEVELOPMENT", "TESTING_GUIDE", "IMPLEMENTATION_PLAN", "CONTRIBUTING", "CHANGELOG"]),
]

# Display names where title-casing the file name reads wrong.
TITLES = {
    "README": "Overview",
    "API": "API",
    "AI_SECURITY": "AI Security",
    "APP_FLOW": "App Flow",
    "DOCKER_COMPOSE_MANUAL": "Docker Compose Manual",
}


def title_of(name):
    return TITLES.get(name, name.replace("_", " ").title())


# --------------------------------------------------------------------------
# Markdown → HTML. Deliberately a small, predictable subset.
# --------------------------------------------------------------------------
def _inline(text):
    text = html.escape(text, quote=False)
    # Code spans are set aside first, so an asterisk inside one is never
    # taken for emphasis, and restored last.
    codes = []

    def stash(m):
        codes.append(m.group(1))
        return f"\x00{len(codes) - 1}\x00"

    text = re.sub(r"`([^`]+)`", stash, text)
    # Bold may contain italics (`**from the *last* run**`): `[^*]+` refused
    # those and left the asterisks on the page.
    text = re.sub(r"\*\*(?=\S)(.+?)(?<=\S)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"(?<![*\w])\*([^*\n]+)\*(?!\w)", r"<em>\1</em>", text)
    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r'<a href="\2">\1</a>', text)
    return re.sub(r"\x00(\d+)\x00", lambda m: f"<code>{codes[int(m.group(1))]}</code>", text)


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
# Page chrome. The header mark is the real brand bitmap (BRAND.md, "Logo");
# the inline SVG shield this replaced was an early placeholder drawn in the
# operator's generic blue/violet, not in VEYRS colours.
HEAD = """<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>{title} — VEYRS Docs Center</title>
<link rel="stylesheet" href="/static/veyrs-tokens.css">
<link rel="stylesheet" href="/static/veyrs.css?v={asset_v}">
<link rel="icon" href="/static/veyrs-favicon.png" type="image/png">
</head><body>
<a class="skip" href="#main">Skip to content</a>
<header class="topbar">
  <a class="brand" href="/">{mark}<span class="brand-text"><b>VEYRS</b><i>Docs Center</i></span></a>
  <form class="topsearch" action="/search.html" method="get" role="search">
    <input type="search" name="q" placeholder="Search the docs" aria-label="Search the docs" autocomplete="off">
  </form>
  <button class="navtoggle" aria-label="Toggle navigation" aria-expanded="false">☰</button>
</header>"""

FOOT = """<footer class="docfoot">
      <span>VEYRS Docs Center · internal documentation · {version}</span>
      <span>Source: <a href="https://github.com/visionebc/veyrs">visionebc/veyrs</a></span>
    </footer>"""

PAGE = HEAD + """
<div class="shell">
  <nav class="sidebar" aria-label="Documentation">{nav}</nav>
  <main id="main">
    <article class="doc">{body}</article>
    """ + FOOT + """
  </main>
  <aside class="toc" aria-label="On this page">{toc}</aside>
</div>
<script src="/static/veyrs.js?v={asset_v}" defer></script>
</body></html>"""

WIDE = HEAD + """
<div class="shell wide">
  <nav class="sidebar" aria-label="Documentation">{nav}</nav>
  <main id="main">
    {body}
    """ + FOOT + """
  </main>
</div>
<script src="/static/veyrs.js?v={asset_v}" defer></script>
</body></html>"""

MARK = '<img class="mark" src="/static/veyrs-mark-gradient.png" alt="" width="36" height="23">'

_HEX = re.compile(r"<code>(#[0-9A-Fa-f]{6})</code>")


def swatches(body):
    """Put a colour chip in front of every `#RRGGBB` code span.

    The docs site serves no CSP, so the chip's colour is an inline style. The
    product site renders the same Markdown and does NOT call this.
    """
    return _HEX.sub(lambda m: f'<span class="swatch" style="background:{m.group(1)}" aria-hidden="true"></span><code>{m.group(1)}</code>', body)


def _summary(md):
    """First prose paragraph after the title, as plain text (cards, search)."""
    for block in re.split(r"\n\s*\n", md):
        b = block.strip()
        if not b or b.startswith(("#", "|", "```", "-", "*", ">", "<")) or re.match(r"^\d+\.", b):
            continue
        text = re.sub(r"`([^`]*)`", r"\1", " ".join(b.split()))
        text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
        text = re.sub(r"[*_]{1,2}([^*_]+)[*_]{1,2}", r"\1", text)
        return text if len(text) <= 180 else text[:177].rsplit(" ", 1)[0] + "…"
    return ""


def _plain(html_body):
    return " ".join(html.unescape(re.sub(r"<[^>]+>", " ", html_body)).split())


def _version():
    try:
        txt = open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8").read()
        m = re.search(r'^version\s*=\s*"([^"]+)"', txt, flags=re.M)
        return "v" + m.group(1) if m else ""
    except OSError:
        return ""


def _asset_version():
    h = hashlib.sha256()
    for f in ("veyrs.css", "veyrs.js"):
        with open(os.path.join(ROOT, "site", "static", f), "rb") as fh:
            h.update(fh.read())
    return h.hexdigest()[:10]


def build(out_dir):
    names = {f[:-3] for f in os.listdir(DOCS) if f.endswith(".md")}
    grouped, seen = [], set()
    for section, blurb, keys in NAV:
        present = [k for k in keys if k in names]
        seen.update(present)
        if present:
            grouped.append((section, blurb, present))
    adrs = sorted(f[:-3] for f in os.listdir(os.path.join(DOCS, "ADRs")) if f.endswith(".md")) \
        if os.path.isdir(os.path.join(DOCS, "ADRs")) else []
    other = sorted(names - seen)
    if other:
        grouped.append(("Other", "Documents not yet filed in a category", other))

    version, asset_v = _version(), _asset_version()

    def nav_html(active):
        home_cls = ' class="active"' if active == "__home__" else ""
        parts = [f'<div class="navgroup"><ul><li><a href="/"{home_cls}>Docs Center home</a></li></ul></div>']
        for section, _blurb, keys in grouped:
            parts.append(f'<div class="navgroup"><span class="navtitle">{section}</span><ul>')
            for k in keys:
                cls = ' class="active"' if k == active else ""
                parts.append(f'<li><a href="/{k}.html"{cls}>{html.escape(title_of(k))}</a></li>')
            parts.append("</ul></div>")
        if adrs:
            parts.append('<div class="navgroup"><span class="navtitle">Decision records</span><ul>')
            for a in adrs:
                cls = ' class="active"' if a == active else ""
                parts.append(f'<li><a href="/adr/{a}.html"{cls}>{html.escape(a)}</a></li>')
            parts.append("</ul></div>")
        return "".join(parts)

    os.makedirs(out_dir, exist_ok=True)
    static_out = os.path.join(out_dir, "static")
    if os.path.isdir(static_out):
        shutil.rmtree(static_out)
    shutil.copytree(os.path.join(ROOT, "site", "static"), static_out)

    written = 0
    targets = [(n, os.path.join(DOCS, n + ".md"), os.path.join(out_dir, n + ".html"), "/" + n + ".html")
               for n in sorted(names)]
    for a in adrs:
        os.makedirs(os.path.join(out_dir, "adr"), exist_ok=True)
        targets.append((a, os.path.join(DOCS, "ADRs", a + ".md"),
                        os.path.join(out_dir, "adr", a + ".html"), "/adr/" + a + ".html"))

    index, summaries = [], {}
    section_of = {k: s for s, _b, keys in grouped for k in keys}
    for name, src, dst, url in targets:
        md = open(src, encoding="utf-8").read()
        body, toc = render(md)
        body = swatches(body)
        summaries[url] = _summary(md)
        toc_html = ""
        if toc:
            toc_html = '<span class="tocTitle">On this page</span><ul>' + "".join(
                f'<li class="l{l}"><a href="#{s}">{html.escape(t)}</a></li>' for l, t, s in toc
            ) + "</ul>"
        title = title_of(name) if url == "/" + name + ".html" else ("Decision records index" if name == "README" else name)
        open(dst, "w", encoding="utf-8").write(
            PAGE.format(title=html.escape(title), body=body, nav=nav_html(name), toc=toc_html,
                        mark=MARK, version=version, asset_v=asset_v)
        )
        index.append({
            "t": title, "u": url, "c": section_of.get(name, "Decision records"),
            "s": summaries[url],
            "h": [t for _l, t, _s in toc],
            "x": _plain(body)[:4000],
        })
        written += 1

    with open(os.path.join(out_dir, "search-index.json"), "w", encoding="utf-8") as fh:
        json.dump(index, fh, ensure_ascii=False, separators=(",", ":"))

    # Home: one card per category, every doc with its first-paragraph summary.
    cards = []
    for section, blurb, keys in grouped:
        items = "".join(
            f'<li><a href="/{k}.html">{html.escape(title_of(k))}</a>'
            f'<span>{html.escape(summaries.get("/" + k + ".html", ""))}</span></li>' for k in keys)
        cards.append(f'<section class="dc-card"><h2>{html.escape(section)}</h2>'
                     f'<p class="dc-blurb">{html.escape(blurb)}</p><ul>{items}</ul></section>')
    if adrs:
        items = "".join(f'<li><a href="/adr/{a}.html">{html.escape(a)}</a>'
                        f'<span>{html.escape(summaries.get("/adr/" + a + ".html", ""))}</span></li>' for a in adrs)
        cards.append('<section class="dc-card"><h2>Decision records</h2>'
                     f'<p class="dc-blurb">Architecture decisions and why they were taken</p><ul>{items}</ul></section>')
    home = (
        '<div class="dc-hero"><h1>VEYRS Docs Center</h1>'
        f'<p>Every VEYRS document in one place — {len(targets)} pages in {len(cards)} categories, '
        f'for VEYRS {html.escape(version)}.</p>'
        '<form class="dc-search" action="/search.html" method="get" role="search">'
        '<input type="search" name="q" placeholder="Search every document…" aria-label="Search every document">'
        '<button type="submit">Search</button></form></div>'
        '<div class="dc-grid">' + "".join(cards) + "</div>"
    )
    open(os.path.join(out_dir, "index.html"), "w", encoding="utf-8").write(
        WIDE.format(title="Home", body=home, nav=nav_html("__home__"), mark=MARK,
                    version=version, asset_v=asset_v))
    search = (
        '<div class="dc-hero small"><h1>Search</h1>'
        '<form class="dc-search" action="/search.html" method="get" role="search">'
        '<input type="search" name="q" id="dc-q" placeholder="Search every document…" aria-label="Search every document">'
        '<button type="submit">Search</button></form></div>'
        '<p id="dc-count" class="dc-count" aria-live="polite"></p><ol id="dc-results" class="dc-results"></ol>'
        '<noscript><p>Search needs JavaScript. Browse the categories on the <a href="/">home page</a>.</p></noscript>'
    )
    open(os.path.join(out_dir, "search.html"), "w", encoding="utf-8").write(
        WIDE.format(title="Search", body=search, nav=nav_html(""), mark=MARK,
                    version=version, asset_v=asset_v))
    return written


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="/var/www/veyrs")
    args = ap.parse_args()
    n = build(args.out)
    print(f"built {n} pages + home + search -> {args.out}")
