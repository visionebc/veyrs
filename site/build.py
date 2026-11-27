#!/usr/bin/env python3
"""VEYRS documentation portal generator (the "Docs Center").

Renders every Markdown file under docs/ - top-level manuals, decision records
and the domain folders (architecture/, operations/, api/reference/, ...) - into
a static, searchable documentation portal.

Zero third-party dependencies on purpose: the docs host must stay trivially
reproducible and auditable (see docs/SECURITY.md, "build toolchain"). Mermaid
diagrams are NOT rendered here (that needs Node): scripts/render-diagrams.py
pre-renders each ```mermaid block to docs/diagrams/rendered/<hash>.svg on a
development machine, and this builder only links the SVG whose hash matches
the block. A block without its SVG is shown as source with a warning.

Usage:  python3 site/build.py [--out /var/www/veyrs]
        (builds beside --out and swaps it in atomically; the previous tree stays in <out>.prev)

Design: site/design-system/veyrs-docs/MASTER.md (UI UX Pro Max, Minimalism &
Swiss Style for documentation) with the deviations recorded in
site/design-system/veyrs-docs/pages/portal.md.
"""
import argparse
import hashlib
import html
import json
import os
import posixpath
import re
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCS = os.path.join(ROOT, "docs")
RENDERED = os.path.join(DOCS, "diagrams", "rendered")

SITE_URL = "https://veyrs-web.example.com"
CONSOLE_URL = "https://veyrs-app-1.example.com"
SOURCE_URL = "https://github.com/visionebc/veyrs"
SOURCE_BRANCH = "release/0.27.0"

# --------------------------------------------------------------------------
# Information architecture. Every document belongs to exactly one domain:
# by its key (path under docs/ without .md) or by its folder. A document that
# matches nothing lands in "Other", and tests/test_docs_center.py fails until
# it is filed. Order inside a domain: the keys in the order listed, then the
# folders' documents (README first, then by title).
# --------------------------------------------------------------------------
DOMAINS = [
    ("start", "Start here", "What VEYRS is, who it is for and how to read these documents",
     ["README", "executive/README", "executive/overview"], ["executive/"]),
    ("product", "Product & features", "Every function of the console and the API, how it works and who may use it",
     ["USER_GUIDE", "USER_MANUAL", "APP_FLOW", "ADMIN_GUIDE"], ["functional/", "frontend/"]),
    ("architecture", "Architecture", "How VEYRS is built: components, C4 views, data flows and trust boundaries",
     ["architecture/README", "architecture/overview", "ARCHITECTURE", "TECHNICAL_REQUIREMENTS"],
     ["architecture/", "diagrams/"]),
    ("integrations", "Integrations & automation", "Scanners, connectors, feeds, agents, webhooks and scheduled jobs",
     ["INTEGRATIONS"], ["integrations/"]),
    ("api", "API", "Conventions, authentication and every endpoint, generated from the code",
     ["API", "api/README", "api/guide"], ["api/"]),
    ("data", "Data", "Schema, tenancy, row-level security, lifecycle and the data dictionary",
     ["DATABASE", "database/README", "DATABASE_SCHEMA"], ["database/"]),
    ("operate", "Install & operate", "Installation, configuration, deployment, availability, backup and recovery",
     ["operations/README", "operations/installation", "DEPLOYMENT", "DOCKER_COMPOSE_MANUAL", "SYSTEM_MANUAL",
      "HIGH_AVAILABILITY", "DISASTER_RECOVERY"], ["operations/", "deployment/", "infrastructure/", "internal/"]),
    ("troubleshooting", "Troubleshooting", "Symptoms, causes, diagnostic commands and fixes",
     ["troubleshooting/README"], ["troubleshooting/"]),
    ("security", "Security", "Security architecture, threat model, AI safeguards and known risks",
     ["security/README", "SECURITY", "THREAT_MODEL", "AI_SECURITY"], ["security/"]),
    ("engineering", "Engineering", "Developing, testing, releasing and maintaining VEYRS",
     ["DEVELOPMENT", "CONTRIBUTING", "TESTING_GUIDE", "IMPLEMENTATION_PLAN", "CHANGELOG"],
     ["development/", "testing/"]),
    ("design", "Design & brand", "Brand, design tokens, console UI and accessibility",
     ["BRAND", "DESIGN_SYSTEM"], ["design/"]),
    ("reference", "Reference", "Configuration, permissions, inventory, traceability, coverage and glossary",
     ["reference/glossary", "reference/configuration", "reference/permissions", "reference/inventory",
      "reference/traceability", "reference/coverage"], ["reference/"]),
    ("audit", "Documentation audit", "What was verified, what was not, inconsistencies, risks and debt",
     ["audit/README"], ["audit/"]),
    ("adr", "Decision records", "Architecture decisions and why they were taken", ["ADRs/README"], ["ADRs/"]),
]

# Kept for compatibility with older callers: the top-level manuals by domain.
NAV = [(title, blurb, [k for k in keys if "/" not in k]) for _s, title, blurb, keys, _d in DOMAINS]

# Display names where title-casing the file name reads wrong (no front matter).
TITLES = {
    "README": "Overview",
    "API": "API guide",
    "AI_SECURITY": "AI Security",
    "APP_FLOW": "App Flow",
    "DOCKER_COMPOSE_MANUAL": "Docker Compose Manual",
}

STATUS_WORDS = ("Verified", "Implemented", "Partial", "Planned", "Obsolete", "Unknown")


def title_of(name):
    base = name.rsplit("/", 1)[-1]
    return TITLES.get(name, base.replace("_", " ").replace("-", " ").title() if base.isupper()
                      else base.replace("-", " ").replace("_", " ").capitalize())


def slugify(text):
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def gh_slug(text):
    """Heading id the way GitHub and Gitea compute it, so an anchor written
    for the repository view also works in the portal: markup dropped,
    lowercased, punctuation removed (underscores and hyphens kept), spaces
    become hyphens. Duplicates get -1, -2 ... (see _Ctx.unique)."""
    t = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)
    t = re.sub(r"[`*]", "", t).strip().lower()
    t = re.sub(r"[^\w\- ]", "", t)
    return t.replace(" ", "-")


# --------------------------------------------------------------------------
# Front matter
# --------------------------------------------------------------------------
_FM = re.compile(r"\A---\n(.*?)\n---[ \t]*\n", re.S)


def parse_front_matter(md):
    """Return (meta dict, body). Lists are written `[a, b]`."""
    m = _FM.match(md)
    if not m:
        return {}, md
    meta = {}
    for line in m.group(1).splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        v = v.strip()
        if v.startswith("[") and v.endswith("]"):
            v = [x.strip() for x in v[1:-1].split(",") if x.strip()]
        meta[k.strip()] = v
    return meta, md[m.end():]


# --------------------------------------------------------------------------
# Syntax highlighting (build time, small and predictable)
# --------------------------------------------------------------------------
_S_DQ = r'"(?:[^"\\\n]|\\.)*"'
_S_SQ = r"'(?:[^'\\\n]|\\.)*'"
_NUM = r"\b\d+(?:\.\d+)?\b"
_LANGS = {
    "bash": [("c", r"(?<![\w$])#.*"), ("s", _S_DQ + "|" + _S_SQ), ("v", r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|\$\(|\$\d"),
             ("k", r"\b(?:if|then|else|elif|fi|for|in|do|done|while|case|esac|function|return|export|local|set|unset|sudo|cd|exit)\b"),
             ("f", r"(?:(?<=^)|(?<=[|;&]\s)|(?<=\$\()|(?<=&&\s)|(?<=\|\|\s))[A-Za-z0-9_./-]+"),
             ("o", r"(?<=\s)--?[A-Za-z0-9][\w-]*")],
    "python": [("c", r"#.*"), ("s", r'"""[\s\S]*?"""|\'\'\'[\s\S]*?\'\'\'|[rbfRBF]?' + _S_DQ + r"|[rbfRBF]?" + _S_SQ),
               ("k", r"\b(?:def|class|return|if|elif|else|for|while|in|import|from|as|with|try|except|finally|raise|"
                     r"yield|lambda|None|True|False|and|or|not|is|async|await|pass|break|continue|global)\b"),
               ("n", _NUM), ("f", r"\b[A-Za-z_]\w*(?=\()"), ("d", r"@[\w.]+")],
    "json": [("p", _S_DQ + r"(?=\s*:)"), ("s", _S_DQ), ("k", r"\b(?:true|false|null)\b"), ("n", r"-?" + _NUM)],
    "yaml": [("c", r"(?<!\S)#.*"), ("p", r"^[ \t-]*[A-Za-z0-9_.\"'-]+(?=\s*:(?:\s|$))"), ("s", _S_DQ + "|" + _S_SQ),
             ("k", r"\b(?:true|false|null|yes|no)\b"), ("n", _NUM)],
    "sql": [("c", r"--.*"), ("s", _S_SQ),
            ("k", r"(?i:\b(?:select|from|where|and|or|not|insert|into|values|update|set|delete|create|table|index|"
                  r"alter|add|column|drop|on|using|policy|enable|force|row|level|security|grant|revoke|to|as|join|left|"
                  r"inner|group|by|order|limit|null|is|primary|key|references|cascade|unique|default|begin|commit|"
                  r"with|returning|count|distinct|having|case|when|then|else|end|exists|in|like|text|uuid|current_setting)\b)"),
            ("n", _NUM)],
    "ini": [("c", r"^\s*[#;].*"), ("h", r"^\s*\[[^\]]+\]"), ("p", r"^\s*[A-Za-z0-9_.-]+(?=\s*=)"), ("s", _S_DQ + "|" + _S_SQ)],
    "nginx": [("c", r"#.*"), ("s", _S_DQ + "|" + _S_SQ), ("v", r"\$[A-Za-z_]\w*"),
              ("k", r"\b(?:server|location|listen|server_name|root|alias|proxy_pass|proxy_set_header|return|rewrite|"
                    r"add_header|include|upstream|ssl_certificate|ssl_certificate_key|expires|try_files|index|"
                    r"default_server|backup|if|set|map|limit_req|client_max_body_size)\b"), ("n", _NUM)],
    "http": [("k", r"^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b|^HTTP/[\d.]+"), ("p", r"^[A-Za-z-]+(?=:\s)"),
             ("s", _S_DQ), ("n", r"\b[1-5]\d\d\b")],
}
_ALIASES = {"sh": "bash", "shell": "bash", "console": "bash", "zsh": "bash", "py": "python", "yml": "yaml",
            "toml": "ini", "env": "ini", "conf": "ini", "systemd": "ini", "dotenv": "ini", "psql": "sql",
            "postgresql": "sql"}
_COMPILED = {}


def highlight(code, lang):
    """HTML for `code` with token spans. Unknown languages are escaped only."""
    lang = _ALIASES.get(lang.lower(), lang.lower())
    rules = _LANGS.get(lang)
    if not rules:
        return html.escape(code)
    rx = _COMPILED.get(lang)
    if rx is None:
        rx = _COMPILED[lang] = re.compile("|".join(f"(?P<t{i}>{p})" for i, (_c, p) in enumerate(rules)), re.M)
    out, pos = [], 0
    for m in rx.finditer(code):
        if m.start() == m.end():
            continue
        out.append(html.escape(code[pos:m.start()]))
        cls = rules[int(m.lastgroup[1:])][0]
        out.append(f'<span class="tk-{cls}">{html.escape(m.group())}</span>')
        pos = m.end()
    out.append(html.escape(code[pos:]))
    return "".join(out)


def mermaid_hash(source):
    """Content hash shared with scripts/render-diagrams.py."""
    return hashlib.sha256((source.strip() + "\n").encode("utf-8")).hexdigest()[:16]


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
    text = re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)", r'<a href="\2">\1</a>', text)
    return re.sub(r"\x00(\d+)\x00", lambda m: f"<code>{codes[int(m.group(1))]}</code>", text)


def _cells(r):
    # A pipe escaped as `\|` belongs to the cell, not to the table.
    s = r.strip()
    if s.startswith("|"):
        s = s[1:]
    if s.endswith("|") and not s.endswith("\\|"):
        s = s[:-1]
    return [c.strip().replace("\\|", "|") for c in re.split(r"(?<!\\)\|", s)]


def _status_cell(c, rich):
    inner = _inline(c)
    if rich and c.strip() in STATUS_WORDS:
        w = c.strip()
        return f'<span class="badge st-{w.lower()}">{w}</span>'
    return inner


def _table(rows, rich=False):
    head, body = rows[0], rows[2:]
    out = ['<div class="tablewrap" tabindex="0" role="region" aria-label="Table">' if rich else "", "<table><thead><tr>"]
    out += [f"<th>{_inline(c)}</th>" for c in _cells(head)]
    out.append("</tr></thead><tbody>")
    for r in body:
        out.append("<tr>" + "".join(f"<td>{_status_cell(c, rich)}</td>" for c in _cells(r)) + "</tr>")
    out.append("</tbody></table>" + ("</div>" if rich else ""))
    return "".join(out)


_ITEM = re.compile(r"^\s*(?:[-*]|\d+\.)\s+")
_CALLOUT = re.compile(r"^\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\]\s*$")
CALLOUT_ICON = {
    "NOTE": '<path d="M12 16v-4M12 8h.01"/><circle cx="12" cy="12" r="10"/>',
    "TIP": '<path d="M9 18h6M10 22h4M12 2a7 7 0 0 0-4 12.7V17h8v-2.3A7 7 0 0 0 12 2z"/>',
    "IMPORTANT": '<path d="M12 8v4M12 16h.01"/><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>',
    "WARNING": '<path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0zM12 9v4M12 17h.01"/>',
    "CAUTION": '<path d="M7.9 2h8.2L22 7.9v8.2L16.1 22H7.9L2 16.1V7.9z"/><path d="M12 8v4M12 16h.01"/>',
}


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


class _Ctx:
    """Per-document render state for the portal (rich) mode."""

    def __init__(self):
        self.ids = {}
        self.mermaid = []  # (hash, source)

    def unique(self, slug):
        n = self.ids.get(slug, 0)
        self.ids[slug] = n + 1
        return slug if n == 0 else f"{slug}-{n}"


def _mermaid_figure(src):
    h = mermaid_hash(src)
    svg = os.path.join(RENDERED, h + ".svg")
    code = html.escape(src.strip())
    if not os.path.isfile(svg):
        return (f'<div class="callout callout-warning" role="note"><p class="callout-title">Diagram not rendered</p>'
                f'<p>No pre-rendered SVG for this diagram (hash <code>{h}</code>). Run '
                f'<code>python3 scripts/render-diagrams.py</code> on a machine with Node and mermaid-cli.</p></div>'
                f'<pre class="code" data-lang="mermaid"><code>{code}</code></pre>'), h
    return (f'<figure class="diagram"><a class="diagram-img" href="/diagrams/{h}.svg" target="_blank" rel="noopener" '
            f'aria-label="Open the diagram full size in a new tab"><img src="/diagrams/{h}.svg" alt="Diagram (Mermaid source below)" loading="lazy"></a>'
            f'<figcaption><a href="/diagrams/{h}.svg" target="_blank" rel="noopener">Open full size</a>'
            f'<details><summary>Mermaid source</summary><pre class="code" data-lang="mermaid"><code>{code}</code></pre></details>'
            f'</figcaption></figure>'), h


def render(md, rich=False, _ctx=None):
    """Markdown → (html, toc). `rich=True` is the portal's mode: highlighted
    code, callouts with icons, Mermaid figures, wrapped tables, status badges
    and de-duplicated heading ids. The default stays the plain subset the
    product site (site/web/build_web.py) renders. Front matter is stripped in
    both modes."""
    if _ctx is None:
        md = parse_front_matter(md)[1]
        _ctx = _Ctx() if rich else None
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
            raw = "\n".join(buf)
            if rich and lang == "mermaid":
                fig, h = _mermaid_figure(raw)
                _ctx.mermaid.append(h)
                out.append(fig)
            elif rich:
                label = f'<span class="lang">{html.escape(lang)}</span>' if lang else ""
                out.append(f'<div class="codeblock">{label}<pre class="code" data-lang="{html.escape(lang)}">'
                           f'<code>{highlight(raw, lang)}</code></pre></div>')
            else:
                out.append(f'<pre class="code" data-lang="{html.escape(lang)}"><code>{html.escape(raw)}</code></pre>')
            i += 1
            continue

        if (line.lstrip().startswith("|") and i + 1 < len(lines)
                and lines[i + 1].lstrip().startswith("|")
                and set(lines[i + 1].replace("|", "").strip()) <= set("-: ")):
            block = []
            while i < len(lines) and lines[i].lstrip().startswith("|"):
                block.append(lines[i])
                i += 1
            out.append(_table(block, rich))
            continue

        m = re.match(r"^(#{1,4})\s+(.*)$", line)
        if m:
            lvl, txt = len(m.group(1)), m.group(2).strip()
            if rich:
                slug = _ctx.unique(gh_slug(txt))
            else:
                slug = re.sub(r"[^a-z0-9]+", "-", txt.lower()).strip("-")
            if lvl in (2, 3):
                toc.append((lvl, txt, slug))
            if rich and lvl > 1:
                out.append(f'<h{lvl} id="{slug}">{_inline(txt)}<a class="anchor" href="#{slug}" '
                           f'aria-label="Link to this section">#</a></h{lvl}>')
            else:
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

        if line.startswith("> ") or line.strip() == ">":
            # The quote's contents are Markdown too: a bare ">" separates
            # paragraphs and a quote may hold a fence. Both used to end the
            # quote and leak out as a literal "&gt;" or "```" paragraph.
            buf = []
            while i < len(lines) and (lines[i].startswith("> ") or lines[i].strip() == ">"):
                buf.append(lines[i][2:])
                i += 1
            kind = _CALLOUT.match(buf[0].strip()) if buf else None
            if kind:
                k = kind.group(1)
                inner = render("\n".join(buf[1:]), rich, _ctx)[0]
                icon = (f'<svg class="ico" viewBox="0 0 24 24" aria-hidden="true">{CALLOUT_ICON[k]}</svg>'
                        if rich else "")
                out.append(f'<blockquote class="callout callout-{k.lower()}"><p class="callout-title">{icon}'
                           f'{k.capitalize()}</p>{inner}</blockquote>')
                continue
            inner = render("\n".join(buf), rich, _ctx)[0]
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
# Documents
# --------------------------------------------------------------------------
def url_of(key):
    if key.startswith("ADRs/"):
        return "/adr/" + key[5:] + ".html"
    return "/" + key + ".html"


def discover():
    keys = []
    for dirpath, dirnames, filenames in os.walk(DOCS):
        dirnames[:] = sorted(d for d in dirnames if d not in ("rendered", "__pycache__") and not d.startswith("."))
        for f in sorted(filenames):
            if f.endswith(".md"):
                rel = os.path.relpath(os.path.join(dirpath, f), DOCS)[:-3].replace(os.sep, "/")
                keys.append(rel)
    return keys


def domain_of(key):
    for slug, _t, _b, keys, dirs in DOMAINS:
        if key in keys:
            return slug
    for slug, _t, _b, keys, dirs in DOMAINS:
        if any(key.startswith(d) for d in dirs):
            return slug
    return None


def file_docs(keys=None):
    """{domain slug: [keys in reading order]} plus "other" for unfiled keys."""
    keys = discover() if keys is None else keys
    titles = {}
    for k in keys:
        try:
            meta, body = parse_front_matter(open(os.path.join(DOCS, k + ".md"), encoding="utf-8").read())
        except OSError:
            meta, body = {}, ""
        titles[k] = doc_title(k, meta, body)
    grouped = {}
    for slug, _t, _b, explicit, dirs in DOMAINS:
        mine = [k for k in keys if domain_of(k) == slug]
        ordered = [k for k in explicit if k in mine]
        rest = [k for k in mine if k not in ordered]
        rest.sort(key=lambda k: (k.count("/"), k.rsplit("/", 1)[0], not k.endswith("/README"),
                                 "README" != k.rsplit("/", 1)[-1], titles[k].lower()))
        grouped[slug] = ordered + rest
    other = [k for k in keys if domain_of(k) is None]
    if other:
        grouped["other"] = other
    return grouped


def doc_title(key, meta, body):
    if meta.get("title"):
        return meta["title"]
    m = re.search(r"^#\s+(.+)$", body, flags=re.M)
    if m and key not in TITLES and not key.startswith("ADRs/"):
        return re.sub(r"[`*]", "", m.group(1)).strip()
    if key.startswith("ADRs/") and key != "ADRs/README":
        return key[5:]
    if key == "ADRs/README":
        return "Decision records index"
    return title_of(key)


# --------------------------------------------------------------------------
# Page chrome
# --------------------------------------------------------------------------
ICON = {
    "search": '<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>',
    "sun": '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
    "moon": '<path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/>',
    "menu": '<path d="M4 6h16M4 12h16M4 18h16"/>',
    "ext": '<path d="M14 4h6v6M10 14 20 4M19 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1h5"/>',
    "left": '<path d="m15 18-6-6 6-6"/>', "right": '<path d="m9 18 6-6-6-6"/>',
    "file": '<path d="M14 3H6a1 1 0 0 0-1 1v16a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V8z"/><path d="M14 3v5h5"/>',
    "start": '<path d="M5 12h14M13 6l6 6-6 6"/>',
    "product": '<rect x="3" y="4" width="18" height="14" rx="2"/><path d="M3 9h18"/>',
    "architecture": '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="8.5" y="14" width="7" height="7" rx="1"/><path d="M6.5 10v2h11v-2M12 12v2"/>',
    "integrations": '<path d="M9 7H6a3 3 0 0 0 0 6h3M15 7h3a3 3 0 0 1 0 6h-3M8 10h8"/>',
    "api": '<path d="m8 8-4 4 4 4M16 8l4 4-4 4M14 5l-4 14"/>',
    "data": '<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/>',
    "operate": '<path d="M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/>',
    "troubleshooting": '<path d="M14.7 6.3a4 4 0 0 0-5.4 5.4L3 18l3 3 6.3-6.3a4 4 0 0 0 5.4-5.4l-2.5 2.5-2.5-.5-.5-2.5z"/>',
    "security": '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
    "engineering": '<path d="m16 18 6-6-6-6M8 6l-6 6 6 6"/>',
    "design": '<circle cx="13.5" cy="6.5" r="1.5"/><circle cx="17.5" cy="10.5" r="1.5"/><circle cx="8.5" cy="7.5" r="1.5"/><circle cx="6.5" cy="12.5" r="1.5"/><path d="M12 2a10 10 0 0 0 0 20c1 0 1.6-.8 1.6-1.7 0-.4-.2-.8-.4-1.1-.3-.3-.4-.7-.4-1.1 0-.9.8-1.7 1.7-1.7h2A5.5 5.5 0 0 0 22 11c0-5-4.5-9-10-9z"/>',
    "reference": '<path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20V3H6.5A2.5 2.5 0 0 0 4 5.5z"/><path d="M4 19.5A2.5 2.5 0 0 0 6.5 22H20v-5"/>',
    "audit": '<path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/>',
    "adr": '<path d="M12 3v18M3 7h18M6 7l-3 7a3 3 0 0 0 6 0zM18 7l-3 7a3 3 0 0 0 6 0z"/>',
    "other": '<circle cx="12" cy="12" r="10"/>',
}


def icon(name, cls="ico"):
    return f'<svg class="{cls}" viewBox="0 0 24 24" aria-hidden="true" focusable="false">{ICON.get(name, ICON["other"])}</svg>'


HEAD = """<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<meta name="color-scheme" content="light dark">
<title>{title} · VEYRS Docs Center</title>
<script src="/static/theme.js?v={asset_v}"></script>
<link rel="preload" href="/static/fonts/inter-regular.woff2" as="font" type="font/woff2" crossorigin>
<link rel="stylesheet" href="/static/veyrs.css?v={asset_v}">
<link rel="icon" href="/static/veyrs-favicon.png" type="image/png">
</head><body class="{body_class}">
<a class="skip" href="#main">Skip to content</a>
<header class="topbar">
  <div class="topbar-inner">
    <button class="iconbtn sidetoggle" type="button" aria-label="Open the documentation menu" aria-expanded="false" aria-controls="sidebar">{i_menu}</button>
    <a class="brand" href="/">{mark}<span class="brand-name">VEYRS</span><span class="brand-sub">Docs Center</span></a>
    <form class="topsearch" action="/search.html" method="get" role="search">
      <label class="sr-only" for="topq">Search the documentation</label>
      {i_search}<input id="topq" type="search" name="q" placeholder="Search the docs" autocomplete="off"><kbd aria-hidden="true">/</kbd>
    </form>
    <nav class="sitelinks" aria-label="VEYRS">{sitenav}</nav>
    <button class="iconbtn themetoggle" type="button" aria-label="Switch between light and dark theme">{i_sun}{i_moon}</button>
    <a class="console" href="{console}">Console{i_ext}</a>
  </div>
</header>"""

FOOT = """<footer class="sitefoot">
  <div class="foot-inner">
    <img src="/static/veyrs-logo-on-dark-gradient.png" alt="VEYRS" width="140" height="35">
    <p>Unified Cybersecurity Risk Management · Docs Center · {version}<br>Built from <code>docs/</code> by <code>site/build.py</code>. Source of truth: the code.</p>
    <nav class="foot-links" aria-label="More">
      <a href="/">Docs Center home</a><a href="/reference/coverage.html">Coverage index</a>
      <a href="{site}/">Product site</a><a href="{source}">Source repository</a>
    </nav>
  </div>
</footer>
<script src="/static/veyrs.js?v={asset_v}" defer></script>
</body></html>"""

PAGE = HEAD + """
<div class="shell">
  <nav class="sidebar" id="sidebar" aria-label="Documentation">{nav}</nav>
  <main id="main" tabindex="-1">
    <article class="doc">
      <nav class="crumbs" aria-label="Breadcrumb">{crumbs}</nav>
      <header class="dochead">{dochead}</header>
      <details class="toc-inline"><summary>On this page</summary>{toc_inline}</details>
      <div class="prose">{body}</div>
      {related}
      <nav class="pager" aria-label="Previous and next">{pager}</nav>
    </article>
  </main>
  <aside class="toc" aria-label="On this page">{toc}</aside>
</div>
""" + FOOT

WIDE = HEAD + """
<div class="shell wide">
  <nav class="sidebar" id="sidebar" aria-label="Documentation">{nav}</nav>
  <main id="main" tabindex="-1">{body}</main>
</div>
""" + FOOT

MARK = '<img class="mark" src="/static/veyrs-mark-gradient.png" alt="" width="28" height="18">'


def site_nav():
    """The product site's navigation links, with Docs pointing at this site."""
    sys.path.insert(0, os.path.join(ROOT, "site", "web"))
    try:
        from build_web import NAV as SITE_NAV  # noqa: E402  (sibling builder)
    finally:
        sys.path.pop(0)
    links = []
    for href, label in SITE_NAV:
        if href == "docs.html":
            links.append(f'<a href="/" class="active" aria-current="true">{html.escape(label)}</a>')
        else:
            links.append(f'<a href="{SITE_URL}/{href}">{html.escape(label)}</a>')
    return "".join(links)


_HEX = re.compile(r"<code>(#[0-9A-Fa-f]{6})</code>")


def swatches(body):
    """Put a colour chip in front of every `#RRGGBB` code span.

    The docs site serves no CSP, so the chip's colour is an inline style. The
    product site renders the same Markdown and does NOT call this.
    """
    return _HEX.sub(lambda m: f'<span class="swatch" style="background:{m.group(1)}" aria-hidden="true"></span><code>{m.group(1)}</code>', body)


_H1 = re.compile(r"^\s*<h1[^>]*>(.*?)</h1>\s*", re.S)


def split_title(body):
    """The document's own `# Title` moves into the page header."""
    m = _H1.match(body)
    return (m.group(1), body[m.end():]) if m else (None, body)


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
        return m.group(1) if m else ""
    except OSError:
        return ""


def _asset_version():
    h = hashlib.sha256()
    for f in ("veyrs.css", "veyrs.js", "theme.js"):
        with open(os.path.join(ROOT, "site", "static", f), "rb") as fh:
            h.update(fh.read())
    return h.hexdigest()[:10]


def source_href(path):
    path = path.strip().strip("`")
    path = re.sub(r":\d+(?:-\d+)?$", "", path)
    return f"{SOURCE_URL}/src/branch/{SOURCE_BRANCH}/{path.lstrip('./')}"


_HREF = re.compile(r'href="([^"]+)"')


def rewrite_links(body, key, known, copies):
    """Relative .md links → portal URLs; links leaving docs/ → the source tree."""
    base = posixpath.dirname(key)

    def fix(m):
        href = m.group(1)
        if re.match(r"^(?:[a-z][a-z0-9+.-]*:|#|/|doc:)", href):
            return m.group(0)
        path, _, anchor = href.partition("#")
        frag = f"#{anchor}" if anchor else ""
        target = posixpath.normpath(posixpath.join(base, path)) if path else key
        if target.startswith("../") or target == "..":
            repo = posixpath.normpath(posixpath.join("docs", base, path))
            return f'href="{source_href(repo)}{frag}"'
        if target.endswith(".md") and target[:-3] in known:
            return f'href="{url_of(target[:-3])}{frag}"'
        if target in known:
            return f'href="{url_of(target)}{frag}"'
        if (target.rstrip("/") + "/README") in known:
            return f'href="{url_of(target.rstrip("/") + "/README")}{frag}"'
        if os.path.isfile(os.path.join(DOCS, target)):
            copies.add(target)
            return f'href="/{target}{frag}"'
        return m.group(0)  # left as written: the link checker reports it

    return _HREF.sub(fix, body)


def build(out_dir):
    version, asset_v = _version(), _asset_version()
    keys = discover()
    grouped = file_docs(keys)
    known = set(keys)
    dom = {s: (t, b) for s, t, b, _k, _d in DOMAINS}
    dom["other"] = ("Other", "Documents not yet filed in a domain")

    docs = {}
    for k in keys:
        md = open(os.path.join(DOCS, k + ".md"), encoding="utf-8").read()
        meta, body_md = parse_front_matter(md)
        docs[k] = {"meta": meta, "md": body_md, "title": doc_title(k, meta, body_md),
                   "domain": next(s for s, ks in grouped.items() if k in ks)}

    chrome = dict(mark=MARK, version="v" + version if version else "", asset_v=asset_v, sitenav=site_nav(),
                  console=CONSOLE_URL, site=SITE_URL, source=SOURCE_URL, i_menu=icon("menu"),
                  i_search=icon("search", "ico search-ico"), i_sun=icon("sun", "ico i-sun"),
                  i_moon=icon("moon", "ico i-moon"), i_ext=icon("ext", "ico i-ext"))

    def group_label(prefix):
        rk = prefix + "README"
        return docs[rk]["title"] if rk in docs else prefix.rstrip("/").split("/")[-1].replace("-", " ").capitalize()

    def nav_html(active):
        home_attr = ' class="navhome active" aria-current="page"' if active == "__home__" else ' class="navhome"'
        parts = ['<ul class="navroot">',
                 f'<li><a{home_attr} href="/">{icon("start")}Docs Center home</a></li>']
        order = [s for s, *_ in DOMAINS] + (["other"] if "other" in grouped else [])
        for slug in order:
            ks = grouped.get(slug) or []
            if not ks:
                continue
            is_open = active in ks
            parts.append(f'<li class="navdomain"><details{" open" if is_open else ""}><summary>{icon(slug)}'
                         f'<span>{html.escape(dom[slug][0])}</span><span class="count">{len(ks)}</span></summary><ul>')
            # Nested group for folders two levels deep (api/reference/...).
            nested = {}
            for k in ks:
                if k.count("/") >= 2:
                    nested.setdefault(k.rsplit("/", 1)[0] + "/", []).append(k)
            done = set()
            for k in ks:
                if k in done:
                    continue
                prefix = k.rsplit("/", 1)[0] + "/" if k.count("/") >= 2 else None
                if prefix and len(nested.get(prefix, [])) > 1:
                    members = nested[prefix]
                    done.update(members)
                    gopen = active in members
                    parts.append(f'<li class="navgroup"><details{" open" if gopen else ""}><summary>'
                                 f'{html.escape(group_label(prefix))}<span class="count">{len(members)}</span></summary><ul>')
                    for mk in members:
                        parts.append(_nav_item(mk, docs, active, short=True))
                    parts.append("</ul></details></li>")
                    continue
                done.add(k)
                parts.append(_nav_item(k, docs, active))
            parts.append("</ul></details></li>")
        parts.append("</ul>")
        return "".join(parts)

    os.makedirs(out_dir, exist_ok=True)
    static_out = os.path.join(out_dir, "static")
    if os.path.isdir(static_out):
        shutil.rmtree(static_out)
    shutil.copytree(os.path.join(ROOT, "site", "static"), static_out)
    # The fonts are the console's own self-hosted set: one copy in the repo
    # (the public export's binary guard only admits woff2 under
    # frontend/console/fonts/), copied into the portal at build time.
    shutil.copytree(os.path.join(ROOT, "frontend", "console", "fonts"),
                    os.path.join(static_out, "fonts"))
    diag_out = os.path.join(out_dir, "diagrams")
    if os.path.isdir(diag_out):
        shutil.rmtree(diag_out)
    os.makedirs(diag_out)
    # Pages from an older layout would linger forever otherwise.
    for sub in ("adr",) + tuple(sorted({k.split("/")[0] for k in keys if "/" in k and not k.startswith("ADRs/")})):
        p = os.path.join(out_dir, sub)
        if os.path.isdir(p):
            shutil.rmtree(p)

    index, copies, used_svgs = [], set(), set()
    flat = {s: ks for s, ks in grouped.items()}
    for k in keys:
        d = docs[k]
        ctx = _Ctx()
        body, toc = render(d["md"], rich=True, _ctx=ctx)
        used_svgs.update(ctx.mermaid)
        body = swatches(rewrite_links(body, k, known, copies))
        heading, article = split_title(body)
        title = d["title"]
        meta = d["meta"]
        slug = d["domain"]
        dtitle = dom[slug][0]

        crumbs = [f'<a href="/">Docs</a>', f'<span>{html.escape(dtitle)}</span>']
        if k.count("/") >= 2:
            prefix = k.rsplit("/", 1)[0] + "/"
            if prefix + "README" in docs and prefix + "README" != k:
                crumbs.append(f'<a href="{url_of(prefix + "README")}">{html.escape(group_label(prefix))}</a>')
        crumbs.append(f'<span aria-current="page">{html.escape(title)}</span>')
        crumbs_html = '<ol>' + "".join(f"<li>{c}</li>" for c in crumbs) + "</ol>"

        status = meta.get("status", "")
        status_word = status.split("|")[0].strip() if isinstance(status, str) else ""
        badge = (f'<span class="badge st-{status_word.lower()}" title="Document verification state">{status_word}</span>'
                 if status_word in STATUS_WORDS else "")
        ver = meta.get("version", "")
        ver = version if ver in ("current", "") else ver
        facts = [badge] if badge else []
        if ver:
            facts.append(f'<span class="fact">VEYRS {html.escape(ver)}</span>')
        if meta.get("verified"):
            facts.append(f'<span class="fact">Verified <time datetime="{html.escape(meta["verified"])}">'
                         f'{html.escape(meta["verified"])}</time></span>')
        facts.append(f'<a class="fact" href="{source_href("docs/" + k + ".md")}">View source</a>')
        dochead = f'<p class="eyebrow">{icon(slug)}{html.escape(dtitle)}</p><h1>{heading or html.escape(title)}</h1>'
        if meta.get("purpose"):
            dochead += f'<p class="lead">{_inline(meta["purpose"])}</p>'
        dochead += '<div class="facts">' + "".join(facts) + "</div>"
        extra = []
        if meta.get("scope"):
            extra.append(f'<div class="scope"><span>Scope</span><p>{_inline(meta["scope"])}</p></div>')
        srcs = meta.get("sources") or []
        if isinstance(srcs, str):
            srcs = [srcs]
        if srcs:
            items = "".join(
                f'<li><a href="{source_href(s)}"><code>{html.escape(s)}</code></a></li>'
                if not re.match(r"^[a-z]+ ", s) else f"<li><code>{html.escape(s)}</code></li>" for s in srcs)
            extra.append(f'<details class="sources"><summary>Sources ({len(srcs)})</summary><ul>{items}</ul></details>')
        if extra:
            dochead += '<div class="docmeta">' + "".join(extra) + "</div>"

        toc_list = ""
        if toc:
            toc_list = "<ul>" + "".join(
                f'<li class="l{l}"><a href="#{s}">{_inline(t)}</a></li>' for l, t, s in toc) + "</ul>"
        toc_html = f'<p class="toc-title">On this page</p>{toc_list}' if toc else ""

        rel = meta.get("related") or []
        if isinstance(rel, str):
            rel = [rel]
        rel_items = []
        for r in rel:
            rk = r[:-3] if r.endswith(".md") else r
            rk = posixpath.normpath(rk)
            if rk in docs and rk != k:
                rel_items.append(f'<li><a href="{url_of(rk)}">{icon("file")}<span>{html.escape(docs[rk]["title"])}'
                                 f'</span><small>{html.escape(dom[docs[rk]["domain"]][0])}</small></a></li>')
        related = (f'<section class="related" aria-labelledby="rel-h"><h2 id="rel-h">Related</h2>'
                   f'<ul>{"".join(rel_items)}</ul></section>') if rel_items else ""

        seq = flat[slug]
        pos = seq.index(k)
        pager = ""
        if pos > 0:
            p = seq[pos - 1]
            pager += f'<a class="prev" href="{url_of(p)}" rel="prev">{icon("left")}<span><small>Previous</small>{html.escape(docs[p]["title"])}</span></a>'
        if pos < len(seq) - 1:
            n = seq[pos + 1]
            pager += f'<a class="next" href="{url_of(n)}" rel="next"><span><small>Next</small>{html.escape(docs[n]["title"])}</span>{icon("right")}</a>'

        page = PAGE.format(title=html.escape(title), body=article, nav=nav_html(k), toc=toc_html,
                           toc_inline=toc_list or "<p>No sections.</p>", crumbs=crumbs_html, dochead=dochead,
                           related=related, pager=pager, body_class="page-doc", **chrome)
        dst = os.path.join(out_dir, url_of(k).lstrip("/"))
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        open(dst, "w", encoding="utf-8").write(page)
        if dst.endswith(os.sep + "README.html") and os.path.dirname(dst) != out_dir.rstrip(os.sep):
            # A folder's README also answers the folder URL (/troubleshooting/):
            # nginx serves index.html there and lists nothing otherwise. Same
            # directory, so every relative link in the page still resolves.
            open(os.path.join(os.path.dirname(dst), "index.html"), "w", encoding="utf-8").write(page)
        summary = meta.get("purpose") or _summary(d["md"])
        d["summary"] = summary if isinstance(summary, str) else ""
        index.append({
            "t": title, "u": url_of(k), "c": dtitle, "s": d["summary"],
            "h": [re.sub(r"[`*]", "", t) for _l, t, _s in toc],
            "a": [s for _l, _t, s in toc],
            "x": _plain(body)[:6000],
        })

    for h in used_svgs:
        src = os.path.join(RENDERED, h + ".svg")
        if os.path.isfile(src):
            shutil.copy2(src, os.path.join(diag_out, h + ".svg"))
    for rel in sorted(copies):
        dst = os.path.join(out_dir, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(os.path.join(DOCS, rel), dst)

    with open(os.path.join(out_dir, "search-index.json"), "w", encoding="utf-8") as fh:
        json.dump(index, fh, ensure_ascii=False, separators=(",", ":"))

    write_home(out_dir, docs, grouped, dom, chrome, nav_html, version)
    search_body = (
        '<section class="hero hero-slim"><div class="hero-inner"><nav class="crumbs" aria-label="Breadcrumb"><ol>'
        '<li><a href="/">Docs</a></li><li><span aria-current="page">Search</span></li></ol></nav>'
        '<h1>Search</h1><p class="lead">Every document, searched in your browser. Section matches link straight to the section.</p>'
        '<form class="bigsearch" action="/search.html" method="get" role="search"><label class="sr-only" for="dc-q">Search every document</label>'
        f'{icon("search", "ico search-ico")}<input type="search" name="q" id="dc-q" placeholder="Search every document…">'
        '<button type="submit">Search</button></form></div></section>'
        '<div class="wide-body"><p id="dc-count" class="dc-count" role="status" aria-live="polite"></p>'
        '<ol id="dc-results" class="dc-results"></ol>'
        '<noscript><p>Search needs JavaScript. Browse the domains on the <a href="/">home page</a>.</p></noscript></div>')
    open(os.path.join(out_dir, "search.html"), "w", encoding="utf-8").write(
        WIDE.format(title="Search", body=search_body, nav=nav_html(""), body_class="page-search", **chrome))
    return len(keys)


def _nav_item(k, docs, active, short=False):
    t = docs[k]["title"]
    if short:
        t = re.sub(r"^API reference:\s*", "", t)
    cur = ' class="active" aria-current="page"' if k == active else ""
    return f'<li><a href="{url_of(k)}"{cur}>{html.escape(t)}</a></li>'


def _coverage_rows():
    """(measure, covered, total, pct) rows from the generated coverage index."""
    p = os.path.join(DOCS, "reference", "coverage.md")
    if not os.path.isfile(p):
        return []
    rows = []
    for line in open(p, encoding="utf-8"):
        c = _cells(line) if line.startswith("|") else []
        if len(c) == 5 and c[4].endswith(("%", "(generated)")) and c[0] != "Domain":
            rows.append(c)
    return rows


def _first_int(path, pattern):
    try:
        m = re.search(pattern, open(os.path.join(DOCS, path), encoding="utf-8").read())
        return int(m.group(1)) if m else None
    except OSError:
        return None


def write_home(out_dir, docs, grouped, dom, chrome, nav_html, version):
    n_docs = len(docs)
    ops = _first_int("api/reference/README.md", r"\*\*(\d+) operations\*\*")
    tables = _first_int("DATABASE_SCHEMA.md", r"\*\*(\d+) tables\*\*")
    status_counts = {}
    for d in docs.values():
        s = d["meta"].get("status", "")
        s = s.split("|")[0].strip() if isinstance(s, str) and s.split("|")[0].strip() in STATUS_WORDS else "No front matter"
        status_counts[s] = status_counts.get(s, 0) + 1

    stats = [(str(n_docs), "documents", "/reference/coverage.html")]
    if ops:
        stats.append((str(ops), "API operations", "/api/reference/README.html"))
    if tables:
        stats.append((str(tables), "database tables", "/DATABASE_SCHEMA.html"))
    domains_n = sum(1 for s in grouped if grouped[s])
    stats.append((str(domains_n), "domains", "#domains"))
    stat_html = "".join(f'<a class="stat" href="{u}"><strong>{v}</strong><span>{html.escape(l)}</span></a>' for v, l, u in stats)

    def link_if(key, label, desc, ico):
        if key not in docs:
            return ""
        return (f'<a class="quick" href="{url_of(key)}">{icon(ico)}<span><strong>{html.escape(label)}</strong>'
                f'<small>{html.escape(desc)}</small></span></a>')

    quick = "".join(filter(None, [
        link_if("operations/installation", "Install VEYRS", "From zero to a running node", "operate")
        or link_if("DEPLOYMENT", "Install VEYRS", "From zero to a running node", "operate"),
        link_if("api/reference/README", "API reference", "Every endpoint, generated from the code", "api"),
        link_if("troubleshooting/README", "Troubleshooting", "Symptom → cause → fix", "troubleshooting"),
        link_if("architecture/overview", "Architecture", "Components and how they talk", "architecture")
        or link_if("ARCHITECTURE", "Architecture", "Components and how they talk", "architecture"),
        link_if("security/security-architecture", "Security", "Controls, trust boundaries, risks", "security")
        or link_if("SECURITY", "Security", "Controls, trust boundaries, risks", "security"),
        link_if("reference/configuration", "Configuration", "Every VEYRS_* setting and its default", "reference"),
        link_if("audit/README", "Documentation audit", "What is verified and what is not", "audit"),
    ]))

    cards = []
    for slug, title, blurb, _k, _d in DOMAINS + [("other", "Other", "Documents not yet filed in a domain", [], [])]:
        ks = grouped.get(slug) or []
        if not ks:
            continue
        top = ks[:5]
        items = "".join(f'<li><a href="{url_of(k)}">{html.escape(docs[k]["title"])}</a></li>' for k in top)
        more = f'<p class="more">+{len(ks) - len(top)} more in the menu</p>' if len(ks) > len(top) else ""
        cards.append(f'<section class="domain" aria-labelledby="d-{slug}"><div class="domain-head">{icon(slug)}'
                     f'<h2 id="d-{slug}">{html.escape(title)}</h2><span class="count">{len(ks)}</span></div>'
                     f'<p>{html.escape(blurb)}</p><ul>{items}</ul>{more}</section>')

    cov = _coverage_rows()
    cov_html = ""
    if cov:
        rows = "".join(
            f'<tr><td>{html.escape(c[0])}</td><td>{_inline(c[1])}</td><td class="num">{html.escape(c[2])} / {html.escape(c[3])}</td>'
            f'<td class="num"><span class="meter" aria-hidden="true"><i style="width:{_pct(c[4])}%"></i></span>{html.escape(c[4])}</td></tr>'
            for c in cov)
        cov_html = (f'<section class="panel coverage-wide" aria-labelledby="cov-h"><div class="panel-head"><h2 id="cov-h">Coverage</h2>'
                    f'<a href="/reference/coverage.html">How it is measured</a></div><div class="tablewrap" tabindex="0" role="region" aria-label="Coverage">'
                    f'<table class="covtable"><thead><tr><th>Domain</th><th>Measure</th><th class="num">Covered</th><th class="num">Coverage</th></tr></thead>'
                    f'<tbody>{rows}</tbody></table></div></section>')

    st_items = "".join(
        f'<li><span class="badge st-{s.lower()}">{s}</span><strong>{n}</strong></li>' if s in STATUS_WORDS
        else f'<li><span class="badge st-none">{html.escape(s)}</span><strong>{n}</strong></li>'
        for s, n in sorted(status_counts.items(), key=lambda x: (x[0] not in STATUS_WORDS, STATUS_WORDS.index(x[0]) if x[0] in STATUS_WORDS else 9)))
    recent = sorted((d for d in docs.values() if d["meta"].get("verified")),
                    key=lambda d: (d["meta"]["verified"], d["title"]), reverse=True)
    recent_html = "".join(
        f'<li><a href="{url_of(k)}">{html.escape(d["title"])}</a><time datetime="{html.escape(d["meta"]["verified"])}">'
        f'{html.escape(d["meta"]["verified"])}</time></li>'
        for k, d in sorted(((k, d) for k, d in docs.items() if d["meta"].get("verified")),
                           key=lambda kd: (kd[1]["meta"]["verified"], kd[1]["title"]), reverse=True)[:8])
    side = (f'<section class="panel" aria-labelledby="st-h"><div class="panel-head"><h2 id="st-h">Verification status</h2></div>'
            f'<ul class="statuslist">{st_items}</ul><p class="hint">Status words: Verified (code read and observed), Implemented '
            f'(in code, not observed), Partial, Planned, Obsolete, Unknown.</p></section>')
    if recent_html:
        side += (f'<section class="panel" aria-labelledby="rv-h"><div class="panel-head"><h2 id="rv-h">Recently verified</h2></div>'
                 f'<ul class="recent">{recent_html}</ul></section>')

    body = (
        '<section class="hero"><div class="hero-inner">'
        f'<p class="eyebrow">VEYRS {html.escape(version)} · documentation</p>'
        '<h1>VEYRS Docs Center</h1>'
        '<p class="lead">How VEYRS works, how to run it and how to change it, verified against the code. '
        'Start with a task below or search everything.</p>'
        '<form class="bigsearch" action="/search.html" method="get" role="search"><label class="sr-only" for="homeq">Search every document</label>'
        f'{icon("search", "ico search-ico")}<input id="homeq" type="search" name="q" placeholder="Search every document…">'
        '<button type="submit">Search</button></form>'
        f'<div class="stats">{stat_html}</div></div></section>'
        f'<div class="wide-body"><div class="quicks">{quick}</div>'
        f'<div class="home-grid"><div><h2 class="section-title" id="domains">Domains</h2><div class="domains">{"".join(cards)}</div></div>'
        f'<aside class="home-side">{side}</aside></div>{cov_html}</div>')
    open(os.path.join(out_dir, "index.html"), "w", encoding="utf-8").write(
        WIDE.format(title="Home", body=body, nav=nav_html("__home__"), body_class="page-home", **chrome))


def _pct(s):
    m = re.match(r"(\d+)", s)
    return m.group(1) if m else "100"


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="/var/www/veyrs")
    ap.add_argument("--site-url", default=SITE_URL, help="product site the navigation bar links to")
    ap.add_argument("--console-url", default=CONSOLE_URL, help="console the Console button opens")
    args = ap.parse_args()
    SITE_URL, CONSOLE_URL = args.site_url.rstrip("/"), args.console_url.rstrip("/")
    # Atomic publish (TD-43): build beside the live directory, then swap. The
    # live tree is never half-written and `static/` is never missing.
    import atomic_swap
    out = os.path.abspath(args.out.rstrip("/") or "/")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    tmp = tempfile.mkdtemp(prefix=os.path.basename(out) + ".new-", dir=os.path.dirname(out))
    try:
        n = build(tmp)
        how = atomic_swap.swap(tmp, out)
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    print(f"built {n} pages + home + search -> {out} ({how} swap; previous tree: {out}.prev)")
