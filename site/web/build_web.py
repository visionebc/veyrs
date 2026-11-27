#!/usr/bin/env python3
"""VEYRS product site generator (veyrs-web.example.com, veyrs.example.com).

Separate from site/build.py, which renders the Docs Center at veyrs-a. This one
builds the product site: what VEYRS is, what it does, how it is put together,
how to get it, and the two manuals operators read most.

Five locales, as static pages: English at the site root, then /es/, /de/, /fr/
and /it/. Every string a visitor reads comes from site/web/i18n/<lang>.json,
English being the source (tests/test_site_i18n.py checks the others are
complete). The two long manuals are rendered from Markdown and stay English in
every locale, under a short localized notice: the repository's documentation
policy is English only.

Zero third-party dependencies, same as the docs builder: the public-facing
host must stay trivially reproducible and auditable. Markdown rendering is
imported from the docs builder rather than copied, so the two sites cannot
drift into rendering the same file differently. No JavaScript: the menus are
<details> elements, so the site works under `script-src 'none'`.

Usage:  python3 site/web/build_web.py [--out /var/www/veyrs-web] [--public]
"""
import argparse
import hashlib
import html
import json
import math
import os
import posixpath
import re
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "site"))

from build import ICON as DOCS_ICON  # noqa: E402  (docs builder: one icon set)
from build import render as render_markdown  # noqa: E402

DOCS = os.path.join(ROOT, "docs")
BRAND = os.path.join(ROOT, "site", "static")
ASSETS_SRC = os.path.join(HERE, "assets")
I18N = os.path.join(HERE, "i18n")
FONTS = os.path.join(ROOT, "frontend", "console", "fonts")

# English is the source locale and lives at the site root; the others are
# directories. The names are endonyms: a reader looks for their own language.
LANGS = [("en", "English"), ("es", "Español"), ("de", "Deutsch"),
         ("fr", "Français"), ("it", "Italiano")]
SOURCE_LANG = "en"

# The executive navigation: five entries, the console as the call to action.
# (href, English label). site/build.py reads this list for the Docs Center's
# header, so it stays a list of (href, label) pairs.
NAV = [
    ("features.html", "Capabilities"),
    ("architecture.html", "Architecture"),
    ("security.html", "Security"),
    ("download.html", "Download"),
    ("docs.html", "Documentation"),
]
NAV_KEYS = {"features.html": "nav.capabilities", "architecture.html": "nav.architecture",
            "security.html": "nav.security", "download.html": "nav.download",
            "docs.html": "nav.documentation"}

# Defaults point at the A environment. They are MODULE GLOBALS, reassigned by
# main() from the command line, because the same source builds the site for
# more than one environment: the public site must not send a production
# visitor to the pre-production console.
CONSOLE_URL = "https://veyrs-app-1.example.com"
DOCS_URL = "https://veyrs-docs.example.com"
SITE_URL = "https://veyrs-web.example.com"
PUBLIC_SITE_URL = "https://veyrs.example.com"

# Links inside a rendered doc are relative to docs/ in the repository
# (`../INSTALL.md`, `../docker/compose.yaml`, `ARCHITECTURE.md`). On this site
# they would resolve against the site root and 404. Repository files point at
# the public mirror, where every one of those paths exists.
REPO_URL = "https://github.com/visionebc/veyrs/blob/main"
RELEASES_URL = "https://github.com/visionebc/veyrs/releases/latest"

# Set by --public. The public site is reached from the internet, where DOCS_URL
# does not resolve, so every documentation link goes to the Markdown on the
# public mirror instead. Without it (the LAN site) links go to the Docs Center.
PUBLIC_DOCS = False

# Set by --webfonts. "self" serves the console's own font files from
# /assets/fonts/ (CSP font-src 'self'); "google" links Google Fonts for a host
# whose CSP still only admits fonts.gstatic.com.
WEBFONTS = "self"

# The two manuals this site renders itself; every other doc is linked.
LOCAL_DOCS = {"USER_MANUAL": "manual.html", "DOCKER_COMPOSE_MANUAL": "install.html"}

# Docs Center pages that are not top-level docs, with the public-mirror file
# that covers the same ground (the mirror only carries docs/*.md and the ADRs).
DOC_TARGETS = {
    # api/guide.html exists in the Docs Center but its vhost proxies /api/ to the
    # application, so that URL answers 404: the top-level API page is reachable.
    "API_GUIDE": ("API.html", "docs/API.md"),
    "INSTALLATION": ("operations/installation.html", "INSTALL.md"),
    "ADR_INDEX": ("adr/README.html", "docs/ADRs/README.md"),
}


def doc_href(slug):
    """Where a link to the doc `slug` (docs/<slug>.md) points on this site."""
    if slug in LOCAL_DOCS:
        return LOCAL_DOCS[slug]
    if slug in DOC_TARGETS:
        lan, public = DOC_TARGETS[slug]
        return f"{REPO_URL}/{public}" if PUBLIC_DOCS else f"{DOCS_URL}/{lan}"
    if PUBLIC_DOCS:
        return f"{REPO_URL}/docs/{slug}.md"
    return f"{DOCS_URL}/{slug}.html"


def _doc_links(body):
    # Bodies name a doc as href="doc:SLUG"; it is resolved here, at build time.
    return re.sub(r'href="doc:(\w+)"', lambda m: f'href="{doc_href(m.group(1))}"', body)


def docs_home():
    # A directory is served under /tree/; /blob/ answers with a redirect.
    return f"{REPO_URL.replace('/blob/', '/tree/')}/docs" if PUBLIC_DOCS else DOCS_URL


def adr_index():
    # The docs site has no /adr/ index page (403); the ADR README is the index.
    return doc_href("ADR_INDEX")


# ---------------------------------------------------------------------------
# Strings
# ---------------------------------------------------------------------------
def load_strings():
    out = {}
    for code, _name in LANGS:
        with open(os.path.join(I18N, f"{code}.json"), encoding="utf-8") as fh:
            out[code] = json.load(fh)
    return out


STRINGS = load_strings()
LANG = SOURCE_LANG          # the locale being built; set by build_locale()


def t(key, **kw):
    """The current locale's string for `key`, placeholders filled in.

    Values are trusted HTML from the repository (they carry <b>, <code>...).
    A key missing from a translation falls back to English; the i18n test
    fails on it before it can ship."""
    s = STRINGS[LANG].get(key)
    if s is None:
        s = STRINGS[SOURCE_LANG][key]
    for k, v in kw.items():
        s = s.replace("{" + k + "}", str(v))
    return s


def prefix():
    """Relative path from the current locale's directory to the site root."""
    return "" if LANG == SOURCE_LANG else "../"


def asset(name):
    return f"{prefix()}assets/{name}"


def locale_href(code, slug):
    """Link from the current page to the same page in locale `code`."""
    base = "" if code == SOURCE_LANG else f"{code}/"
    return f"{prefix()}{base}{slug}"


def absolute(code, slug):
    path = "" if code == SOURCE_LANG else f"{code}/"
    return f"{SITE_URL}/{path}{'' if slug == 'index.html' else slug}"


# ---------------------------------------------------------------------------
# Icons: the Docs Center's set plus the ones only this site needs. Same
# stroke style (24 px grid, 1.75 stroke, round joins).
# ---------------------------------------------------------------------------
ICONS = dict(DOCS_ICON)
ICONS.update({
    "eye": '<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
    "globe": '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>',
    "gauge": '<path d="M3.5 18a9 9 0 1 1 17 0"/><path d="m12 14 4.5-4.5"/><circle cx="12" cy="14" r="1.2"/>',
    "target": '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="1"/>',
    "shield-check": '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/>',
    "layers": '<path d="m12 3 9 5-9 5-9-5 9-5z"/><path d="m3 13 9 5 9-5"/>',
    "scan": '<path d="M4 8V5a1 1 0 0 1 1-1h3M16 4h3a1 1 0 0 1 1 1v3M20 16v3a1 1 0 0 1-1 1h-3M8 20H5a1 1 0 0 1-1-1v-3"/><path d="M7 12h10"/>',
    "pulse": '<path d="M3 12h4l3-8 4 16 3-8h4"/>',
    "clock": '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    "chart": '<path d="M3 21h18M7 17v-6M12 17V6M17 17v-4"/>',
    "lock": '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
    "key": '<circle cx="8" cy="15" r="4"/><path d="m10.8 12.2 8.2-8.2M17 6l2 2M15 8l2 2"/>',
    "user-check": '<circle cx="9" cy="8" r="4"/><path d="M2 21a7 7 0 0 1 14 0"/><path d="m16 11 2 2 4-4"/>',
    "file-check": '<path d="M14 3H6a1 1 0 0 0-1 1v16a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V8z"/><path d="M14 3v5h5"/><path d="m9 14 2 2 4-4"/>',
    "server": '<rect x="3" y="4" width="18" height="7" rx="1.5"/><rect x="3" y="13" width="18" height="7" rx="1.5"/><path d="M7 7.5h.01M7 16.5h.01"/>',
    "box": '<path d="M21 8 12 3 3 8v8l9 5 9-5z"/><path d="m3 8 9 5 9-5M12 13v8"/>',
    "nodes": '<rect x="9" y="2" width="6" height="5" rx="1"/><rect x="2" y="17" width="6" height="5" rx="1"/><rect x="16" y="17" width="6" height="5" rx="1"/><path d="M12 7v5M5 17v-3h14v3"/>',
    "book": '<path d="M2 4h6a4 4 0 0 1 4 4v13a3 3 0 0 0-3-3H2z"/><path d="M22 4h-6a4 4 0 0 0-4 4v13a3 3 0 0 1 3-3h7z"/>',
    "download": '<path d="M12 3v12M7 10l5 5 5-5M5 21h14"/>',
    "terminal": '<path d="m4 17 6-5-6-5M12 19h8"/>',
    "arrow": '<path d="M5 12h14M13 6l6 6-6 6"/>',
    "chevron": '<path d="m6 9 6 6 6-6"/>',
    "check": '<path d="M20 6 9 17l-5-5"/>',
    "library": '<path d="M4 4v16M9 4v16M14 4l5 16"/>',
})


def icon(name, cls="ico"):
    return (f'<svg class="{cls}" viewBox="0 0 24 24" aria-hidden="true" focusable="false">'
            f'{ICONS[name]}</svg>')


# ---------------------------------------------------------------------------
# Chrome
# ---------------------------------------------------------------------------
BRAND_NAME = "VEYRS"


def page_title(title, subtitle):
    """`<Page> — VEYRS`, and `VEYRS — <tagline>` for the page titled with the
    brand itself. Appending the brand unconditionally titled the home page
    "VEYRS — VEYRS" until 0.35.4."""
    if title.strip() == BRAND_NAME:
        return f"{BRAND_NAME} — {subtitle}"
    return f"{title} — {BRAND_NAME}"


def _nav_links(slug, cls):
    out = []
    for href, _label in NAV:
        cur = ' aria-current="page"' if href == slug else ""
        out.append(f'<a class="{cls}" href="{href}"{cur}>{t(NAV_KEYS[href])}</a>')
    return "".join(out)


def _cur(code):
    return ' aria-current="true"' if code == LANG else ""


def _menu_langs(slug):
    return "".join(f'<li><a href="{locale_href(code, slug)}" hreflang="{code}" lang="{code}"{_cur(code)}>'
                   f'{name}</a></li>' for code, name in LANGS)


def _lang_menu(slug, where):
    """The language switcher: a <details> disclosure, usable with keyboard
    and without script. Each entry names its language in that language and
    keeps the reader on the same page."""
    items = []
    for code, name in LANGS:
        cur = _cur(code)
        mark = icon("check", "ico ico-sm") if code == LANG else '<span class="ico-sm"></span>'
        items.append(f'<li><a href="{locale_href(code, slug)}" hreflang="{code}" lang="{code}"{cur}>'
                     f'{mark}<span>{name}</span><span class="code">{code.upper()}</span></a></li>')
    current = dict(LANGS)[LANG]
    return (f'<details class="lang lang-{where}">'
            f'<summary aria-label="{t("lang.label")}: {current}">{icon("globe")}'
            f'<span class="lang-code">{LANG.upper()}</span>{icon("chevron", "ico ico-sm chev")}</summary>'
            f'<ul class="lang-list" role="list">{"".join(items)}</ul></details>')


def _head_links(slug):
    alts = "".join(f'<link rel="alternate" hreflang="{code}" href="{absolute(code, slug)}">\n'
                   for code, _ in LANGS)
    alts += f'<link rel="alternate" hreflang="x-default" href="{absolute(SOURCE_LANG, slug)}">\n'
    if WEBFONTS == "google":
        fonts = ('<link rel="preconnect" href="https://fonts.googleapis.com">\n'
                 '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>\n'
                 '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700'
                 '&amp;family=JetBrains+Mono:wght@400;500&amp;display=swap">\n')
    else:
        fonts = (f'<link rel="preload" href="{asset("fonts/inter-regular.woff2")}" as="font" type="font/woff2" crossorigin>\n'
                 f'<link rel="preload" href="{asset("fonts/inter-semibold.woff2")}" as="font" type="font/woff2" crossorigin>\n'
                 f'<link rel="stylesheet" href="{asset("fonts.css")}?v={ASSET_HASH}">\n')
    return alts, fonts


def _footer(slug):
    year = _copyright_year()
    docs_center = (f'<a href="{docs_home()}">{t("footer.docs_github")} {icon("ext", "ico ico-xs")}</a>'
                   if PUBLIC_DOCS else
                   f'<a href="{docs_home()}">{t("footer.docs_center")} {icon("ext", "ico ico-xs")}</a>')
    langs = " ".join(
        f'<a href="{locale_href(code, slug)}" hreflang="{code}" lang="{code}"{_cur(code)}>{name}</a>'
        for code, name in LANGS)
    return f"""
<footer class="sitefoot">
  <div class="wrap foot-grid">
    <div class="foot-brand">
      <img src="{asset("veyrs-logo-on-dark-gradient.png")}" alt="VEYRS" width="168" height="121" loading="lazy">
      <p>{t("footer.blurb")}</p>
      <p class="foot-acronym">{t("brand.acronym")}</p>
    </div>
    <nav class="foot-col" aria-label="{t("footer.product")}">
      <h2>{t("footer.product")}</h2>
      <a href="index.html">{t("nav.overview")}</a>
      <a href="features.html">{t("nav.capabilities")}</a>
      <a href="architecture.html">{t("nav.architecture")}</a>
      <a href="security.html">{t("nav.security")}</a>
      <a href="download.html">{t("nav.download")}</a>
    </nav>
    <nav class="foot-col" aria-label="{t("footer.docs")}">
      <h2>{t("footer.docs")}</h2>
      <a href="docs.html">{t("footer.docs_hub")}</a>
      <a href="manual.html">{t("footer.manual")}</a>
      <a href="install.html">{t("footer.install")}</a>
      <a href="{doc_href("API_GUIDE")}">{t("footer.api")}</a>
      {docs_center}
    </nav>
    <nav class="foot-col" aria-label="{t("footer.platform")}">
      <h2>{t("footer.platform")}</h2>
      <a href="{CONSOLE_URL}">{t("common.open_console")} {icon("ext", "ico ico-xs")}</a>
      <a href="{RELEASES_URL}">{t("footer.releases")} {icon("ext", "ico ico-xs")}</a>
      <a href="{doc_href("SECURITY")}">{t("footer.security_policy")}</a>
      <a href="{doc_href("HIGH_AVAILABILITY")}">{t("footer.availability")}</a>
    </nav>
  </div>
  <div class="wrap"><div class="foot-bottom">
    <p>© {year} Vision EBC · {t("footer.license")}</p>
    <p class="foot-langs"><span class="sr-only">{t("lang.label")}: </span>{langs}</p>
  </div></div>
</footer>"""


def page(slug, title, subtitle, body, *, kind="page", eyebrow="", head_extra="", description=None):
    """One HTML document. `kind`: "home" (hero supplied by the body), "page"
    (navy page head) or "doc" (page head + rendered manual)."""
    body = _doc_links(body)
    alts, fonts = _head_links(slug)
    if kind == "home":
        head_html = ""
    else:
        crumbs = (f'<p class="eyebrow on-dark"><a href="index.html">VEYRS</a>'
                  f'<span aria-hidden="true">/</span>{eyebrow}</p>') if eyebrow else ""
        head_html = f"""
<header class="pagehead">
  <div class="wrap">
    {crumbs}
    <h1>{html.escape(title)}</h1>
    <p class="lead">{subtitle}</p>
    {head_extra}
  </div>
</header>"""
    plain_sub = re.sub(r"<[^>]+>", "", subtitle)
    title_text = page_title(title, plain_sub)
    plain_sub = re.sub(r"<[^>]+>", "", description or subtitle)
    return f"""<!DOCTYPE html>
<html lang="{LANG}">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{html.escape(title_text)}</title>
<meta name="description" content="{html.escape(plain_sub)}">
<meta name="theme-color" content="#001030">
<link rel="canonical" href="{absolute(LANG, slug)}">
{alts}<meta property="og:type" content="website">
<meta property="og:site_name" content="VEYRS">
<meta property="og:title" content="{html.escape(title_text)}">
<meta property="og:description" content="{html.escape(plain_sub)}">
<meta property="og:url" content="{absolute(LANG, slug)}">
<meta property="og:image" content="{SITE_URL}/assets/veyrs-logo-on-dark-gradient.png">
<meta property="og:locale" content="{t("lang.og_locale")}">
<link rel="icon" href="{asset("veyrs-favicon.ico")}" sizes="any">
<link rel="icon" type="image/png" href="{asset("veyrs-favicon.png")}">
{fonts}<link rel="stylesheet" href="{asset("web.css")}?v={ASSET_HASH}">
</head>
<body class="kind-{kind}">
<a class="skip" href="#main">{t("common.skip")}</a>
<header class="topnav">
  <div class="wrap nav-inner">
    <a class="brand" href="index.html" aria-label="VEYRS — {t("nav.overview")}">
      <img src="{asset("veyrs-mark-gradient.png")}" alt="" width="30" height="19"><span>VEYRS</span>
    </a>
    <nav class="nav-links" aria-label="{t("nav.main")}">{_nav_links(slug, "nav-link")}</nav>
    <div class="nav-tools">
      {_lang_menu(slug, "desk")}
      <a class="btn btn-primary btn-sm nav-cta" href="{CONSOLE_URL}">{t("common.open_console")}</a>
      <details class="menu">
        <summary aria-label="{t("common.menu")}">{icon("menu")}</summary>
        <div class="menu-panel">
          <nav aria-label="{t("nav.main")}">{_nav_links(slug, "menu-link")}</nav>
          <a class="btn btn-primary" href="{CONSOLE_URL}">{t("common.open_console")}</a>
          <p class="menu-langs-label">{t("lang.label")}</p>
          <ul class="menu-langs" role="list">{_menu_langs(slug)}</ul>
        </div>
      </details>
    </div>
  </div>
</header>
{head_html}
<main id="main">
{body}
</main>
{_footer(slug)}
</body>
</html>
"""


def _copyright_year():
    # From the LICENSE, not the clock: two nodes building the same commit on
    # either side of New Year must still produce the same site.
    with open(os.path.join(ROOT, "LICENSE"), encoding="utf-8") as fh:
        m = re.search(r"Copyright \(c\) (\d{4})", fh.read())
    return m.group(1) if m else ""


# ---------------------------------------------------------------------------
# Building blocks
# ---------------------------------------------------------------------------
STANDARDS = ["CVE", "CVSS v2 · v3.0 · v3.1 · v4.0", "EPSS", "CISA KEV", "CWE", "CPE"]
FRAMEWORKS = ["NIST CSF 2.0", "CIS Controls", "ISO/IEC 27001", "ISO/IEC 27002"]


def section_head(eyebrow_key, title_key, lead_key=None, *, center=False, dark=False):
    cls = "section-head" + (" center" if center else "")
    lead = f'<p class="lead">{t(lead_key)}</p>' if lead_key else ""
    return (f'<div class="{cls}"><p class="eyebrow{" on-dark" if dark else ""}">{t(eyebrow_key)}</p>'
            f'<h2>{t(title_key)}</h2>{lead}</div>')


def feature_card(ico, title, text, href=None, link_text=None):
    link = (f'<a class="card-link" href="{href}">{link_text}{icon("arrow", "ico ico-sm")}</a>'
            if href else "")
    return (f'<div class="card"><span class="tile">{icon(ico)}</span>'
            f'<h3>{title}</h3><p>{text}</p>{link}</div>')


def _table(head, rows):
    # Wrapped so a wide table scrolls inside itself on a phone instead of
    # widening the page (the failure install.html once had).
    th = "".join(f'<th scope="col">{h}</th>' for h in head)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows)
    return f'<div class="tablewrap"><table><thead><tr>{th}</tr></thead><tbody>{body}</tbody></table></div>'


def note(text, tone=""):
    return f'<div class="note{(" " + tone) if tone else ""}"><p>{text}</p></div>'


def _meter(value):
    return (f'<svg class="meter" viewBox="0 0 100 4" preserveAspectRatio="none" aria-hidden="true">'
            f'<rect class="track" width="100" height="4" rx="2"/>'
            f'<rect class="fill" width="{value}" height="4" rx="2"/></svg>')


def product_mock():
    """The hero's illustrative decision queue. Every value is made up and the
    panel says so; it shows the ranking idea, not a customer's data."""
    rows = [
        ("payments-gateway", "mock.exp.internet", True, "6.5", 94, "crit", "mock.due.7"),
        ("customer-portal", "mock.exp.internet", False, "8.1", 81, "high", "mock.due.14"),
        ("hr-intranet", "mock.exp.internal", False, "7.5", 48, "med", "mock.due.30"),
        ("lab-host-07", "mock.exp.isolated", False, "9.8", 22, "low", "mock.due.window"),
    ]
    sev = {"crit": "mock.sev.critical", "high": "mock.sev.high", "med": "mock.sev.medium", "low": "mock.sev.low"}
    items = []
    for asset_name, exp, kev, cvss, risk, level, due in rows:
        kev_html = '<span class="kev">CISA KEV</span>' if kev else ""
        items.append(
            f'<li class="mrow"><div class="m-asset"><b>{asset_name}</b>'
            f'<span class="m-meta">{t(exp)}{kev_html}</span><span class="m-due">{t(due)}</span></div>'
            f'<div class="m-cvss"><span class="m-label">CVSS</span>{cvss}</div>'
            f'<div class="m-risk"><span class="sev sev-{level}">{t(sev[level])}</span>'
            f'<span class="m-score">{risk}</span>{_meter(risk)}</div></li>')
    return f"""
<figure class="mock" aria-labelledby="mock-cap">
  <div class="mock-bar"><span class="dots" aria-hidden="true"><i></i><i></i><i></i></span>
    <span class="mock-title">{t("mock.title")}</span><span class="mock-tag">{t("common.illustrative")}</span></div>
  <div class="mock-cols" aria-hidden="true"><span>{t("mock.col.asset")}</span><span>CVSS</span><span>{t("mock.col.risk")}</span></div>
  <ol class="mock-rows">{"".join(items)}</ol>
  <figcaption id="mock-cap">{t("mock.caption")}</figcaption>
</figure>"""


def chain():
    steps = ["chain.visibility", "chain.exposure", "chain.risk", "chain.action", "chain.security"]
    sep = f'<li class="sep" aria-hidden="true">{icon("arrow", "ico ico-xs")}</li>'
    return (f'<ol class="chain" aria-label="{t("chain.label")}">'
            + sep.join(f"<li>{t(k)}</li>" for k in steps) + "</ol>")


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------
def build_index():
    how = [("eye", "chain.visibility", "home.how.v"), ("globe", "chain.exposure", "home.how.e"),
           ("gauge", "chain.risk", "home.how.r"), ("target", "chain.action", "home.how.a"),
           ("shield-check", "chain.security", "home.how.s")]
    steps = "".join(
        f'<li class="step"><span class="step-n">0{i}</span><span class="tile">{icon(ico)}</span>'
        f'<h3>{t(title)}</h3><p>{t(text)}</p></li>'
        for i, (ico, title, text) in enumerate(how, 1))
    caps = [("layers", "ingest", "#ingestion"), ("scan", "exec", "#execution"),
            ("pulse", "intel", "#intelligence"), ("gauge", "risk", "#prioritisation"),
            ("clock", "sla", "#ticketing"), ("chart", "report", "#reporting")]
    cap_cards = "".join(
        feature_card(ico, t(f"home.cap.{k}.t"), t(f"home.cap.{k}.d", n=_parser_count()),
                     f"features.html{anchor}", t("common.learn_more"))
        for ico, k, anchor in caps)
    trust = [("data", "rls"), ("audit", "audit"), ("user-check", "auth"),
             ("key", "secrets"), ("file-check", "signed"), ("server", "selfhost")]
    trust_cards = "".join(
        f'<div class="trust-item"><span class="tile">{icon(ico)}</span><div>'
        f'<h3>{t(f"home.trust.{k}.t")}</h3><p>{t(f"home.trust.{k}.d")}</p></div></div>'
        for ico, k in trust)
    prin = "".join(
        f'<div class="pillar"><span class="pillar-n">0{i}</span><h3>{t(f"home.prin.{i}.t")}</h3>'
        f'<p>{t(f"home.prin.{i}.d")}</p></div>' for i in (1, 2, 3))
    standards = "".join(f"<li>{s}</li>" for s in STANDARDS)
    frameworks = "".join(f"<li>{s}</li>" for s in FRAMEWORKS)
    return f"""
<section class="hero">
  <div class="wrap hero-grid">
    <div class="hero-copy">
      <p class="eyebrow on-dark">{t("brand.tagline")}</p>
      <h1>{t("home.hero.h1a")}<br><span class="accent">{t("home.hero.h1b")}</span></h1>
      <p class="hero-lead">{t("home.hero.lead")}</p>
      <div class="cta-row">
        <a class="btn btn-primary btn-lg" href="{CONSOLE_URL}">{t("common.open_console")}{icon("arrow", "ico ico-sm")}</a>
        <a class="btn btn-ghost btn-lg" href="features.html">{t("home.hero.cta2")}</a>
      </div>
      <ul class="hero-facts" role="list">
        <li>{icon("check", "ico ico-sm")}{t("home.hero.fact1")}</li>
        <li>{icon("check", "ico ico-sm")}{t("home.hero.fact2")}</li>
        <li>{icon("check", "ico ico-sm")}{t("home.hero.fact3")}</li>
      </ul>
    </div>
    <div class="hero-visual">{product_mock()}</div>
  </div>
  <div class="wrap">{chain()}</div>
</section>

<section class="standards" aria-labelledby="std-title">
  <div class="wrap std-grid">
    <h2 id="std-title" class="std-title">{t("home.std.title")}</h2>
    <div class="std-lists">
      <ul class="chips" role="list" aria-label="{t("home.std.standards")}">{standards}</ul>
      <p class="std-sub">{t("home.std.frameworks")}</p>
      <ul class="chips chips-muted" role="list" aria-label="{t("home.std.frameworks")}">{frameworks}</ul>
    </div>
  </div>
</section>

<section class="section">
  <div class="wrap split">
    <div>
      <p class="eyebrow">{t("home.problem.eyebrow")}</p>
      <h2>{t("home.problem.title")}</h2>
      <p class="lead">{t("home.problem.p1")}</p>
      <p>{t("home.problem.p2")}</p>
    </div>
    <div class="compare" role="group" aria-label="{t("home.cmp.title")}">
      <p class="compare-title">{t("home.cmp.title")}</p>
      <div class="cmp cmp-a">
        <div class="cmp-score"><span>CVSS</span><b>9.8</b></div>
        <div class="cmp-body"><b>{t("home.cmp.a.asset")}</b><span>{t("home.cmp.a.signal")}</span></div>
        <span class="sev sev-low">{t("home.cmp.a.verdict")}</span>
      </div>
      <div class="cmp cmp-b">
        <div class="cmp-score"><span>CVSS</span><b>6.5</b></div>
        <div class="cmp-body"><b>{t("home.cmp.b.asset")}</b><span>{t("home.cmp.b.signal")}</span></div>
        <span class="sev sev-crit">{t("home.cmp.b.verdict")}</span>
      </div>
      <p class="compare-note">{t("home.cmp.note")}</p>
    </div>
  </div>
</section>

<section class="section alt">
  <div class="wrap">
    {section_head("home.how.eyebrow", "home.how.title", "home.how.lead")}
    <ol class="steps" role="list">{steps}</ol>
  </div>
</section>

<section class="section">
  <div class="wrap">
    {section_head("home.cap.eyebrow", "home.cap.title", "home.cap.lead")}
    <div class="grid g3">{cap_cards}</div>
  </div>
</section>

<section class="section band-navy">
  <div class="wrap">
    {section_head("home.prin.eyebrow", "home.prin.title", "home.prin.lead", dark=True)}
    <div class="pillars">{prin}</div>
  </div>
</section>

<section class="section">
  <div class="wrap">
    {section_head("home.trust.eyebrow", "home.trust.title", "home.trust.lead")}
    <div class="trust-grid">{trust_cards}</div>
    <p class="more"><a class="card-link" href="security.html">{t("home.trust.more")}{icon("arrow", "ico ico-sm")}</a></p>
  </div>
</section>

<section class="section alt">
  <div class="wrap">
    {section_head("home.deploy.eyebrow", "home.deploy.title", "home.deploy.lead")}
    <div class="grid g3">
      {feature_card("terminal", t("home.deploy.native.t"), t("home.deploy.native.d"), "download.html", t("home.deploy.native.link"))}
      {feature_card("box", t("home.deploy.docker.t"), t("home.deploy.docker.d"), "install.html", t("home.deploy.docker.link"))}
      {feature_card("nodes", t("home.deploy.ha.t"), t("home.deploy.ha.d"), "architecture.html", t("home.deploy.ha.link"))}
    </div>
  </div>
</section>
{final_cta()}"""


def final_cta():
    return f"""
<section class="section final">
  <div class="wrap">
    <div class="final-panel">
      <div>
        <h2>{t("final.title")}</h2>
        <p>{t("final.lead")}</p>
      </div>
      <div class="cta-row">
        <a class="btn btn-primary btn-lg" href="{CONSOLE_URL}">{t("common.open_console")}{icon("arrow", "ico ico-sm")}</a>
        <a class="btn btn-ghost btn-lg" href="docs.html">{t("common.read_docs")}</a>
      </div>
    </div>
  </div>
</section>"""


def subnav(items):
    links = "".join(f'<a href="#{anchor}">{t(key)}</a>' for anchor, key in items)
    return f'<nav class="subnav" aria-label="{t("common.on_this_page")}">{links}</nav>'


def block(anchor, ico, title, content, *, alt=False):
    """One long-form section of an inner page."""
    return (f'<section class="section{" alt" if alt else ""}" id="{anchor}" aria-labelledby="{anchor}-h">'
            f'<div class="wrap prose-grid"><div class="prose-side"><span class="tile">{icon(ico)}</span></div>'
            f'<div class="prose"><h2 id="{anchor}-h">{title}</h2>{content}</div></div></section>')


FEATURE_SECTIONS = [("ingestion", "feat.nav.ingest"), ("execution", "feat.nav.exec"),
                    ("intelligence", "feat.nav.intel"), ("prioritisation", "feat.nav.risk"),
                    ("ticketing", "feat.nav.sla"), ("reporting", "feat.nav.report")]


def build_features():
    ingest = _table([t("feat.ingest.th.cat"), t("feat.ingest.th.tools"), t("feat.ingest.th.note")], [
        [t("feat.ingest.net"), "Nessus, Qualys, Greenbone / OpenVAS, Nmap", t("feat.ingest.net.n")],
        [t("feat.ingest.web"), "OWASP ZAP, Nuclei", t("feat.ingest.web.n")],
        [t("feat.ingest.img"), "Trivy, Grype", t("feat.ingest.img.n")],
        [t("feat.ingest.code"), "Semgrep, Bandit, CodeQL / SARIF, Dependabot, npm audit, pip-audit", t("feat.ingest.code.n")],
        [t("feat.ingest.iac"), "Gitleaks, Checkov", t("feat.ingest.iac.n")],
        [t("feat.ingest.cloud"), "Prowler", t("feat.ingest.cloud.n")],
        [t("feat.ingest.gen"), "CSV, JSON", t("feat.ingest.gen.n")],
    ])
    exec_rows = [[t(f"feat.exec.r{i}.c"), t(f"feat.exec.r{i}.b")] for i in range(1, 7)]
    intel = _table([t("feat.intel.th.feed"), t("feat.intel.th.src"), t("feat.intel.th.effect")], [
        ["NVD", "nvd.nist.gov", t("feat.intel.nvd")],
        ["EPSS", "FIRST", t("feat.intel.epss")],
        ["KEV", "CISA", t("feat.intel.kev")],
        ["CWE", "MITRE", t("feat.intel.cwe")],
    ])
    sla_cards = "".join(
        f'<div class="card card-flat"><h3>{t(f"feat.sla.{k}.t")}</h3><p>{t(f"feat.sla.{k}.d")}</p></div>'
        for k in ("clock", "itsm"))
    report_cards = "".join(
        f'<div class="card card-flat"><h3>{t(f"feat.report.{k}.t")}</h3><p>{t(f"feat.report.{k}.d")}</p></div>'
        for k in ("reports", "compliance"))
    return (
        block("ingestion", "layers", t("feat.ingest.title"),
              f'<p class="lead">{t("feat.ingest.lead", n=_parser_count())}</p>{ingest}'
              + note(t("feat.dedupe.note"), "warn"))
        + block("execution", "scan", t("feat.exec.title"),
                f'<p>{t("feat.exec.p")}</p>' + _table([t("feat.exec.th.c"), t("feat.exec.th.b")], exec_rows), alt=True)
        + block("intelligence", "pulse", t("feat.intel.title"), intel + f'<p>{t("feat.intel.p")}</p>')
        + block("prioritisation", "gauge", t("feat.risk.title"),
                f'<p class="lead">{t("feat.risk.p1")}</p><p>{t("feat.risk.p2")}</p>', alt=True)
        + block("ticketing", "clock", t("feat.sla.title"), f'<div class="grid g2">{sla_cards}</div>')
        + block("reporting", "chart", t("feat.report.title"), f'<div class="grid g2">{report_cards}</div>', alt=True)
        + final_cta())


def arch_diagram():
    """The reference topology as HTML boxes: the labels are translated text,
    which an image could not be."""
    return f"""
<figure class="topo" aria-labelledby="topo-cap">
  <div class="topo-row"><div class="node node-edge">{icon("globe", "ico ico-sm")}<span>{t("arch.d.proxy")}</span><small>{t("arch.d.proxy.s")}</small></div></div>
  <div class="topo-link" aria-hidden="true"></div>
  <div class="topo-row two">
    <div class="node">{icon("server", "ico ico-sm")}<span>{t("arch.d.app1")}</span><small>{t("arch.d.app1.s")}</small></div>
    <div class="node">{icon("server", "ico ico-sm")}<span>{t("arch.d.app2")}</span><small>{t("arch.d.app2.s")}</small></div>
  </div>
  <div class="topo-link" aria-hidden="true"></div>
  <div class="topo-row"><div class="node node-state">{icon("data", "ico ico-sm")}<span>{t("arch.d.db")}</span><small>PostgreSQL · Redis</small></div></div>
  <div class="topo-link dashed" aria-hidden="true"><span>{t("arch.d.repl")}</span></div>
  <div class="topo-row"><div class="node node-standby">{icon("data", "ico ico-sm")}<span>{t("arch.d.standby")}</span><small>{t("arch.d.standby.s")}</small></div></div>
  <figcaption id="topo-cap">{t("arch.d.caption")}</figcaption>
</figure>"""


def build_architecture():
    nodes = _table([t("arch.th.node"), t("arch.th.role")],
                   [[t(f"arch.n{i}"), t(f"arch.n{i}.r")] for i in range(1, 5)])
    fail = _table([t("arch.th.failure"), t("arch.th.impact"), t("arch.th.recovery")], [
        [t("arch.f1"), f'<span class="sev sev-ok">{t("arch.none")}</span>', t("arch.f1.r")],
        [t("arch.f2"), f'<span class="sev sev-ok">{t("arch.none")}</span>', t("arch.f2.r")],
        [t("arch.f3"), t("arch.f3.i"), t("arch.f3.r")],
        [t("arch.f4"), t("arch.f4.i"), t("arch.f4.r")],
        [t("arch.f5"), t("arch.f5.i"), t("arch.f5.r")],
    ])
    prot = _table([t("arch.th.layer"), t("arch.th.covers"), t("arch.th.not")],
                  [[t(f"arch.p{i}"), t(f"arch.p{i}.c"), t(f"arch.p{i}.n")] for i in range(1, 4)])
    stack = _table([t("arch.th.layer"), t("arch.th.choice")], [
        ["API", t("arch.s.api")],
        [t("arch.s.data"), t("arch.s.data.v")],
        [t("arch.s.cache"), t("arch.s.cache.v")],
        ["ORM", "SQLAlchemy 2"],
        [t("arch.s.auth"), t("arch.s.auth.v")],
        [t("arch.s.secrets"), t("arch.s.secrets.v")],
        [t("arch.s.schema"), t("arch.s.schema.v")],
        [t("arch.s.deps"), t("arch.s.deps.v", packages=_pinned_packages())],
    ])
    return (
        block("topology", "nodes", t("arch.topology.title"),
              f'<p class="lead">{t("arch.topology.lead")}</p>{arch_diagram()}{nodes}')
        + block("stateless", "server", t("arch.stateless.title"),
                f'<p>{t("arch.stateless.p1")}</p><p>{t("arch.stateless.p2")}</p>'
                + note(t("arch.dns.note")), alt=True)
        + block("singletons", "target", t("arch.single.title"), f'<p>{t("arch.single.p")}</p>')
        + block("failures", "gauge", t("arch.fail.title"), fail, alt=True)
        + block("protection", "data", t("arch.prot.title"), prot + note(t("arch.prot.note"), "warn"))
        + block("promotion", "shield-check", t("arch.promo.title"),
                f'<p>{t("arch.promo.p")} <a href="doc:HIGH_AVAILABILITY">HIGH_AVAILABILITY</a>.</p>', alt=True)
        + block("stack", "layers", t("arch.stack.title"), stack)
        + final_cta())


def _pinned_packages():
    # Counted at build time: the page said 52 while requirements.txt pinned 53.
    with open(os.path.join(ROOT, "requirements.txt")) as fh:
        return sum(1 for line in fh if line.strip() and not line.lstrip().startswith(("#", "-")))


def _parser_count():
    """Distinct report formats VEYRS parses, read from the two parser
    registries so the page cannot claim a number the code does not have.
    Aliases (openvas -> greenbone, codeql -> sarif) count once."""
    src = ""
    for name in ("parsers.py", "parsers_modern.py"):
        with open(os.path.join(ROOT, "backend", "veyrs", "services", "importers", name), encoding="utf-8") as fh:
            src += fh.read()
    funcs = set()
    for reg in ("PARSERS", "MODERN_PARSERS"):
        m = re.search(rf"^{reg}\s*(?::[^=]+)?=\s*\{{(.*?)^\}}", src, flags=re.S | re.M)
        if not m:
            raise SystemExit(f"build_web: cannot find the {reg} registry")
        funcs |= set(re.findall(r":\s*(parse_\w+)", m.group(1)))
    return len(funcs)


def build_security():
    auth = _table([t("sec.th.control"), t("sec.th.behaviour")],
                  [[t(f"sec.auth.r{i}.c"), t(f"sec.auth.r{i}.b")] for i in range(1, 8)])
    untrusted = "".join(f"<li>{t(f'sec.input.{i}')}</li>" for i in (1, 2, 3))
    agent = "".join(f"<li>{t(f'sec.agent.{i}')}</li>" for i in (1, 2, 3, 4))
    return (
        block("isolation", "data", t("sec.iso.title"),
              f'<p class="lead">{t("sec.iso.lead")}</p>' + note(t("sec.iso.note")))
        + block("authentication", "user-check", t("sec.auth.title"),
                auth + f'<h3>{t("sec.mfa.title")}</h3><p>{t("sec.mfa.p")}</p>', alt=True)
        + block("secrets", "key", t("sec.secrets.title"),
                f'<p>{t("sec.secrets.p1")}</p><p>{t("sec.secrets.p2")}</p>')
        + block("input", "file-check", t("sec.input.title"),
                f'<p>{t("sec.input.p")}</p><ul>{untrusted}</ul>', alt=True)
        + block("agents", "scan", t("sec.agent.title"), f'<p>{t("sec.agent.p")}</p><ul>{agent}</ul>')
        + block("observability", "pulse", t("sec.obs.title"), f'<p>{t("sec.obs.p")}</p>', alt=True)
        + block("supply-chain", "box", t("sec.supply.title"),
                f'<p>{t("sec.supply.p1", packages=_pinned_packages())}</p><p>{t("sec.supply.p2")}</p>'
                f'<p class="muted">{t("sec.more")} <a href="doc:THREAT_MODEL">THREAT_MODEL</a> · '
                f'<a href="doc:SECURITY">SECURITY</a> · <a href="doc:AI_SECURITY">AI_SECURITY</a></p>')
        + final_cta())


# The thresholds check_requirements() in veyrs-setup.sh applies. They are
# restated here because the page explains them; tests/test_site_render.py reads
# them back out of the installer, so the page cannot quietly drift from it.
SETUP_CPU_WARN_BELOW = 2          # cores: warn below this, never refuse
SETUP_RAM_OK_MB = 3800            # MemTotal at or above: ok
SETUP_RAM_MIN_MB = 1900           # below this: refuse; between: warn
SETUP_DISK_OK_MB = 12000          # free MB on /: ok
SETUP_DISK_MIN_MB = 5000          # below this: refuse; between: warn

VERIFY_SNIPPET = """B=https://github.com/visionebc/veyrs/releases/latest/download
curl -fL -O $B/veyrs-setup.sh -O $B/SHA256SUMS -O $B/SHA256SUMS.sig
# The key comes from the REPOSITORY, not from the release it vouches for:
curl -fLo allowed_signers https://raw.githubusercontent.com/visionebc/veyrs/main/release/allowed_signers
ssh-keygen -Y verify -f allowed_signers -I release@veyrs -n veyrs-release \\
    -s SHA256SUMS.sig &lt; SHA256SUMS        # must print: Good "veyrs-release" signature
sha256sum -c --ignore-missing SHA256SUMS  # must print "veyrs-setup.sh: OK"
sudo bash veyrs-setup.sh --check          # inspect this host, change nothing
sudo bash veyrs-setup.sh                  # native or Docker, bundled or external PostgreSQL"""

# Destinations of the network table. Host names are code, not prose: they stay
# here (tests/test_phase53_system_inventory.py reads them out of this file).
NET_GITHUB_HOSTS = ("<code>github.com</code>, <code>release-assets.githubusercontent.com</code> "
                    "(<code>api.github.com</code>: {latest})")
NET_NATIVE_HOSTS = "<code>pypi.org</code>, <code>files.pythonhosted.org</code>"
NET_RHEL_HOSTS = "<code>download.postgresql.org</code>"
NET_DOCKER_HOSTS = ("<code>download.docker.com</code>, <code>ghcr.io</code>, <code>pkg-containers.githubusercontent.com</code>, "
                    "<code>registry-1.docker.io</code>, <code>auth.docker.io</code>, <code>production.cloudflare.docker.com</code>")
NET_INTEL_HOSTS = ("<code>services.nvd.nist.gov</code>, <code>epss.empiricalsecurity.com</code>, "
                   "<code>www.cisa.gov</code>, <code>cwe.mitre.org</code>")
NET_UPDATE_HOSTS = ("<code>api.github.com</code>, <code>github.com</code>, "
                    "<code>release-assets.githubusercontent.com</code>")
NET_MFA_HOSTS = "<code>api.telegram.org</code>"
NET_AI_HOSTS = ("<code>api.openai.com</code>, <code>api.anthropic.com</code>, "
                "<code>generativelanguage.googleapis.com</code>")


def build_download():
    # Nominal size plus the exact gate: a "4 GB" machine reports a MemTotal
    # below 4096 MB, which is why the installer compares against 3800.
    def gb(mb):
        return f'{math.ceil(mb / 1000)} GB <span class="muted">({mb:,} MB)</span>'

    assets_tbl = _table([t("dl.th.asset"), t("dl.th.what")], [
        ["<code>veyrs-setup.sh</code>", t("dl.a.setup")],
        ["<code>SHA256SUMS</code>, <code>SHA256SUMS.sig</code>", t("dl.a.sums")],
        ["<code>veyrs-&lt;v&gt;-src.tar.gz</code>", t("dl.a.src")],
        ["<code>veyrs-&lt;v&gt;-wheels-x86_64.tar.gz</code>", t("dl.a.wheels")],
    ])
    native = _table([t("dl.th.step"), t("dl.th.priv"), t("dl.th.why"), t("dl.th.avoid")], [
        [t("dl.n1"), "<b>root</b>", t("dl.n1.w"), "<code>--skip-system-packages</code>"],
        [t("dl.n2"), t("dl.n2.p"), t("dl.n2.w"), t("dl.n2.a")],
        ["Redis", "<b>root</b>", t("dl.n3.w"), "<code>--skip-redis</code>"],
        [t("dl.n4"), t("dl.n4.p"), t("dl.n4.w"), "—"],
        [t("dl.n5"), t("dl.n5.p"), t("dl.n5.w"), "—"],
        [t("dl.n6"), "<b>root</b>", t("dl.n6.w"), "—"],
        [t("dl.n7"), "<b>root</b>", t("dl.n7.w"), "<code>--skip-nginx</code>"],
    ])
    docker = _table([t("dl.th.who"), t("dl.th.runs"), t("dl.th.notes")], [
        ["<code>veyrs-setup.sh</code>", "<b>root</b>", t("dl.d1")],
        [t("dl.d2.who"), t("dl.d2.runs"), t("dl.d2")],
        [t("dl.d3.who"), "uid <code>10001</code>", t("dl.d3")],
        ["<code>console</code>", "uid <code>101</code>", t("dl.d4")],
        ["<code>init</code>", t("dl.d5.runs"), t("dl.d5")],
        [t("dl.d6.who"), "uid <code>10001</code>", t("dl.d6")],
    ])
    network = _table([t("dl.th.dir"), t("dl.th.dest"), t("dl.th.when")], [
        [t("dl.in"), t("dl.net.in"), t("dl.net.always")],
        [t("dl.loop"), "8000", t("dl.net.loop")],
        [t("dl.out"), "5432 · 6379", t("dl.net.db")],
        [t("dl.out"), "443: " + t("dl.net.mirrors") + "; " + NET_GITHUB_HOSTS.replace("{latest}", t("dl.net.latest"))
         + "; " + t("dl.net.native") + ": " + NET_NATIVE_HOSTS + "; " + t("dl.net.rhel") + ": " + NET_RHEL_HOSTS
         + "; Docker: " + NET_DOCKER_HOSTS, t("dl.net.install")],
        [t("dl.out"), "443: " + NET_INTEL_HOSTS, t("dl.net.intel")],
        [t("dl.out"), "443: " + NET_UPDATE_HOSTS, t("dl.net.update")],
        [t("dl.out"), "443: " + NET_MFA_HOSTS + "; " + t("dl.net.relay"), t("dl.net.mfa")],
        [t("dl.out"), "443: " + NET_AI_HOSTS, t("dl.net.ai")],
    ])
    gates = _table([t("dl.th.res"), t("dl.th.refused"), t("dl.th.warn"), t("dl.th.notes")], [
        ["CPU", t("dl.never"), t("dl.cores", n=SETUP_CPU_WARN_BELOW), t("dl.g.cpu")],
        ["RAM", gb(SETUP_RAM_MIN_MB), gb(SETUP_RAM_OK_MB), t("dl.g.ram")],
        [t("dl.g.disk"), gb(SETUP_DISK_MIN_MB), gb(SETUP_DISK_OK_MB), t("dl.g.disk.n")],
        [t("dl.g.arch"), "—", "—", t("dl.g.arch.n")],
    ])
    sizing = _table([t("dl.th.deploy"), "vCPU", "RAM", t("dl.th.disk"), t("dl.th.notes")], [
        [t("dl.s1"), "2", "4 GB", "20 GB", t("dl.s1.n")],
        [t("dl.s2"), "2–4", t("dl.s2.ram"), t("dl.s2.disk"), t("dl.s2.n")],
        [t("dl.s3"), "4", "4 GB", "20 GB", t("dl.s3.n")],
        [t("dl.s4"), "4–6", "6–8 GB", "100 GB", t("dl.s4.n")],
    ])
    scale = _table([t("dl.th.findings"), "vCPU", "RAM", t("dl.th.notes")], [
        ["&lt; 50k", "2", "4 GB", t("dl.f1")],
        ["50k – 500k", "4", "8 GB", t("dl.f2")],
        ["500k – 5M", "8", "16 GB", t("dl.f3")],
        ["&gt; 5M", "—", "—", t("dl.f4")],
    ])
    ref = _table([t("dl.th.node"), t("dl.th.alloc"), t("dl.th.use")], [
        [t("dl.r1"), "4 vCPU · 4 GB RAM · 60 GB", t("dl.r1.u")],
        [t("dl.r2"), "6 vCPU · 6 GB RAM · 100 GB", t("dl.r2.u")],
    ])
    return (
        block("release", "download", t("dl.get.title"),
              f'<p class="lead">{t("dl.get.lead")}</p><pre class="code" lang="en"><code>{VERIFY_SNIPPET}</code></pre>'
              f'<p>{t("dl.get.check")}</p>{assets_tbl}'
              f'<p class="links"><a href="{RELEASES_URL}">{t("dl.get.all")}</a> · '
              f'<a href="install.html">{t("dl.get.docker")}</a></p>')
        + block("permissions", "lock", t("dl.perm.title"),
                note(t("dl.perm.note")) + f'<h3>{t("dl.perm.native")}</h3>{native}<p>{t("dl.perm.super")}</p>'
                f'<h3>{t("dl.perm.docker")}</h3>{docker}<p>{t("dl.perm.lxc")}</p>'
                f'<h3>{t("dl.perm.unasked")}</h3><ul><li>{t("dl.u1")}</li><li>{t("dl.u2")}</li><li>{t("dl.u3")}</li></ul>'
                f'<p>{t("dl.selinux")}</p><p>{t("dl.service")}</p>', alt=True)
        + block("network", "globe", t("dl.net.title"), f'<p>{t("dl.net.p")}</p>{network}')
        + block("hardware", "server", t("dl.hw.title"),
                f'<h3>{t("dl.hw.gates")}</h3><p>{t("dl.hw.gates.p")}</p>{gates}'
                + note(t("dl.hw.disk"), "warn")
                + f'<h3>{t("dl.hw.sizing")}</h3>{sizing}<p>{t("dl.hw.follow")}</p>{scale}'
                f'<h3>{t("dl.hw.ref")}</h3><p>{t("dl.hw.ref.p")}</p>{ref}', alt=True)
        + final_cta())


# The documents' own (English) names; the descriptions are translated.
DOC_TITLES = {
    "README": "README", "USER_GUIDE": "User guide", "USER_MANUAL": "User manual",
    "ADMIN_GUIDE": "Administrator guide", "DOCKER_COMPOSE_MANUAL": "Docker Compose manual",
    "ARCHITECTURE": "Architecture", "DATABASE": "Database", "API": "API",
    "HIGH_AVAILABILITY": "High availability", "DEPLOYMENT": "Deployment", "DEVELOPMENT": "Development",
    "SECURITY": "Security", "THREAT_MODEL": "Threat model", "AI_SECURITY": "AI security",
    "INTEGRATIONS": "Integrations", "DISASTER_RECOVERY": "Disaster recovery",
    "CHANGELOG": "Changelog", "CONTRIBUTING": "Contributing",
}


def build_docs():
    featured = [
        ("book", "manual", [("manual.html", "docs.f.manual.l1")]),
        ("terminal", "install", [("install.html", "docs.f.install.l1"), ("doc:INSTALLATION", "docs.f.install.l2"),
                                 ("download.html", "docs.f.install.l3")]),
        ("nodes", "arch", [("architecture.html", "docs.f.arch.l1"), ("doc:HIGH_AVAILABILITY", "docs.f.arch.l2"),
                           ("doc:ARCHITECTURE", "docs.f.arch.l3")]),
        ("shield-check", "sec", [("security.html", "docs.f.sec.l1"), ("doc:SECURITY", "docs.f.sec.l2"),
                                 ("doc:THREAT_MODEL", "docs.f.sec.l3")]),
        ("api", "api", [("doc:API_GUIDE", "docs.f.api.l1")]),
        ("library", "center", [(docs_home(), "docs.f.center.l1" if not PUBLIC_DOCS else "docs.f.center.l1p")]),
    ]
    cards = []
    for ico, key, links in featured:
        lis = "".join(f'<li><a href="{h}">{t(lk)}{icon("arrow", "ico ico-xs")}</a></li>' for h, lk in links)
        title = t(f"docs.f.{key}.t" + ("p" if key == "center" and PUBLIC_DOCS else ""))
        cards.append(f'<div class="card doc-card"><span class="tile">{icon(ico)}</span><h3>{title}</h3>'
                     f'<p>{t(f"docs.f.{key}.d")}</p><ul class="doc-links" role="list">{lis}</ul></div>')
    guide = _table([t("docs.which.th.need"), t("docs.which.th.read")], [
        [t(f"docs.which.r{i}"), t(f"docs.which.r{i}.a")] for i in range(1, 6)])
    groups = [
        ("docs.g.start", ["README", "USER_GUIDE", "USER_MANUAL", "ADMIN_GUIDE", "DOCKER_COMPOSE_MANUAL"]),
        ("docs.g.arch", ["ARCHITECTURE", "DATABASE", "API", "HIGH_AVAILABILITY", "DEPLOYMENT", "DEVELOPMENT"]),
        ("docs.g.sec", ["SECURITY", "THREAT_MODEL", "AI_SECURITY"]),
        ("docs.g.ops", ["INTEGRATIONS", "DISASTER_RECOVERY", "CHANGELOG", "CONTRIBUTING"]),
    ]
    lib = []
    for gkey, slugs in groups:
        items = "".join(
            f'<li><a href="{doc_href(s)}">{DOC_TITLES[s]}</a><span>{t("docs.d." + s)}</span></li>'
            for s in slugs)
        lib.append(f'<div class="lib-group"><h3>{t(gkey)}</h3><ul role="list">{items}</ul></div>')
    en_note = "" if LANG == SOURCE_LANG else note(t("docs.en_only"))
    return (
        f'<section class="section"><div class="wrap">{en_note}<div class="grid g3">{"".join(cards)}</div></div></section>'
        f'<section class="section alt"><div class="wrap narrow">'
        f'{section_head("docs.which.eyebrow", "docs.which.title", "docs.which.lead")}{guide}</div></section>'
        f'<section class="section"><div class="wrap">'
        f'{section_head("docs.lib.eyebrow", "docs.lib.title", "docs.lib.lead")}'
        f'<div class="library">{"".join(lib)}</div>'
        f'<p class="more">{t("docs.adr")} <a href="{adr_index()}">{t("docs.adr.link")}</a></p></div></section>')


def _repo_links(body):
    """Rewrite a rendered doc's relative links: other docs go where doc_href()
    sends them (Docs Center on the LAN, mirror in public), repository files to
    the public mirror."""
    def fix(m):
        href = m.group(1)
        if re.match(r"^(?:[a-z][a-z0-9+.-]*:|#|/)", href):
            return m.group(0)
        target, _, frag = href.partition("#")
        path = posixpath.normpath(posixpath.join("docs", target))
        if path.startswith(".."):
            return m.group(0)
        if path.startswith("docs/") and path.endswith(".md") and path.count("/") == 1:
            out = doc_href(path[5:-3])
        else:
            out = f"{REPO_URL}/{path}"
        return f'href="{out}{"#" + frag if frag else ""}"'
    return re.sub(r'href="([^"]+)"', fix, body)


def _doc_page(name):
    md = open(os.path.join(DOCS, name + ".md"), encoding="utf-8").read()
    body, toc = render_markdown(md)
    body = re.sub(r"<h1[^>]*>.*?</h1>\s*", "", body, count=1, flags=re.S)   # the page head carries it
    entries = [(text, slug) for level, text, slug in toc if level == 2]
    items = "".join(f'<li><a href="#{slug}">{html.escape(text)}</a></li>' for text, slug in entries)
    en = "" if LANG == SOURCE_LANG else (
        f'<div class="note lang-note"><p>{icon("globe", "ico ico-sm")}{t("doc.en_only")} '
        f'<a href="{locale_href(SOURCE_LANG, LOCAL_DOCS[name])}" hreflang="en" lang="en">{t("doc.en_link")}</a></p></div>')
    return f"""
<div class="wrap doc-layout">
  <aside class="doc-toc" aria-label="{t("common.on_this_page")}">
    <p class="toc-title">{t("common.on_this_page")}</p>
    <ul role="list">{items}</ul>
  </aside>
  <div class="doc-main">
    {en}
    <details class="toc-mobile"><summary>{t("common.on_this_page")} ({len(entries)})</summary><ul role="list">{items}</ul></details>
    <article class="doc" lang="en">{_repo_links(body)}</article>
  </div>
</div>"""


def build_manual():
    return _doc_page("USER_MANUAL")


def build_install():
    return _doc_page("DOCKER_COMPOSE_MANUAL")


# ---------------------------------------------------------------------------
# slug, page key, builder, kind, eyebrow key
PAGES = [
    ("index.html", "home", build_index, "home", None),
    ("features.html", "features", build_features, "page", "eyebrow.product"),
    ("architecture.html", "architecture", build_architecture, "page", "eyebrow.product"),
    ("security.html", "security", build_security, "page", "eyebrow.product"),
    ("download.html", "download", build_download, "page", "eyebrow.product"),
    ("docs.html", "docs", build_docs, "page", "eyebrow.docs"),
    ("manual.html", "manual", build_manual, "doc", "eyebrow.docs"),
    ("install.html", "install", build_install, "doc", "eyebrow.docs"),
]

HEAD_SUBNAV = {"features": FEATURE_SECTIONS}

BRAND_FILES = [
    "veyrs-logo-on-dark-gradient.png", "veyrs-mark-gradient.png",
    "veyrs-favicon.ico", "veyrs-favicon.png", "veyrs-tokens.css",
]


def _read(path):
    with open(path, "rb") as fh:
        return fh.read()


ASSET_HASH = hashlib.sha256(_read(os.path.join(ASSETS_SRC, "web.css"))
                            + _read(os.path.join(ASSETS_SRC, "fonts.css"))).hexdigest()[:10]


def render_page(slug, key, builder, kind, eyebrow_key):
    if kind == "home":
        return page(slug, BRAND_NAME, t("brand.tagline"), builder(), kind="home",
                    description=t("home.meta"))
    extra = subnav(HEAD_SUBNAV[key]) if key in HEAD_SUBNAV else ""
    return page(slug, t(f"page.{key}.title"), t(f"page.{key}.lead"), builder(),
                kind=kind, eyebrow=t(eyebrow_key), head_extra=extra)


def build_locale(code, out):
    global LANG
    LANG = code
    target = out if code == SOURCE_LANG else os.path.join(out, code)
    os.makedirs(target, exist_ok=True)
    for slug, key, builder, kind, eyebrow_key in PAGES:
        with open(os.path.join(target, slug), "w", encoding="utf-8") as fh:
            fh.write(render_page(slug, key, builder, kind, eyebrow_key))
    LANG = SOURCE_LANG


def main():
    # `global` must precede every use of the name in this scope, including
    # the argparse defaults that read the current values.
    global CONSOLE_URL, DOCS_URL, SITE_URL, PUBLIC_DOCS, WEBFONTS

    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="/var/www/veyrs-web")
    ap.add_argument("--console-url",
                    default=os.environ.get("VEYRS_SITE_CONSOLE_URL", CONSOLE_URL))
    ap.add_argument("--docs-url",
                    default=os.environ.get("VEYRS_SITE_DOCS_URL", DOCS_URL))
    ap.add_argument("--site-url", default=os.environ.get("VEYRS_SITE_URL"),
                    help="absolute URL of this site, for canonical and hreflang links "
                         f"(default {SITE_URL}, or {PUBLIC_SITE_URL} with --public)")
    ap.add_argument("--public", action="store_true",
                    help="internet-facing build: link docs to the public mirror, "
                         "not to --docs-url (which only resolves on the LAN)")
    ap.add_argument("--webfonts", choices=("self", "google"), default="self",
                    help="self: serve the console's font files (CSP font-src 'self'); "
                         "google: link Google Fonts for a host whose CSP only admits them")
    args = ap.parse_args()

    CONSOLE_URL = args.console_url.rstrip("/")
    DOCS_URL = args.docs_url.rstrip("/")
    PUBLIC_DOCS = args.public
    SITE_URL = (args.site_url or (PUBLIC_SITE_URL if args.public else SITE_URL)).rstrip("/")
    WEBFONTS = args.webfonts

    assets = os.path.join(args.out, "assets")
    os.makedirs(assets, exist_ok=True)
    for name in ("web.css", "fonts.css"):
        shutil.copyfile(os.path.join(ASSETS_SRC, name), os.path.join(assets, name))
    # The fonts are the console's own self-hosted set: one copy in the
    # repository (frontend/console/fonts/), copied here at build time.
    if os.path.isdir(os.path.join(assets, "fonts")):
        shutil.rmtree(os.path.join(assets, "fonts"))
    shutil.copytree(FONTS, os.path.join(assets, "fonts"))
    for name in BRAND_FILES:
        src = os.path.join(BRAND, name)
        if os.path.isfile(src):
            shutil.copyfile(src, os.path.join(assets, name))
        else:
            print(f"  ! missing brand asset: {name}")

    for code, _name in LANGS:
        build_locale(code, args.out)
        print(f"  {code}: {len(PAGES)} pages")

    print(f"built {len(PAGES) * len(LANGS)} pages ({len(LANGS)} locales) -> {args.out} (css {ASSET_HASH})")
    print(f"  console -> {CONSOLE_URL}")
    print(f"  docs    -> {docs_home()}")
    print(f"  site    -> {SITE_URL} (fonts: {WEBFONTS})")


if __name__ == "__main__":
    main()
