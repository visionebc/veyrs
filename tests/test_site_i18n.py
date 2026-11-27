"""The product site in five languages, and the links between its pages.

`site/web/build_web.py` builds the same eight pages for English (the site root)
and for /es/, /de/, /fr/ and /it/, from `site/web/i18n/<lang>.json`. Nothing
fails at build time when a translation is incomplete (a missing key falls back
to English) or when a page in one locale links to a page that does not exist,
so these tests do:

* every locale has every key, keeps every tag, code span and placeholder of
  the English source, and translates what it does not declare identical;
* every page exists in every locale and names all of them (hreflang);
* no relative link or anchor of either build is broken;
* the public build names no LAN host in any locale;
* the output needs no inline script or style (the vhost's CSP forbids both)
  and loads its fonts from its own origin.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
WEB = ROOT / "site" / "web"
I18N = WEB / "i18n"
BUILDER = WEB / "build_web.py"
LANGS = ["en", "es", "de", "fr", "it"]
PAGES = ["index.html", "features.html", "architecture.html", "security.html",
         "download.html", "docs.html", "manual.html", "install.html"]

# A value made only of these may stay identical to English in any locale:
# brand, standards and protocol names are not translated.
TERMS = {"VEYRS", "CVE", "CVSS", "EPSS", "KEV", "CISA", "CWE", "CPE", "SLA", "SLAs", "API",
         "REST", "ITSM", "NVD", "MITRE", "FIRST", "PostgreSQL", "Redis", "Docker", "Compose",
         "Jira", "ServiceNow", "OIDC", "LDAP", "RADIUS", "TOTP", "GitHub", "Docs", "Center"}

# Split so scripts/public-export.sh, which rewrites host names, leaves the
# last one recognisable in the exported tree.
LAN_HOSTS = ("veyrs-docs.example.com", "veyrs-web-a.", "veyrs-app-1", "veyrs-app-2",
             "veyrs-app.", ".visionebc" + ".mx")


def strings(lang):
    return json.loads((I18N / f"{lang}.json").read_text(encoding="utf-8"))


def keys(d):
    return [k for k in d if not k.startswith("_")]


def tags(v):
    return Counter(re.findall(r"</?\w+", v))


def codes(v):
    return re.findall(r"<code>(.*?)</code>", v, flags=re.S)


def placeholders(v):
    return Counter(re.findall(r"\{\w+\}", v))


def only_terms(v):
    text = re.sub(r"<code>.*?</code>|<[^>]+>", " ", v)
    words = re.findall(r"[A-Za-zÀ-ÿ]{2,}", text)
    return all(w in TERMS for w in words)


# ---------------------------------------------------------------------------
# strings
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("lang", LANGS[1:])
def test_every_locale_has_every_key_and_no_other(lang):
    en, tr = strings("en"), strings(lang)
    assert keys(tr) == keys(en), (
        f"{lang}.json: missing {sorted(set(keys(en)) - set(keys(tr)))}, "
        f"extra {sorted(set(keys(tr)) - set(keys(en)))} (order must follow en.json)")
    assert all(isinstance(tr[k], str) and tr[k].strip() for k in keys(tr)), f"{lang}.json has an empty value"


@pytest.mark.parametrize("lang", LANGS[1:])
def test_translations_keep_tags_code_spans_and_placeholders(lang):
    en, tr = strings("en"), strings(lang)
    for k in keys(en):
        assert tags(tr[k]) == tags(en[k]), (lang, k, "tags differ")
        assert codes(tr[k]) == codes(en[k]), (lang, k, "a <code> span was changed")
        assert placeholders(tr[k]) == placeholders(en[k]), (lang, k, "placeholder lost")


@pytest.mark.parametrize("lang", LANGS[1:])
def test_no_value_is_left_in_english_unless_declared(lang):
    en, tr = strings("en"), strings(lang)
    declared = set(tr.get("_identical_ok", []))
    assert declared <= set(keys(en)), f"{lang}: _identical_ok names unknown keys"
    for k in keys(en):
        if tr[k] == en[k]:
            assert k in declared or only_terms(en[k]), f"{lang}: {k} is still English: {en[k]!r}"
    stale = sorted(k for k in declared if tr[k] != en[k])
    assert not stale, f"{lang}: _identical_ok lists translated keys {stale}"


def test_the_english_source_declares_nothing_identical():
    assert strings("en").get("_identical_ok") == []


def test_the_page_strings_are_read_from_the_i18n_files():
    # A string written into the builder would ship untranslated in four locales.
    src = BUILDER.read_text(encoding="utf-8")
    used = set(re.findall(r'\bt\(\s*"([a-z0-9_.]+)"\s*[,)]', src))
    en = set(keys(strings("en")))
    literal = {k for k in used if "{" not in k}
    assert literal <= en, f"keys used by the builder but missing from en.json: {sorted(literal - en)}"


# ---------------------------------------------------------------------------
# builds
# ---------------------------------------------------------------------------
def _build(out, *extra):
    subprocess.run([sys.executable, str(BUILDER), "--out", str(out), *extra],
                   check=True, capture_output=True)
    return out


@pytest.fixture(scope="module")
def lan(tmp_path_factory):
    return _build(tmp_path_factory.mktemp("lan"))


@pytest.fixture(scope="module")
def public(tmp_path_factory):
    return _build(tmp_path_factory.mktemp("public"), "--public",
                  "--console-url", "https://console.example.com")


def page_dir(root, lang):
    return root if lang == "en" else root / lang


def test_every_page_exists_in_every_locale(lan):
    for lang in LANGS:
        for page in PAGES:
            assert (page_dir(lan, lang) / page).is_file(), f"{lang}/{page} missing"


def test_every_page_declares_its_language_and_every_alternate(lan):
    base = "https://veyrs-web.example.com"
    for lang in LANGS:
        for page in PAGES:
            text = (page_dir(lan, lang) / page).read_text(encoding="utf-8")
            assert f'<html lang="{lang}">' in text, (lang, page)
            alts = dict(re.findall(r'<link rel="alternate" hreflang="([\w-]+)" href="([^"]+)">', text))
            assert set(alts) == set(LANGS) | {"x-default"}, (lang, page, sorted(alts))
            tail = "" if page == "index.html" else page
            for code in LANGS:
                assert alts[code] == f"{base}/{'' if code == 'en' else code + '/'}{tail}", (lang, page, code)
            assert alts["x-default"] == alts["en"]
            assert f'<link rel="canonical" href="{alts[lang]}">' in text, (lang, page)


def test_the_language_switcher_keeps_the_reader_on_the_same_page(lan):
    for lang in LANGS:
        text = (page_dir(lan, lang) / "security.html").read_text(encoding="utf-8")
        switch = text.split('<details class="lang lang-desk">', 1)[1].split("</details>", 1)[0]
        hrefs = dict((code, href) for href, code in re.findall(r'<a href="([^"]+)" hreflang="(\w+)"', switch))
        assert set(hrefs) == set(LANGS)
        for code, href in hrefs.items():
            target = (page_dir(lan, lang) / href).resolve()
            assert target == (page_dir(lan, code) / "security.html").resolve(), (lang, code, href)
        assert re.search(rf'hreflang="{lang}" lang="{lang}" aria-current="true"', switch), lang
        assert re.search(r'<summary aria-label="[^"]+">', switch), "the switcher needs an accessible name"


def test_titles_and_descriptions_are_translated(lan):
    seen = {}
    for lang in LANGS:
        text = (page_dir(lan, lang) / "features.html").read_text(encoding="utf-8")
        title = re.search(r"<title>([^<]+)</title>", text).group(1)
        desc = re.search(r'<meta name="description" content="([^"]+)">', text).group(1)
        seen[lang] = (title, desc)
    assert len({d for _t, d in seen.values()}) == len(LANGS), seen


def test_the_manuals_stay_english_under_a_localized_notice(lan):
    for lang in LANGS:
        for page in ("manual.html", "install.html"):
            text = (page_dir(lan, lang) / page).read_text(encoding="utf-8")
            assert '<article class="doc" lang="en">' in text, (lang, page)
            notice = strings(lang)["doc.en_only"]
            assert (notice in text) == (lang != "en"), (lang, page)


def _links(root):
    """(page, href) for every relative href/src in the build."""
    for built in sorted(root.rglob("*.html")):
        text = built.read_text(encoding="utf-8")
        for href in re.findall(r'(?:href|src)="([^"]+)"', text):
            if re.match(r"^(?:[a-z][a-z0-9+.-]*:|//)", href):
                continue
            yield built, text, href


@pytest.mark.parametrize("which", ["lan", "public"])
def test_no_internal_link_or_anchor_is_broken(which, request):
    root = request.getfixturevalue(which)
    broken = []
    for built, text, href in _links(root):
        path, _, frag = href.partition("#")
        path = path.split("?")[0]
        target = (built.parent / path).resolve() if path else built
        if not target.is_file():
            broken.append((str(built.relative_to(root)), href))
            continue
        if frag:
            body = text if target == built else target.read_text(encoding="utf-8")
            if f'id="{frag}"' not in body:
                broken.append((str(built.relative_to(root)), href))
    assert not broken, broken[:20]


def test_the_public_build_names_no_lan_host_in_any_locale(public):
    pages = sorted(public.rglob("*.html"))
    assert len(pages) == len(LANGS) * len(PAGES)
    for built in pages:
        text = built.read_text(encoding="utf-8")
        for host in LAN_HOSTS:
            assert host not in text, (str(built.relative_to(public)), host)
        assert "https://veyrs.example.com/" in text      # canonical and hreflang


def test_the_output_needs_no_inline_script_or_style(lan):
    for built in lan.rglob("*.html"):
        text = built.read_text(encoding="utf-8")
        assert "<script" not in text, built.name
        assert "<style" not in text, built.name
        assert not re.search(r"\sstyle=\"", text), built.name
        assert not re.search(r"\son[a-z]+=\"", text), built.name


def test_icons_are_svg_not_emoji(lan):
    emoji = re.compile("[\U0001F300-\U0001FAFF☀-➿⭐⭕☰]")
    for built in lan.rglob("*.html"):
        text = built.read_text(encoding="utf-8")
        body = text.split("<main", 1)[1].split('<article class="doc"', 1)[0]
        assert not emoji.search(body), (built.name, emoji.search(body).group(0))


def test_fonts_are_self_hosted_from_the_one_copy(lan):
    text = (lan / "index.html").read_text(encoding="utf-8")
    assert "fonts.googleapis" not in text and "fonts.gstatic" not in text
    css = (lan / "assets" / "fonts.css").read_text(encoding="utf-8")
    for name in re.findall(r'url\("fonts/([^"]+)"\)', css):
        assert (lan / "assets" / "fonts" / name).is_file(), name
    assert (lan / "assets" / "fonts" / "LICENSE-Inter.txt").is_file()
    # The repository holds the font files once, under frontend/console/fonts/.
    assert not list((ROOT / "site").rglob("*.woff2"))


def test_the_vhost_allows_what_the_site_loads_and_nothing_else():
    conf = (ROOT / "infrastructure" / "nginx-veyrs-web.conf").read_text(encoding="utf-8")
    csp = re.search(r'Content-Security-Policy "([^"]+)"', conf).group(1)
    policy = dict((d.split()[0], d.split()[1:]) for d in (p.strip() for p in csp.split(";")) if d)
    assert policy["font-src"] == ["'self'"]
    assert policy["style-src"] == ["'self'"]
    assert policy["script-src"] == ["'none'"]
