"""The console Documentation link must leave the console (0.38.1).

Since the console moved to its own vhost, ``href="/"`` on it was the console
itself: clicking Documentation just reloaded the page. The console now links
to ``/documentation`` and every vhost that serves it redirects that path to a
real documentation site.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
INDEX = ROOT / "frontend" / "console" / "index.html"
VHOSTS = {
    "host": ROOT / "infrastructure" / "nginx-veyrs-console.conf",
    "docker": ROOT / "docker" / "console.conf",
    "install": ROOT / "install.sh",
}
REDIRECT = re.compile(r"location\s*=\s*/documentation\s*\{\s*return\s+30[12]\s+(\S+);")


def _doc_links() -> list[str]:
    html = INDEX.read_text()
    tags = re.findall(r"<a\b[^>]*>(?:(?!</a>).)*?</a>", html, re.S)
    return [t for t in tags if "Documentation" in t]


def test_every_documentation_link_targets_the_redirect() -> None:
    links = _doc_links()
    assert len(links) >= 2, "login footer and shell should both link to the docs"
    for tag in links:
        assert 'href="/documentation"' in tag, tag
        assert 'rel="noopener"' in tag, tag


def test_no_console_link_points_at_its_own_root() -> None:
    assert 'href="/"' not in INDEX.read_text()


@pytest.mark.parametrize("name", sorted(VHOSTS))
def test_each_console_vhost_redirects_documentation(name: str) -> None:
    match = REDIRECT.search(VHOSTS[name].read_text())
    assert match, f"{name}: no `location = /documentation` redirect"
    target = match.group(1)
    assert target.startswith(("https://", "${")), f"{name}: {target}"
    # Not back to the console itself: none of the vhost's own names. (Spelled
    # this way, not as a host literal: the public export refuses internal
    # host names anywhere in the tree, tests included.)
    own = {n for line in re.findall(r"^\s*server_name\s+([^;]+);", VHOSTS[name].read_text(), re.M)
           for n in line.split() if n != "_" and not n.startswith("$")}
    assert not any(n in target for n in own), f"{name}: redirects back to the console ({target})"


def test_the_host_vhost_sends_operators_to_the_docs_center() -> None:
    target = REDIRECT.search(VHOSTS["host"].read_text()).group(1)
    assert target == "https://veyrs-docs.example.com/"


def test_install_sh_defines_a_default_docs_url() -> None:
    text = VHOSTS["install"].read_text()
    assert re.search(r'^DOCS_URL="\$\{DOCS_URL:-https://', text, re.M)
