"""The site renderer and the product site's manual pages.

`site/build.py` renders `docs/*.md` for both sites, with a deliberately small
Markdown subset. Two gaps in that subset mangled every manual in silence:

* a list item that wrapped onto an indented line was cut at the line break and
  the rest became a stray paragraph — 1185 such lines across `docs/`, splitting
  any **bold** that crossed the break;
* a fence or table indented under a list item was not recognised at all.

Nothing fails when a manual renders badly; these tests make it fail.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "site"))

from build import render  # noqa: E402


def html(md: str) -> str:
    return render(md)[0]


def test_a_wrapped_list_item_stays_one_item():
    out = html("- **Two keys,\n  both required.** More text.\n- next")
    assert out.count("<li>") == 2
    assert "<strong>Two keys, both required.</strong>" in out
    assert "<p>" not in out


def test_a_bare_quote_marker_separates_paragraphs_inside_the_quote():
    out = html("> one\n>\n> two")
    assert out == "<blockquote><p>one</p>\n<p>two</p></blockquote>"
    assert "&gt;" not in out


def test_a_fence_inside_a_quote_is_code():
    out = html("> Verify:\n>\n> ```bash\n> md5sum a b\n> ```")
    assert '<pre class="code" data-lang="bash"><code>md5sum a b</code></pre>' in out
    assert "```" not in out


def test_a_single_paragraph_quote_renders_as_before():
    assert html("> one\n> two") == "<blockquote>one two</blockquote>"


def test_an_indented_fence_under_a_list_item_is_code_with_the_indent_removed():
    out = html("1. Add:\n\n   ```ini\n   A=1\n     B=2\n   ```\n\n3. Start it")
    assert '<pre class="code" data-lang="ini"><code>A=1\n  B=2</code></pre>' in out
    assert "```" not in out


def test_numbering_survives_a_code_block_between_items():
    out = html("1. a\n2. b\n\n   ```\n   x\n   ```\n\n3. c")
    assert '<ol start="3"><li>c</li></ol>' in out


def test_an_indented_table_is_a_table():
    out = html("- item\n\n  | a | b |\n  |---|---|\n  | 1 | 2 |\n")
    assert "<table>" in out and "<td>1</td>" in out


def test_a_pipe_line_that_is_not_a_table_terminates():
    # Used to loop forever: the paragraph collector stopped at "|" without
    # consuming it.
    assert "a | b" in html("| a | b")


def test_every_doc_renders_without_stray_markup():
    for md in sorted((ROOT / "docs").glob("*.md")):
        out = html(md.read_text(encoding="utf-8"))
        prose = re.sub(r"<pre.*?</pre>|<code>.*?</code>", "", out, flags=re.S)
        assert "<p>&gt;" not in prose, md.name
        assert "```" not in prose, md.name


def test_the_product_site_serves_the_docker_manual(tmp_path):
    subprocess.run([sys.executable, str(ROOT / "site" / "web" / "build_web.py"),
                    "--out", str(tmp_path)], check=True, capture_output=True)
    page = (tmp_path / "install.html").read_text()
    assert "Docker Compose" in page
    for built in tmp_path.glob("*.html"):
        text = built.read_text()
        assert 'href="install.html"' in text, f"{built.name} has no Install link"
        # Repo-relative links 404 on the site; they must point at the mirror.
        for href in re.findall(r'href="([^"]+)"', text):
            if re.match(r"^(https?:|#|/)", href):
                continue
            assert (tmp_path / href.split("#")[0].split("?")[0]).exists(), (built.name, href)
    assert "https://github.com/visionebc/veyrs/blob/main/INSTALL.md" in page


def test_the_public_build_never_links_to_the_lan_docs_site(tmp_path):
    # veyrs-a only resolves on the LAN: on the public site every such link is
    # dead. The public build sends documentation links to the mirror instead,
    # and each one must name a file that exists in the repository.
    subprocess.run([sys.executable, str(ROOT / "site" / "web" / "build_web.py"),
                    "--out", str(tmp_path), "--public"], check=True, capture_output=True)
    mirror = "https://github.com/visionebc/veyrs/blob/main/"
    for built in tmp_path.glob("*.html"):
        text = built.read_text()
        assert "veyrs-docs.example.com" not in text, built.name
        assert 'href="doc:' not in text, built.name
        for href in re.findall(r'href="' + re.escape(mirror) + r'([^"#]+)', text):
            assert (ROOT / href).exists(), (built.name, href)


def test_the_lan_build_has_no_unresolved_doc_links(tmp_path):
    subprocess.run([sys.executable, str(ROOT / "site" / "web" / "build_web.py"),
                    "--out", str(tmp_path)], check=True, capture_output=True)
    for built in tmp_path.glob("*.html"):
        text = built.read_text()
        assert 'href="doc:' not in text and "{doc_href" not in text, built.name
        # The docs site has no /adr/ index page (403); the ADR README is it.
        assert "/adr/\"" not in text, built.name


def test_bold_may_contain_italics_and_sit_inside_a_word():
    out = html("1. **\"Due\" is measured from the last *successful* run.** Then.\n\n"
               "The chain: **V**isibility · **E**xposure.")
    assert "**" not in out
    assert '<strong>"Due" is measured from the last <em>successful</em> run.</strong>' in out
    assert "<strong>V</strong>isibility · <strong>E</strong>xposure" in out


def test_asterisks_inside_code_are_code_not_emphasis():
    out = html("Scopes are `*:*` or `a*b*c`, and **bold** stays bold.")
    assert "<code>*:*</code>" in out and "<code>a*b*c</code>" in out
    assert "<strong>bold</strong>" in out


def test_no_doc_leaves_markdown_emphasis_on_the_page():
    for md in sorted((ROOT / "docs").rglob("*.md")):
        out = html(md.read_text(encoding="utf-8"))
        for span in re.findall(r"<code>.*?</code>", out, flags=re.S):
            assert "<em>" not in span and "<strong>" not in span, (md.name, span)
        prose = re.sub(r"<pre.*?</pre>|<code>.*?</code>", "", out, flags=re.S)
        assert "**" not in prose, md.name
