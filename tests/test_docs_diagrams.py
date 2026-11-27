"""Every Mermaid diagram in docs/ has its pre-rendered SVG.

The Docs Center builder runs on the app nodes, which have no Node.js, so
Mermaid blocks are rendered to docs/diagrams/rendered/<hash>.svg on a
development machine (scripts/render-diagrams.py) and committed. The hash is
of the block's source: an edited diagram without a re-render has no SVG and
fails here, instead of the portal silently showing source text (or, worse, a
picture of the previous version).
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_every_mermaid_block_is_rendered():
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "render-diagrams.py"), "--check"],
        capture_output=True, text=True, cwd=ROOT,
    )
    assert result.returncode == 0, (
        "a ```mermaid block in docs/ has no rendered SVG.\n"
        "Render it on a machine with Node + mermaid-cli: python3 scripts/render-diagrams.py\n"
        f"{result.stdout}{result.stderr}"
    )


def test_no_rendered_svg_is_an_orphan():
    sys.path.insert(0, str(ROOT / "scripts"))
    import importlib.util
    spec = importlib.util.spec_from_file_location("render_diagrams", ROOT / "scripts" / "render-diagrams.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    from build import mermaid_hash  # noqa: E402  (site/ is on sys.path via the module)
    wanted = {mermaid_hash(src) for _doc, _line, src in mod.blocks()}
    have = {p.stem for p in (ROOT / "docs" / "diagrams" / "rendered").glob("*.svg")}
    assert not (have - wanted), f"orphan SVGs (prune with render-diagrams.py): {sorted(have - wanted)}"
