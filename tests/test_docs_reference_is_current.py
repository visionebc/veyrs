"""The generated reference must describe the code it was generated from.

`scripts/gen-reference-docs.py --check` is the contract, exactly like the
schema reference (tests/test_docs_are_current.py): the API reference (every
operation, its authentication and permissions), the configuration reference,
the RBAC matrix and the file inventory are rebuilt from the code and compared
byte for byte. A new route, setting, permission or file that skips the
regeneration fails here, with the command that fixes it in the message.

The traceability matrix and the coverage index measure the hand-written
documents, so they change with every manual edit; they are checked for
presence only (see the generator's docstring for why).
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_the_generated_reference_matches_the_code():
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "gen-reference-docs.py"), "--check"],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    assert result.returncode == 0, (
        "the generated reference under docs/api/reference and docs/reference no longer "
        "describes the code.\nRegenerate it: python3 scripts/gen-reference-docs.py\n"
        f"{result.stdout}{result.stderr}"
    )
