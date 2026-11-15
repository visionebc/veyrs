"""One implementation of "parse this XML without letting it own us".

Three call sites need it — vendor scan reports, uploaded documents and the
MITRE CWE catalogue — and each used to carry its own copy of the same guard:

    parser = ElementTree.XMLParser()
    parser.parser.EntityDeclHandler = refuse        # AttributeError on 3.9+

`XMLParser.parser` was deprecated in Python 3.8 and **removed in 3.9**, and both
copies swallowed the resulting `AttributeError` with a `pass`. So from the day
this ran on a modern interpreter there was no entity defence at all, while the
module docstrings claimed there was. Measured on this fleet's 3.11.2 before the
fix: a four-level nested entity turned 200 bytes of upload into 10 kB of text,
which is 1 GB at nine levels — billion laughs, live, against any endpoint that
accepts a `.nessus`/`.xml` file.

What is and is not a risk here, probed rather than assumed:

* an **external** entity (`<!ENTITY x SYSTEM "file:///etc/passwd">`) is never
  resolved — ElementTree installs no external-reference handler and expat
  reports the reference as an undefined entity. No file disclosure, no SSRF.
* an **internal** entity IS expanded, including one whose value references
  other entities. That is the amplification vector, and it is what this module
  stops.

The defence is to refuse the *declaration*, and to look for it **only in the
prolog**. A security report legitimately quotes `<!ENTITY` in a finding
description — refusing a file because of its own example text would be a
self-inflicted outage, so the scan stops at the document element.
"""
from __future__ import annotations

import re

#: The first element start tag. Nothing before it can be an element: a
#: processing instruction opens `<?`, a comment `<!--`, the doctype `<!D`.
_ROOT_RE = re.compile(rb"<[A-Za-z_]")
_ENTITY_RE = re.compile(rb"<!ENTITY", re.IGNORECASE)


class UnsafeXmlError(ValueError):
    """The document declares entities. Refused before it reaches the parser."""


def prolog_of(payload: bytes) -> bytes:
    """Everything before the document element (XML declaration, DTD, comments).

    An entity value may itself contain `<b>`, which ends the slice early — that
    is harmless: the `<!ENTITY` token always precedes its own value, so a
    declaration is still inside whatever this returns.
    """
    root = _ROOT_RE.search(payload)
    return payload if root is None else payload[: root.start()]


def reject_entity_declarations(payload: bytes) -> None:
    """Raise `UnsafeXmlError` if the document declares any entity."""
    if _ENTITY_RE.search(prolog_of(payload)):
        raise UnsafeXmlError("XML entity declarations are not allowed")


__all__ = ["UnsafeXmlError", "prolog_of", "reject_entity_declarations"]
