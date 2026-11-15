"""Outbound collection for VEYRS's intelligence feeds.

Split from `services.intelligence` on purpose: everything under `services` is a
pure function over records already in hand and is therefore testable with no
network. This package is the only code in the backend that reaches NVD, FIRST
or CISA, so the URLs, the rate limits, the retry policy and the watermark
arithmetic all live here and nowhere else.
"""
from . import feeds

__all__ = ["feeds"]
