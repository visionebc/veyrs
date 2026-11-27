"""Bounded upload reading shared by the routes that accept files."""
from __future__ import annotations

from fastapi import HTTPException, UploadFile, status

_CHUNK = 64 * 1024


async def read_capped(file: UploadFile, max_bytes: int, *, detail: str = "file too large") -> bytes:
    """Read an upload without ever holding more than ``max_bytes`` + one chunk.

    ``await file.read()`` materialises the whole body before the size test, so
    the cap protected nothing but the database. This stops at the first chunk
    that crosses the limit and answers 413.
    """
    buf = bytearray()
    while True:
        chunk = await file.read(_CHUNK)
        if not chunk:
            break
        buf += chunk
        if len(buf) > max_bytes:
            raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail)
    return bytes(buf)
