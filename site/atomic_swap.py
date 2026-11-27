#!/usr/bin/env python3
"""Publish a freshly built site directory over the live one without a gap (TD-43).

`site/build.py` used to delete `<out>/static/` and copy it back in place. The
console vhost aliases `/static/` to that directory, so a page load during a
rebuild could miss `veyrs-tokens.css`. The fix is the usual one: build into a
sibling temporary directory, then swap it into place in one step.

On Linux the swap is `renameat2(RENAME_EXCHANGE)`: the two directories trade
places atomically, so a request sees the old tree or the new tree, never a
missing one. Where that call is unavailable (another kernel, an old libc, a
filesystem that does not support it) it falls back to two renames, which leave
a window of a few microseconds in which the path does not exist, and says so.

The previous tree is kept as `<live>.prev` (one generation, outside the
document root) so a bad publish is undone with `mv`. Ownership and mode of the
live directory are copied onto the new one before the swap.

Usage:  python3 site/atomic_swap.py <new-dir> <live-dir>
"""
from __future__ import annotations

import ctypes
import ctypes.util
import os
import shutil
import sys

RENAME_EXCHANGE = 2
AT_FDCWD = -100


def _exchange(a: str, b: str) -> bool:
    """Atomically swap two paths. False when the kernel or libc cannot."""
    libc_name = ctypes.util.find_library("c")
    if not libc_name or not sys.platform.startswith("linux"):
        return False
    libc = ctypes.CDLL(libc_name, use_errno=True)
    fn = getattr(libc, "renameat2", None)
    if fn is None:
        return False
    fn.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    fn.restype = ctypes.c_int
    return fn(AT_FDCWD, os.fsencode(a), AT_FDCWD, os.fsencode(b), RENAME_EXCHANGE) == 0


def _copy_identity(src: str, dst: str) -> None:
    """Give `dst` the owner, group and mode of `src` (best effort for non-root)."""
    st = os.stat(src)
    os.chmod(dst, st.st_mode & 0o7777)
    try:
        os.chown(dst, st.st_uid, st.st_gid)
        for root, dirs, files in os.walk(dst):
            for name in dirs + files:
                os.chown(os.path.join(root, name), st.st_uid, st.st_gid, follow_symlinks=False)
    except PermissionError:
        pass  # not root: the files keep the builder's owner


def swap(new_dir: str, live_dir: str) -> str:
    """Make `live_dir` the content of `new_dir`. Returns "exchange" or "rename"."""
    new_dir, live_dir = os.path.abspath(new_dir), os.path.abspath(live_dir)
    if not os.path.isdir(new_dir):
        raise SystemExit(f"{new_dir} is not a directory")
    prev = live_dir + ".prev"
    if not os.path.isdir(live_dir):                    # first publish
        os.makedirs(os.path.dirname(live_dir), exist_ok=True)
        os.chmod(new_dir, 0o755)
        os.rename(new_dir, live_dir)
        return "rename"
    _copy_identity(live_dir, new_dir)
    if _exchange(new_dir, live_dir):
        # `new_dir` now holds the OLD tree: it becomes the single kept generation.
        shutil.rmtree(prev, ignore_errors=True)
        os.rename(new_dir, prev)
        return "exchange"
    shutil.rmtree(prev, ignore_errors=True)
    os.rename(live_dir, prev)
    os.rename(new_dir, live_dir)
    return "rename"


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    how = swap(argv[1], argv[2])
    print(f"published {argv[2]} ({how}; previous tree in {os.path.abspath(argv[2])}.prev)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
