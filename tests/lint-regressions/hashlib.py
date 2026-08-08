"""A module named after one in the standard library, which A005 refuses.

The file name is the whole defect and its body is beside the point. Issue #1
writes the key derivation, the commitment and the hash chain against `hashlib`
and `hmac` and nothing else, because a third party dependency on that surface
fails silently: an offset from a changed primitive still looks like an offset.
A file in the tree called `hashlib.py` puts an unreviewed module on the import
path ahead of the one that argument is about, and nothing downstream can tell.

This file is never imported, and the name is the reason it is confined to a
directory the package does not reach. It exists so the rule is shown biting
rather than declared.
"""

from __future__ import annotations


def sha256(data: bytes) -> bytes:
    return data
