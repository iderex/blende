"""A bare `except`, which E722 refuses.

Every refusal in this package is an exception, so a handler that names no type
catches the guards along with the input errors it was written for. The reader
below swallows a refusal about a closed region record and returns as though
the file had been read, which turns a guard that bit into a guard that did
nothing, silently.

This file is never imported. It exists so the rule is shown biting rather than
declared.
"""

from __future__ import annotations

from pathlib import Path


def read_region_declaration(path: Path) -> bytes | None:
    try:
        return path.read_bytes()
    except:
        return None
