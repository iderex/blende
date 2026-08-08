"""A module that proves `fmt` and `lint` red on the runner.

Issue #22 asks for gates, and a gate nobody has watched refuse anything is a
workflow file. This module is written the way the mistake actually arrives:
somebody wraps a read in a handler that names no type, and the line runs long
because the message explains itself. Both gates refuse it. The commit after
this one removes the module, so the tree that merges is the one they pass on.
"""

from __future__ import annotations

from pathlib import Path


def read_region_declaration( path: Path ):
    try:
        return path.read_bytes()
    except:
        return None
