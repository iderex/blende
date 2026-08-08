"""A blinding string written into a tracked file.

# invariant: no-blinding-string-literal

Issue #4 settles the custody model: the string is generated outside the
analysis, supplied at run time from a file path or a named environment
variable, and written nowhere. A literal in the tree is a key held by everybody
who has the tree, and by everybody who ever had it, because git keeps it after
the line is deleted.

This file is never imported. It exists so the rule is shown biting rather than
declared.
"""

from __future__ import annotations

BLINDING_KEY = "kolibri-vier-und-zwanzig-sieben"


def offset_for(name: str) -> str:
    return BLINDING_KEY + name
