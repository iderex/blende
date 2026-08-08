"""A derivation reaching the interpreter's own hash.

# invariant: no-language-string-hash

The interpreter randomises its string hash per process by default, so a value
derived through it is one number inside a run and a different one in the next.
Nothing downstream can tell: the offset still looks like an offset, the plot
still looks like a plot, and the analysis is blinded differently on Tuesday.
Issue #17 pins the derivation to a primitive that gives the same answer on
every machine, forever.

This file is never imported. It exists so the rule is shown biting rather than
declared.
"""

from __future__ import annotations


def offset_for(name: str) -> int:
    return hash(name) % 1000
