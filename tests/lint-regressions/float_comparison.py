"""A comparison against a floating point literal, which PLR2004 refuses.

The data path is floats and a blinded value differs from the true one by an
offset, so a boundary written as a comparison against a literal is a boundary
that holds on the machine it was written on and moves on the next one. A
region edge decided this way is the failure issue #8 is about, where the split
stops being the one that was committed to.

The rule is configured to flag floating point literals only, so the integer
comparison below is present on purpose: it shows the rule staying quiet where
issue #22 did not ask it to speak.

This file is never imported. It exists so the rule is shown biting rather than
declared.
"""

from __future__ import annotations


def is_at_the_region_edge(value: float, index: int) -> bool:
    if index == 0:
        return False
    return value == 0.5
