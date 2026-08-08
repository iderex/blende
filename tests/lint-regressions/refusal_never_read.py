"""A refusal bound to a name that is never read, which F841 refuses.

The same defect as `refusal_dropped.py` in its other spelling. The refusal is
kept rather than raised, nothing reads it, and the function returns as though
the value had been accepted.

This file is never imported. It exists so the rule is shown biting rather than
declared.
"""

from __future__ import annotations


class Refusal(Exception):
    """The package's refusal, reduced to what the sample needs."""


def check_declared_range(index: int) -> None:
    refusal = Refusal(f"the value at index {index} lies outside its declared range")
