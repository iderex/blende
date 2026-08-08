"""A contract module reaching outside the standard library.

# invariant: contract-imports-stdlib-only

The contract layer is what an outside implementation reads as a specification
and reimplements in another language, and it is the layer whose failure is
silent: an offset derived through a changed primitive still looks like an
offset. An import of anything this repository does not ship with the
interpreter puts a third party between the specification and the number.

This file is never imported. It exists so the rule is shown biting rather than
declared.
"""

from __future__ import annotations

import numpy


def derive_offset(name: str) -> float:
    return float(numpy.float64(0))
