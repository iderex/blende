"""A core module importing a plotting backend at the top of the file.

# invariant: core-imports-required-only

Issue #1 keeps every plotting library optional so that a batch job writing
blinded numbers on a compute node does not have to install one. An import at
module level makes the whole package fail to import where the backend is
absent, which turns an optional dependency into a required one without anybody
editing the metadata that says otherwise.

The same import inside a function is the form that stays available, and the
rule leaves it alone on purpose.

This file is never imported. It exists so the rule is shown biting rather than
declared.
"""

from __future__ import annotations

import matplotlib


def draw() -> None:
    return matplotlib.nothing
