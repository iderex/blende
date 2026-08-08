"""A module that raises one deprecation on import, to prove the gate red.

Issue #21 asks the build gate to fail on a warning raised during import, and a
gate that has never refused anything is a claim. This module makes the refusal
happen on the runner. The commit after this one removes it and the same job
goes green, and both runs are linked from the pull request body.

It is not a fixture. It carries no bytes anybody digests, it lives with the
package because the walk that has to see it walks the installed package, and it
exists for exactly two commits.
"""

from __future__ import annotations

import warnings

warnings.warn(
    "This module exists to prove that the build gate refuses a warning raised "
    "during import. It is removed in the next commit.",
    DeprecationWarning,
    stacklevel=2,
)
