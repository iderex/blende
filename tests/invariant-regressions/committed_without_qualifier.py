"""An output template saying committed with no qualifier beside it.

# invariant: committed-carries-its-qualifier

Issue #6 is the sentence this project has to be honest about. A digest sitting
in a file on the analyst's own machine proves nothing, because everything the
package can see is under the control of the person it is meant to constrain.
What binds a commitment is a witness outside that control who saw the digest
first. So an artefact is witnessed or it is local, and a line that says
committed on its own tells a referee something the package cannot support.

This file is never imported. It exists so the rule is shown biting rather than
declared.
"""

from __future__ import annotations


def report() -> str:
    return "the analysis plan is committed"
