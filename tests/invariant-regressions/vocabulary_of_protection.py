"""An output template claiming the package protects something.

# invariant: no-vocabulary-of-protection

Blinding is not confidentiality. It stops an analyst reading a value they are
not meant to read yet; it does not stop anybody reading the file. A line the
package prints that says protected, secure or encrypted is a claim about a
property this package does not have, and a reader who acts on it stores real
data somewhere on the strength of it.

The word stays available to a docstring, which is how this one says what the
package does not do without tripping its own rule.

This file is never imported. It exists so the rule is shown biting rather than
declared.
"""

from __future__ import annotations


def report() -> str:
    return "the blinded values in this artefact are secure"
