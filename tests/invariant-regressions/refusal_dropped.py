"""A refusal built as a statement and never raised.

# invariant: refusal-is-raised-not-dropped

Issue #18 makes a refusal an exception carrying structured fields, so the
mistake has a shape: a helper builds the refusal, the caller treats building it
as raising it, and the run walks on past a violation it had already found. A
package that detects a blinding violation and continues is a blind analysis
that is not blind.

The lint gate covers the spelling that binds the refusal to a name and never
reads it, and the spelling where the linter recognises the exception by name.
This rule is the one that reaches a helper of this package's own, which neither
of those does.

This file is never imported. It exists so the rule is shown biting rather than
declared.
"""

from __future__ import annotations


def check_declared_range(index: int) -> None:
    refuse_out_of_range(index)


def refuse_out_of_range(index: int) -> Exception:
    return ValueError(f"the value at index {index} is outside its declared range")
