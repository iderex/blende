"""A refusal that is built and then dropped, which PLW0133 refuses.

Issue #18 makes a refusal an exception carrying structured fields, so this is
the shape the mistake takes here: a helper builds the refusal, the caller
treats building it as raising it, and the run walks on past a violation it had
already detected.

The rule reaches the first function below and not the second, and that was
measured rather than assumed:

    ruff check --isolated --select PLW0133 --output-format concise pl.py
    pl.py:10:5: PLW0133 Missing `raise` statement on exception

where line 10 is the builtin and the call to the locally declared subclass at
line 6 produced nothing. The linter recognises exceptions it knows by name, so
a package that raises its own type keeps the second half of this invariant
uncovered. `refusal_never_read.py` covers the spelling that binds the refusal
to a name, which does hold for any type. What is left over is a call whose
returned refusal is discarded, and no rule in the tool reaches it.

This file is never imported. It exists so the rule is shown biting rather than
declared, and the check that reads it is the `lint` job in
`.github/workflows/style.yml`.
"""

from __future__ import annotations


class Refusal(Exception):
    """The package's own refusal, reduced to what the sample needs."""


def check_declared_range(index: int) -> None:
    Refusal(f"the value at index {index} lies outside its declared range")


def check_region_is_total(index: int) -> None:
    ValueError(f"the record at index {index} was placed in no region")
