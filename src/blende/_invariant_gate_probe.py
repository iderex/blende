"""A module that proves the greppable invariants gate red on the runner.

Issue #28 asks for rules, and a rule nobody has watched refuse anything is a
pattern in a file. This is the mistake in the shape it actually arrives in: a
line the package prints, saying the plan is committed, with neither of the two
words that tell a referee whether anybody outside the analysis saw the digest.
Issue #6 is where that distinction is decided and why it cannot be softened.

The commit after this one removes the module, so the tree that merges is the
one the gate passes on.
"""

from __future__ import annotations


def report() -> str:
    return "the analysis plan is committed"
