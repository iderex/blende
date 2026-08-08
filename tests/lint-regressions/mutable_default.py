"""A mutable default argument, which B006 refuses.

The default is built once when the function is defined and is then shared by
every call that does not pass one. Here the value carried across calls is a
list of record entries, so the second analysis in a process starts holding the
first one's decisions, and the record of decisions says something false about
what was decided and when.

This file is never imported. It exists so the rule is shown biting rather than
declared.
"""

from __future__ import annotations


def record_decision(text: str, entries: list[str] = []) -> list[str]:
    entries.append(text)
    return entries
