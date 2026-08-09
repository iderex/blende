"""The one exception this package raises, and what it may not carry.

Issue #18 decides that an error here is a refusal, that a refusal names what
was refused and why, and that it identifies the offending item by position,
index or field name rather than by printing it. The ordinary habit in a
numerical library is to put the offending value into the message, and here that
habit hands the analyst the answer.

So the type carries structured fields and no formatted string. The caller
decides what to render, and the default rendering is the safe one because the
fields it renders are a rule identifier, a subject and a sentence, none of
which is a place a data value can arrive.

A raise reads as the rule that refused, the name of the thing refused, and the
sentence explaining it, in that order.

What this type does not settle, and issue #18 is where it is argued. Whether a
subject may be an index into a closed region is open: an index into a closed
region is itself information about that region, which is issue #63. Nothing
here decides it, and the declarations this module is raised for carry no data,
so the question has not arrived yet.
"""

from __future__ import annotations


class Refusal(Exception):
    """A refusal, carrying what refused, what it was about, and why.

    `rule` identifies the refusal so a caller can branch on it without reading
    prose, `subject` names the item by a name or a position, and `detail` says
    why in a sentence. A data value belongs in none of the three.
    """

    def __init__(self, rule: str, subject: str, detail: str) -> None:
        super().__init__(f"{rule}: {subject}: {detail}")
        self.rule = rule
        self.subject = subject
        self.detail = detail
