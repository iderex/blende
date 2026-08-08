"""An f-string in a logging call, which G004 refuses.

The argument is formatted before the logger decides whether to emit anything,
so turning the logger off does not stop the value being built, and issue #18
counts a log line as a written artefact under the same classification as a
file. A blinded value interpolated here is a value that has been formatted
whatever the log level says.

This file is never imported. It exists so the rule is shown biting rather than
declared.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def note_entry(index: int, value: float) -> None:
    logger.info(f"entry {index} carried {value}")
