# guard: writes-outside-the-temporary-directory
"""A sample that removes a whole tree in the checkout rather than one file.

The second of two samples for this guard, and they are two because the guard
refuses at two places. Removing a tree walks it by directory descriptor and
unlinks each entry by its bare name, which is the one shape this hook passes
over, so the call that starts the walk is read instead, where the path is
still whole. Without that arm a test could delete any part of the checkout and
meet no refusal.

The path does not exist and is never created. The refusal arrives before the
call looks for it, so a run where the guard failed to bite ends by saying the
directory is not there rather than by removing one that is.
"""

import shutil
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent.parent
NOTHING_IS_THERE = REPOSITORY_ROOT / "a-tree-the-guard-refuses"

shutil.rmtree(NOTHING_IS_THERE)
