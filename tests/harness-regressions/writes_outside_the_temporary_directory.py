# guard: writes-outside-the-temporary-directory
"""A sample that writes into the checkout instead of into the fixed directory.

The near-miss rather than something nobody would write. A test that wants a
file next to its own module is the ordinary mistake here: the path is short,
it works on the machine it was written on, and it leaves the second run of the
suite reading the first run's output.

The path is under this directory and is never created, because the guard
refuses the open before the file exists. `--prove` reads the guard the
refusal names, and the file staying absent is the same statement read a second
way.
"""

from pathlib import Path

BESIDE_THIS_MODULE = Path(__file__).resolve().parent / "a-file-the-guard-refuses"

with BESIDE_THIS_MODULE.open("w", encoding="utf-8") as handle:
    handle.write("This line is never written.\n")
