"""The byte contracts, and nothing that is not one.

Issue #2 decides that the derivation, the commitment and the hash chain are
specified as functions of bytes, published as vectors, and reproducible by an
implementation in another language that has read the specification and not this
source. This package is the reference implementation of those contracts rather
than the definition of them.

What that costs is an import rule this layer holds and the rest of the package
does not. Nothing here imports anything outside the standard library, ever, and
`contract-imports-stdlib-only` in `tools/greppable_invariants.py` refuses the
first line that tries. A reader implementing the contract in C++ reads these
modules as prose about bytes; a third-party import in one of them would be a
line that reader cannot follow.

Two rules follow from the same place and are worth stating where a module
author meets them. Nothing here may depend on dictionary ordering, on the
machine word size, or on the interpreter's own string hash, because all three
differ between two runs of the same analysis. And a value that enters a digest
enters it through `canonical`, so there is one answer to how a string becomes
bytes rather than one per module.

What is here today is the canonical encoding every value enters a digest
through, the declaration set from issue #36, the blinding key from issue #42,
the mapping from digest bytes to a number from issue #40, the offset a
location parameter is blinded by from issue #37, and the bound on writing a
blinded value and reading it back from issue #41. The factor for a scale
parameter is #38, the commitment is #46 and the chain is #54, and none of those
three is here yet.
"""

from __future__ import annotations

__all__: list[str] = []
