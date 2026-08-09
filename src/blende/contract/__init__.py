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

What is here today is the declaration set from issue #36 and the canonical
encoding it is serialised by. The derivation, the commitment and the chain are
issues #40, #46 and #54 and are not here yet.
"""

from __future__ import annotations

__all__: list[str] = []
