"""The published vectors for the offset derivation, and how the file is made.

Issue #43 asks for files an implementation in another language can be checked
against without reading this source. This tool writes the first of them. The
derivation is what the tree carries today: issue #40's mapping from digest
bytes to a number and issue #37's offset for a location parameter. The
commitment in issue #46 and the chain in issue #54 do not exist, so neither
has a vector file here, and the issue stays open for them.

    python tools/derivation_vectors.py            # write the file
    python tools/derivation_vectors.py --check    # exit 1 if it would change

`--check` is for a person about to commit. The default suite reads the file and
recomputes every field from the package, in `tests/test_vectors.py`, so the
gate does not depend on this tool being run.

## Why a tool writes it rather than a person

Every number in the file is a digest or a double, and both are unreadable
enough that a hand-edited one would be indistinguishable from a correct one.
What keeps this from being circular is where the check lives: the suite does
not import this module. It reads the file as an outside implementation would
and calls the package, so the file is evidence about the package rather than a
copy of this tool's output compared with itself.

## What the file is

Plain text, one `name value` pair per line, records separated by a blank line,
comments on lines beginning with `#`. No structure a reader needs a parser for,
because the reader this exists for is somebody writing the derivation in C++
who is not going to install anything to read a test vector.

Every byte string is lower-case hexadecimal. Every number is written twice: as
the shortest decimal that round-trips, and as its IEEE-754 binary64 bytes
big-endian in hexadecimal. Issue #43 asks for both and gives the reason - a
decimal rendering of a double is ambiguous unless it round-trips, and an
implementation that agrees only on the decimal has not been tested.

## The first line

`blende never-blinded blende/derivation-vectors/1 - -`, which is issue #11's
field in the shape that issue fixes: the name, then the state, the format
identifier, the key fingerprint and the commitment digest, separated by single
spaces, ahead of everything else including the comments.

The state is `never-blinded` because the file is produced outside a blind
analysis and makes no claim about a measurement. The last two values are `-`
for a reason worth stating rather than leaving a reader to infer: this file is
not written under one key, it carries several, so a single fingerprint at the
top would name one of them and read as covering all. The fingerprint of each
vector's own key is a field of that vector instead.

## The format identifier

`blende/derivation-vectors/1` is this file's own format under issue #2, and it
is separate from the contracts the vectors are of. A change to which fields a
record carries, or to their order, is a change to it. A change to what the
package computes is a change to `blende/location-offset/1` or
`blende/blinding-key/2`, which the header records so that a reader can tell the
two apart.

It is declared here rather than in `src/`. Nothing in the package reads this
file, and an identifier in the contract layer that no code there uses is an
identifier somebody has to guess the owner of.

## What this does not cover

A group from issue #39. The issue asks for one, group rules are contract as
much as the transforms are, and the declaration carries no group field at all,
so there is nothing to write a vector of.

The factor for a scale parameter, which is issue #38, and the logit offset for
a bounded fraction. Neither transform exists; the derivation refuses a
declaration naming either.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
import sys
import unicodedata
from dataclasses import dataclass
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent

sys.path.insert(0, str(REPOSITORY_ROOT / "src"))

from blende.contract import derivation, interval  # noqa: E402
from blende.contract import key as key_module  # noqa: E402
from blende.contract.declaration import (  # noqa: E402
    DEFAULT_HALF_WIDTH_MULTIPLE,
    Declaration,
    Kind,
    Transform,
)

VECTOR_FILE = REPOSITORY_ROOT / "tests" / "fixtures" / "vectors" / "derivation.txt"

# This file's own format under issue #2, and not the contract of anything it
# describes. See the module docstring for which is which.
FORMAT = "blende/derivation-vectors/1"

# Issue #11's field, ahead of everything else in the artefact.
STATE_LINE = f"blende never-blinded {FORMAT} - -"

_DOUBLE = struct.Struct(">d")

# A published string, in the file so that an outside implementation has the
# exact bytes. It is not a key anybody should use and the file says so.
PUBLISHED_STRING = "blende-published-vector-string-0001"

# Sixteen characters exactly, which is `key.MINIMUM_CHARACTERS`. The floor is
# read from the module rather than written here, and the string is checked
# against it below, so a raised floor reddens this tool instead of silently
# producing a vector the package would now refuse.
MINIMUM_STRING = "vector-key-00001"

# The block a SHA-256 compression step consumes, in bytes. Written here
# because two of the cases below are placed against it and a reader has to see
# what the number is; nothing in the package depends on it.
BLOCK = 64

# One byte past a block. A keyed digest replaces a key longer than its block
# with the digest of that key, and a hand-written keyed hash that skips that
# step agrees with this package on every shorter key and on nothing else.
LONG_MATERIAL = bytes(range(BLOCK + 1))

# A name whose UTF-8 encoding is exactly one block. The padding is computed so
# that editing the prose cannot leave the case sitting somewhere else, which is
# how a boundary case quietly stops being one.
_BLOCK_NAME_STEM = "a-parameter-name-of-exactly-one-sha-256-block-in-utf-8-"
BLOCK_NAME = _BLOCK_NAME_STEM + "0" * (BLOCK - len(_BLOCK_NAME_STEM.encode("utf-8")))

# A name given decomposed: `e` followed by a combining acute accent, which NFC
# composes to one code point outside the basic Latin set. The canonical
# encoding normalises before it encodes, so the bytes that reach the digest are
# not the bytes a caller passed in, and a vector carrying only the normalised
# form would not show that.
DECOMPOSED_NAME = "é-deposited-energy"


@dataclass(frozen=True)
class Case:
    """One offset vector: what goes in, under which key, and why it is here."""

    id: str
    purpose: str
    declaration: Declaration
    blinding_key: key_module.BlindingKey
    # The exact string a caller passed to `key.from_text`, or `None` where the
    # material arrived through `key.from_bytes`. It is written into the file so
    # an implementation reproducing the material has the input rather than the
    # result of the normalisation.
    key_text: str | None


@dataclass(frozen=True)
class MappingCase:
    """One vector of issue #40's mapping, taken on a digest chosen by hand."""

    id: str
    purpose: str
    digest: bytes
    low: float
    high: float


def _hex(value: bytes) -> str:
    return value.hex()


def _bits(value: float) -> str:
    return _DOUBLE.pack(value).hex()


def _text(value: str) -> str:
    return value.encode("utf-8").hex()


def _location(
    name: str,
    low: float = 100.0,
    high: float = 200.0,
    uncertainty: float = 2.0,
    multiple: float | None = None,
) -> Declaration:
    """A blinded location parameter, which is what every vector here is of.

    The defaults are one baseline the cases move away from a field at a time,
    so a record that differs from another in one place says so in one argument
    rather than in a literal a reader has to compare line by line. The kind and
    the transform are not arguments: the derivation refuses every other pairing,
    so a vector of one could not be written.
    """
    return Declaration(
        name=name,
        kind=Kind.LOCATION,
        low=low,
        high=high,
        uncertainty=uncertainty,
        half_width_multiple=multiple,
        transform=Transform.OFFSET,
        blinded=True,
    )


def offset_cases() -> tuple[Case, ...]:
    """The offset vectors, each named for the thing it is the case of."""
    published = key_module.from_text(PUBLISHED_STRING)
    return (
        Case(
            id="ordinary-location-parameter",
            purpose=(
                "the common case: a location parameter with a declared range, "
                "a declared uncertainty and no multiple of its own"
            ),
            declaration=_location("mass"),
            blinding_key=published,
            key_text=PUBLISHED_STRING,
        ),
        Case(
            id="second-parameter-under-one-key",
            purpose=(
                "the same key and a different name, which is the whole of the "
                "domain separation: an implementation that leaves the name out "
                "of the message agrees with the vector above and not with this"
            ),
            declaration=_location("lifetime"),
            blinding_key=published,
            key_text=PUBLISHED_STRING,
        ),
        Case(
            id="range-straddling-zero",
            purpose=(
                "a range whose endpoints have opposite signs, and a small "
                "uncertainty, so the half-width is not the same order as the "
                "range"
            ),
            declaration=_location("time-offset", low=-5.0, high=5.0, uncertainty=0.25),
            blinding_key=published,
            key_text=PUBLISHED_STRING,
        ),
        Case(
            id="half-width-multiple-declared-rather-than-defaulted",
            purpose=(
                "a declaration naming its own multiple, so the half-width is "
                "not the default multiple times the uncertainty and an "
                "implementation that hard-codes the default disagrees"
            ),
            declaration=_location("mass", multiple=2.5),
            blinding_key=published,
            key_text=PUBLISHED_STRING,
        ),
        Case(
            id="name-outside-the-basic-latin-set",
            purpose=(
                "a name given decomposed, so the bytes in the message are the "
                "NFC form and not the bytes the caller passed"
            ),
            declaration=_location(
                DECOMPOSED_NAME,
                low=0.0,
                high=1000.0,
                uncertainty=12.5,
            ),
            blinding_key=published,
            key_text=PUBLISHED_STRING,
        ),
        Case(
            id="name-of-exactly-one-block",
            purpose=(
                "a name whose UTF-8 encoding is exactly one SHA-256 block, "
                "which is where a hand-written digest goes wrong"
            ),
            declaration=_location(BLOCK_NAME),
            blinding_key=published,
            key_text=PUBLISHED_STRING,
        ),
        Case(
            id="minimum-length-blinding-string",
            purpose=(
                "the shortest string the key module admits, so an "
                "implementation can check its own floor against this one"
            ),
            declaration=_location("mass"),
            blinding_key=key_module.from_text(MINIMUM_STRING),
            key_text=MINIMUM_STRING,
        ),
        Case(
            id="key-material-longer-than-one-block",
            purpose=(
                "material one byte past a SHA-256 block, arriving as bytes "
                "rather than as text, which is the case a keyed digest hashes "
                "the key for"
            ),
            declaration=_location("mass"),
            blinding_key=key_module.from_bytes(LONG_MATERIAL),
            key_text=None,
        ),
    )


def mapping_cases() -> tuple[MappingCase, ...]:
    """The endpoints of issue #40's mapping, on digests a derivation cannot aim at.

    A digest of all zero bytes and one of all one bytes are the two ends of the
    mapping, and no key and name can be searched for that produce either. They
    are taken directly on the mapping for that reason, which is also how the
    rule about the upper endpoint becomes visible: on the unit interval the
    all-one digest converts to exactly one, and the mapping returns the
    greatest double below it instead.
    """
    width = hashlib.new(derivation.DIGEST).digest_size
    read = interval.DIGEST_BYTES
    zero = bytes(width)
    one = b"\xff" * width
    mixed = bytes(read) + b"\xff" * (width - read)
    return (
        MappingCase(
            id="all-zero-digest-on-the-unit-interval",
            purpose="the lower endpoint, which is reachable and is the endpoint",
            digest=zero,
            low=0.0,
            high=1.0,
        ),
        MappingCase(
            id="all-one-digest-on-the-unit-interval",
            purpose=(
                "the upper endpoint, where the exact value is below it and the "
                "conversion rounds onto it, so the mapping steps back one double"
            ),
            digest=one,
            low=0.0,
            high=1.0,
        ),
        MappingCase(
            id="all-zero-digest-on-a-symmetric-interval",
            purpose="the lower endpoint of an interval an offset is drawn from",
            digest=zero,
            low=-10.0,
            high=10.0,
        ),
        MappingCase(
            id="all-one-digest-on-a-symmetric-interval",
            purpose=(
                "the upper end of the same interval, where the exact value is "
                "representable and no step back is taken"
            ),
            digest=one,
            low=-10.0,
            high=10.0,
        ),
        MappingCase(
            id="digest-differing-outside-the-bytes-read",
            purpose=(
                "the leading bytes of the all-zero digest and different bytes "
                "after them, which the mapping does not read, so this record "
                "and the first one carry one number"
            ),
            digest=mixed,
            low=0.0,
            high=1.0,
        ),
    )


PREAMBLE = """\
# Published vectors for the offset a location parameter is blinded by.
#
# Issue #43. An implementation in another language agrees with this package
# when it reproduces every value below from the inputs beside them. Reading
# this repository's source is not required and is not the intent.
#
# Format. One `name value` pair per line, records separated by a blank line, a
# record opening with `vector <kind> <id>`. Lines beginning with `#` are
# comments and the first line of the file is issue #11's field rather than a
# comment. Byte strings are lower-case hexadecimal. Every number appears twice,
# as the shortest decimal that round-trips and as its IEEE-754 binary64 bytes
# big-endian; an implementation that agrees on the decimal alone has not been
# tested.
#
# The keys here are published in this file. None of them is a key to use.
#
# A `vector offset` record: the material and the declaration go in, the framed
# context and the keyed digest are the intermediate values an implementation
# can check on their own, and the offset comes out. `name-utf8` is what a
# caller passed and `name-nfc-utf8` is what reaches the message, and the two
# differ wherever the name was not already in NFC. The value of `blinded` is
# the word the canonical encoding writes rather than a true or a false, so the
# field name and its value read the same on every record here.
#
# A `vector mapping` record: a digest chosen by hand and an interval go in, and
# the number comes out. They exist because the two ends of the mapping are
# digests no key and no name can be searched for.
#
# Regenerate with `python tools/derivation_vectors.py`. The default suite reads
# this file and recomputes every field from the package without importing that
# tool.
"""


def _header(offsets: int, mappings: int) -> list[str]:
    """The constants a reader needs before the first record.

    Read from the modules rather than written out, so a change to any of them
    moves this file, and the suite compares the two again on every run.
    """
    return [
        f"format {FORMAT}",
        f"derivation-contract {derivation.CONTRACT}",
        f"key-contract {key_module.CONTRACT}",
        f"digest {derivation.DIGEST}",
        f"digest-bytes-read {interval.DIGEST_BYTES}",
        f"byte-order {interval.BYTE_ORDER}",
        f"divisor {interval.DIVISOR}",
        f"default-half-width-multiple {DEFAULT_HALF_WIDTH_MULTIPLE!r}",
        f"minimum-blinding-string-characters {key_module.MINIMUM_CHARACTERS}",
        f"minimum-key-material-bytes {key_module.MINIMUM_BYTES}",
        f"offset-vectors {offsets}",
        f"mapping-vectors {mappings}",
    ]


def _declared(case: Case, field_name: str) -> float:
    """A number a blinded declaration is required to carry.

    Written rather than read straight off the object because the field is
    optional on the type: a never-blinded declaration carries none of them.
    Every vector here is a blinded location parameter, since the derivation
    refuses anything else, so an absence means a case was written wrong and
    this says so instead of writing `None` into a published file.
    """
    value = getattr(case.declaration, field_name)
    if value is None:
        raise SystemExit(
            f"the vector {case.id} declares no {field_name}, and a published "
            f"vector with a field missing is one nobody can reproduce"
        )
    return float(value)


def _offset_record(case: Case) -> list[str]:
    declaration = case.declaration
    material = case.blinding_key.material
    value = derivation.offset(material, declaration)
    half_width = declaration.half_width()
    multiple = declaration.resolved_multiple()
    low = _declared(case, "low")
    high = _declared(case, "high")
    uncertainty = _declared(case, "uncertainty")
    normalised = unicodedata.normalize("NFC", declaration.name)
    return [
        f"vector offset {case.id}",
        f"purpose {case.purpose}",
        f"key-source {case.blinding_key.source.value}",
        f"key-text-utf8 {_text(case.key_text) if case.key_text else '-'}",
        f"key-material {_hex(material)}",
        f"key-fingerprint {case.blinding_key.fingerprint()}",
        f"name-utf8 {_text(declaration.name)}",
        f"name-nfc-utf8 {_text(normalised)}",
        f"kind {declaration.kind.value}",
        f"transform {declaration.transform.value}",
        "blinded blinded" if declaration.blinded else "blinded never-blinded",
        f"low-decimal {low!r}",
        f"low-bits {_bits(low)}",
        f"high-decimal {high!r}",
        f"high-bits {_bits(high)}",
        f"uncertainty-decimal {uncertainty!r}",
        f"uncertainty-bits {_bits(uncertainty)}",
        f"multiple-decimal {multiple!r}",
        f"multiple-bits {_bits(multiple)}",
        f"half-width-decimal {half_width!r}",
        f"half-width-bits {_bits(half_width)}",
        f"context {_hex(derivation.context(declaration))}",
        f"digest {_hex(derivation.digest_for(material, declaration))}",
        f"offset-decimal {value!r}",
        f"offset-bits {_bits(value)}",
    ]


def _mapping_record(case: MappingCase) -> list[str]:
    value = interval.into(case.id, case.digest, case.low, case.high)
    return [
        f"vector mapping {case.id}",
        f"purpose {case.purpose}",
        f"digest {_hex(case.digest)}",
        f"leading-integer {interval.leading_integer(case.id, case.digest)}",
        f"low-decimal {case.low!r}",
        f"low-bits {_bits(case.low)}",
        f"high-decimal {case.high!r}",
        f"high-bits {_bits(case.high)}",
        f"value-decimal {value!r}",
        f"value-bits {_bits(value)}",
    ]


def render() -> str:
    """The whole file, as the text it is written with."""
    offsets = offset_cases()
    mappings = mapping_cases()
    records = [_header(len(offsets), len(mappings))]
    records.extend(_offset_record(case) for case in offsets)
    records.extend(_mapping_record(case) for case in mappings)
    body = "\n\n".join("\n".join(record) for record in records)
    return f"{STATE_LINE}\n{PREAMBLE}\n{body}\n"


def _check_the_cases_still_sit_where_they_are_placed() -> None:
    """Refuse to write a file whose boundary cases have drifted off the boundary.

    Each constant below is chosen against a number in another module, and each
    stops being the case it is named for without anything else failing. A
    vector that is no longer at a boundary passes every check in the suite and
    proves nothing, which is the quietest way coverage is lost.
    """
    encoded = len(BLOCK_NAME.encode("utf-8"))
    if encoded != BLOCK:
        raise SystemExit(
            f"the block-boundary name encodes to {encoded} bytes rather than "
            f"{BLOCK}, so that vector is no longer on the boundary"
        )
    if len(LONG_MATERIAL) != BLOCK + 1:
        raise SystemExit("the long key material is not one byte past a block")
    if len(MINIMUM_STRING) != key_module.MINIMUM_CHARACTERS:
        raise SystemExit(
            f"the minimum-length string is {len(MINIMUM_STRING)} characters "
            f"and the floor is {key_module.MINIMUM_CHARACTERS}"
        )
    if unicodedata.is_normalized("NFC", DECOMPOSED_NAME):
        raise SystemExit(
            "the decomposed name is already in NFC, so that vector no longer "
            "shows the normalisation"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Write the published vectors.")
    parser.add_argument(
        "--check",
        action="store_true",
        help="do not write; exit 1 if the tracked file is not what this produces",
    )
    arguments = parser.parse_args(argv)
    _check_the_cases_still_sit_where_they_are_placed()
    produced = render()
    relative = VECTOR_FILE.relative_to(REPOSITORY_ROOT).as_posix()
    if arguments.check:
        if VECTOR_FILE.read_bytes().decode("utf-8") == produced:
            print(f"{relative} is what this produces.")
            return 0
        print(
            f"{relative} differs from what this produces. A deliberate change "
            f"to what the package derives is a new contract identifier under "
            f"issue #2 and not a regenerated file on its own."
        )
        return 1
    VECTOR_FILE.parent.mkdir(parents=True, exist_ok=True)
    # The newline is fixed rather than left to the platform. The file is
    # declared binary, so a carriage return written here is one every reader
    # gets and one every recorded digest is taken over.
    with VECTOR_FILE.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(produced)
    print(f"Wrote {relative}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
