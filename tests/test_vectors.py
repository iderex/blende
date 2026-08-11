"""The published vectors, read the way an outside implementation reads them.

Issue #43 asks that the default suite check the implementation against the
vector files. This module is that check, and it is written to be the reader
issue #43 exists for rather than a second copy of the writer.

Two rules it keeps, and both of them are what make it evidence.

It does not import `tools/derivation_vectors.py`. A check that regenerated the
file and compared would prove that the tool is a function, which nobody
doubted; what is worth proving is that the package produces what a stranger
reading the file would compute. So every value here is parsed out of the bytes
on disk and recomputed from `blende.contract`.

It rebuilds the inputs from the file rather than from the constants beside it.
The name comes back from `name-utf8` as hexadecimal, the range endpoints come
back from their IEEE-754 bytes, and the key material comes back from
`key-material` or is re-derived from `key-text-utf8`. An implementation in
another language has exactly those bytes and nothing else, and a check that
reached for a Python constant would pass on a file the stranger cannot use.

## The near-misses

A vector file loses its worth quietly. Nothing goes red when a case is deleted,
and nothing goes red when a case stops being the case it is named for - a name
that was exactly one digest block until somebody rewrote the prose in it, or a
blinding string that was the shortest admissible one until the floor moved.

So the coverage issue #43 asks for is asserted as a property of the bytes
rather than as a list of names that exist. The block-boundary vector is checked
to encode to one block, the long-key vector to one byte past it, the minimum
string to the floor the key module declares, and the decomposed name to a form
that is not already NFC. Each of those fails on a file that still parses, still
verifies and no longer covers what it says it covers.
"""

from __future__ import annotations

import hashlib
import struct
import sys
import unicodedata
import unittest
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parent.parent
SOURCE = REPOSITORY / "src"

sys.path.insert(0, str(SOURCE))

from blende.contract import derivation, interval  # noqa: E402
from blende.contract import key as key_module  # noqa: E402
from blende.contract.declaration import (  # noqa: E402
    DEFAULT_HALF_WIDTH_MULTIPLE,
    Declaration,
    Kind,
    Transform,
)

VECTOR_FILE = REPOSITORY / "tests" / "fixtures" / "vectors" / "derivation.txt"

# Issue #11's field, in the position that issue fixes: the first bytes of the
# artefact, ahead of the comments. Written out here rather than assembled from
# parts, because what a reader trusts before parsing anything is the literal.
STATE_LINE = "blende never-blinded blende/derivation-vectors/1 - -"

_DOUBLE = struct.Struct(">d")

# The identifiers of the cases issue #43 names as the coverage it wants, each
# one against the sentence in that issue it comes from. A case removed from the
# file leaves this list naming it and the run goes red.
REQUIRED_OFFSET_VECTORS = (
    "ordinary-location-parameter",
    "name-outside-the-basic-latin-set",
    "name-of-exactly-one-block",
    "minimum-length-blinding-string",
)
REQUIRED_MAPPING_VECTORS = (
    "all-zero-digest-on-the-unit-interval",
    "all-one-digest-on-the-unit-interval",
)


def _records() -> list[tuple[str, str, dict[str, str]]]:
    """Every record in the file, as a kind, an identifier and its fields.

    The parser is four lines for a reason. Issue #43 asks for a file somebody
    can read without installing anything, and a format needing more than this
    to read is not that file.
    """
    text = VECTOR_FILE.read_bytes().decode("utf-8")
    found = []
    for block in text.split("\n\n"):
        lines = [
            line
            for line in block.splitlines()
            if line and not line.startswith("#") and line != STATE_LINE
        ]
        if not lines:
            continue
        fields = {}
        for line in lines:
            name, _, value = line.partition(" ")
            fields[name] = value
        if "vector" not in fields:
            found.append(("header", "header", fields))
            continue
        kind, _, identifier = fields.pop("vector").partition(" ")
        found.append((kind, identifier, fields))
    return found


def _double(bits: str) -> float:
    """A number read back from the exact form, which is the one that binds."""
    return _DOUBLE.unpack(bytes.fromhex(bits))[0]


class VectorFileShapeTest(unittest.TestCase):
    """The file itself: its first line, its bytes, and what it says it holds."""

    def test_the_first_line_is_the_field_that_says_what_the_artefact_is(self):
        first = VECTOR_FILE.read_bytes().split(b"\n", 1)[0]
        self.assertEqual(first.decode("ascii"), STATE_LINE)

    def test_the_bytes_carry_no_carriage_return(self):
        # The file is declared binary so that a checkout cannot add one. This
        # asserts that none was written in the first place, which the
        # declaration does not cover.
        self.assertNotIn(b"\r", VECTOR_FILE.read_bytes())

    def test_the_counts_in_the_header_are_the_records_that_follow(self):
        records = _records()
        header = next(fields for kind, _, fields in records if kind == "header")
        offsets = [one for kind, _, one in records if kind == "offset"]
        mappings = [one for kind, _, one in records if kind == "mapping"]
        self.assertEqual(int(header["offset-vectors"]), len(offsets))
        self.assertEqual(int(header["mapping-vectors"]), len(mappings))

    def test_the_header_carries_the_constants_the_package_derives_under(self):
        header = next(fields for kind, _, fields in _records() if kind == "header")
        self.assertEqual(header["derivation-contract"], derivation.CONTRACT)
        self.assertEqual(header["key-contract"], key_module.CONTRACT)
        self.assertEqual(header["digest"], derivation.DIGEST)
        self.assertEqual(int(header["digest-bytes-read"]), interval.DIGEST_BYTES)
        self.assertEqual(header["byte-order"], interval.BYTE_ORDER)
        self.assertEqual(int(header["divisor"]), interval.DIVISOR)
        self.assertEqual(
            float(header["default-half-width-multiple"]),
            DEFAULT_HALF_WIDTH_MULTIPLE,
        )
        self.assertEqual(
            int(header["minimum-blinding-string-characters"]),
            key_module.MINIMUM_CHARACTERS,
        )
        self.assertEqual(
            int(header["minimum-key-material-bytes"]), key_module.MINIMUM_BYTES
        )

    def test_the_coverage_issue_43_asks_for_is_present(self):
        records = _records()
        offsets = {name for kind, name, _ in records if kind == "offset"}
        mappings = {name for kind, name, _ in records if kind == "mapping"}
        for required in REQUIRED_OFFSET_VECTORS:
            self.assertIn(required, offsets)
        for required in REQUIRED_MAPPING_VECTORS:
            self.assertIn(required, mappings)

    def test_every_identifier_appears_once(self):
        names = [name for kind, name, _ in _records() if kind != "header"]
        self.assertEqual(len(names), len(set(names)))


class OffsetVectorTest(unittest.TestCase):
    """Each offset vector, recomputed from the bytes the file publishes."""

    def _declaration(self, fields: dict[str, str]) -> Declaration:
        return Declaration(
            name=bytes.fromhex(fields["name-utf8"]).decode("utf-8"),
            kind=Kind(fields["kind"]),
            low=_double(fields["low-bits"]),
            high=_double(fields["high-bits"]),
            uncertainty=_double(fields["uncertainty-bits"]),
            # The file publishes the resolved multiple, which is what the
            # canonical bytes carry: a declaration taking the default and one
            # naming it are one statement about the analysis and one digest.
            half_width_multiple=_double(fields["multiple-bits"]),
            transform=Transform(fields["transform"]),
            blinded=fields["blinded"] == "blinded",
        )

    def _material(self, fields: dict[str, str]) -> bytes:
        recorded = bytes.fromhex(fields["key-material"])
        if fields["key-source"] == "text":
            text = bytes.fromhex(fields["key-text-utf8"]).decode("utf-8")
            rebuilt = key_module.from_text(text)
        else:
            rebuilt = key_module.from_bytes(recorded)
        # The published material and the material the published input produces
        # are the same bytes, or one of the two is a value nobody can arrive
        # at from the other.
        self.assertEqual(rebuilt.material, recorded)
        self.assertEqual(rebuilt.fingerprint(), fields["key-fingerprint"])
        return recorded

    def test_every_offset_vector_is_what_the_package_derives(self):
        for kind, name, fields in _records():
            if kind != "offset":
                continue
            with self.subTest(vector=name):
                declaration = self._declaration(fields)
                material = self._material(fields)
                self.assertEqual(
                    derivation.context(declaration).hex(), fields["context"]
                )
                self.assertEqual(
                    derivation.digest_for(material, declaration).hex(),
                    fields["digest"],
                )
                value = derivation.offset(material, declaration)
                self.assertEqual(_DOUBLE.pack(value).hex(), fields["offset-bits"])
                self.assertEqual(repr(value), fields["offset-decimal"])
                self.assertEqual(
                    _DOUBLE.pack(declaration.half_width()).hex(),
                    fields["half-width-bits"],
                )
                self.assertEqual(
                    _DOUBLE.pack(declaration.resolved_multiple()).hex(),
                    fields["multiple-bits"],
                )

    def test_the_two_forms_of_every_number_are_the_same_number(self):
        # The reason the file carries both is that a decimal rendering of a
        # double is ambiguous unless it round-trips. A record whose two forms
        # disagree hands an outside implementation two answers.
        pairs = (
            "low",
            "high",
            "uncertainty",
            "multiple",
            "half-width",
            "offset",
            "value",
        )
        for kind, name, fields in _records():
            if kind == "header":
                continue
            for stem in pairs:
                if f"{stem}-bits" not in fields:
                    continue
                with self.subTest(vector=name, number=stem):
                    self.assertEqual(
                        float(fields[f"{stem}-decimal"]),
                        _double(fields[f"{stem}-bits"]),
                    )

    def test_the_name_the_message_carries_is_the_normalised_one(self):
        for kind, name, fields in _records():
            if kind != "offset":
                continue
            with self.subTest(vector=name):
                given = bytes.fromhex(fields["name-utf8"]).decode("utf-8")
                self.assertEqual(
                    unicodedata.normalize("NFC", given).encode("utf-8").hex(),
                    fields["name-nfc-utf8"],
                )


class MappingVectorTest(unittest.TestCase):
    """Each mapping vector, taken straight on issue #40's mapping."""

    def test_every_mapping_vector_is_what_the_mapping_produces(self):
        for kind, name, fields in _records():
            if kind != "mapping":
                continue
            with self.subTest(vector=name):
                digest = bytes.fromhex(fields["digest"])
                low = _double(fields["low-bits"])
                high = _double(fields["high-bits"])
                self.assertEqual(
                    interval.leading_integer(name, digest),
                    int(fields["leading-integer"]),
                )
                value = interval.into(name, digest, low, high)
                self.assertEqual(_DOUBLE.pack(value).hex(), fields["value-bits"])
                self.assertEqual(repr(value), fields["value-decimal"])

    def test_the_extreme_digests_are_the_width_the_primitive_produces(self):
        width = hashlib.new(derivation.DIGEST).digest_size
        for kind, name, fields in _records():
            if kind != "mapping":
                continue
            with self.subTest(vector=name):
                self.assertEqual(len(bytes.fromhex(fields["digest"])), width)


class CoverageStillCoversTest(unittest.TestCase):
    """The vectors named for a boundary are still on the boundary.

    Every case here is one that goes on parsing and on verifying after it has
    stopped proving anything, which is why each is derived from the bytes
    rather than taken on trust from the identifier.
    """

    def _fields(self, wanted: str) -> dict[str, str]:
        for _, name, fields in _records():
            if name == wanted:
                return fields
        raise AssertionError(f"the file carries no vector named {wanted}")

    def test_the_block_boundary_name_is_one_block(self):
        block = hashlib.new(derivation.DIGEST).block_size
        fields = self._fields("name-of-exactly-one-block")
        self.assertEqual(len(bytes.fromhex(fields["name-nfc-utf8"])), block)

    def test_the_long_key_is_one_byte_past_a_block(self):
        block = hashlib.new(derivation.DIGEST).block_size
        fields = self._fields("key-material-longer-than-one-block")
        self.assertEqual(len(bytes.fromhex(fields["key-material"])), block + 1)

    def test_the_minimum_string_is_the_floor_the_key_module_declares(self):
        fields = self._fields("minimum-length-blinding-string")
        text = bytes.fromhex(fields["key-text-utf8"]).decode("utf-8")
        self.assertEqual(len(text), key_module.MINIMUM_CHARACTERS)

    def test_the_decomposed_name_is_not_already_normalised(self):
        fields = self._fields("name-outside-the-basic-latin-set")
        self.assertNotEqual(fields["name-utf8"], fields["name-nfc-utf8"])

    def test_two_vectors_differ_only_in_the_name(self):
        # The name inside the message is the whole of the domain separation.
        # These two records share a key, a range and an uncertainty, so an
        # implementation that leaves the name out reaches one offset for both.
        first = self._fields("ordinary-location-parameter")
        second = self._fields("second-parameter-under-one-key")
        self.assertEqual(first["key-material"], second["key-material"])
        self.assertEqual(first["half-width-bits"], second["half-width-bits"])
        self.assertNotEqual(first["name-utf8"], second["name-utf8"])
        self.assertNotEqual(first["offset-bits"], second["offset-bits"])

    def test_the_bytes_after_the_ones_the_mapping_reads_do_not_move_it(self):
        read = interval.DIGEST_BYTES
        zero = self._fields("all-zero-digest-on-the-unit-interval")
        mixed = self._fields("digest-differing-outside-the-bytes-read")
        self.assertEqual(zero["digest"][: read * 2], mixed["digest"][: read * 2])
        self.assertNotEqual(zero["digest"], mixed["digest"])
        self.assertEqual(zero["value-bits"], mixed["value-bits"])


if __name__ == "__main__":
    unittest.main()
