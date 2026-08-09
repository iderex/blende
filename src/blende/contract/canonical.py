"""How a value becomes bytes, once, for everything that enters a digest.

Issue #2 says every input to a specified function has a canonical encoding, so
there is one byte string for a given input and no room for a locale, an
encoding or a float printing rule to change the answer. This module is that
encoding. It is deliberately small and deliberately boring, because an
implementation in another language has to be able to reproduce it from reading
it.

Text. Normalised to NFC and encoded UTF-8. Without the normalisation a name
typed on one system and copied from another differs in bytes while looking the
same to every reader, which is two analysts with the same declaration and
different digests. NFC rather than NFD because it is what text arrives as from
almost every source, so the normalisation is usually the identity and is never
skipped for that reason. Issue #42 owns the same rule for the blinding string
and for what a key may not be; the rule is written here because the parameter
name in issue #36 reached it first, and #42 cites this module rather than
stating a second answer.

Numbers. A float is written as its IEEE-754 binary64 bytes, big-endian, which
is exact and has no printing rule in it. Two spellings that are not the same
double are not the same bytes, which is the intent: a range whose endpoint
moved in the last bit is a different range. A NaN and an infinity are refused
rather than encoded, because neither is a value a range can be sized against,
and negative zero is written as zero so that the two spellings of it agree.

Framing. Every field is written as its length in eight bytes, big-endian,
followed by its bytes. Concatenation without a length is ambiguous: `ab` then
`c` and `a` then `bc` are the same stream, so two different declaration sets
could reach one digest. The length prefix is what makes the encoding
injective, and it is the part an outside implementation is most likely to leave
out.

What this module is not. It is not a serialisation format anybody reads back.
Nothing here parses. The bytes exist to be hashed, and the readable form of a
declaration set is the declaration set.
"""

from __future__ import annotations

import math
import struct
import unicodedata

from .refusal import Refusal

# Named rather than written into the comparison below, because a bare float in
# a comparison is what the lint gate's PLR2004 refuses and it is right to: the
# data path here is floats and an unnamed one is how a boundary check ends up
# right on one machine and wrong on the next.
ZERO = 0.0

# Eight bytes for a length, big-endian, stated rather than derived from a word
# size. A machine that writes it in four bytes or the other way round produces
# a valid-looking digest that is simply different.
_LENGTH = struct.Struct(">Q")

# One conversion, named. A double is written by the same struct in every
# implementation of the floating point standard.
_DOUBLE = struct.Struct(">d")


def canonical_text(subject: str, value: str) -> bytes:
    """The bytes of a string that enters a digest.

    `subject` names what is being encoded and appears in a refusal. It is not
    part of the encoding.
    """
    normalised = unicodedata.normalize("NFC", value)
    if not normalised:
        raise Refusal(
            "text-is-empty",
            subject,
            "an empty string is not a name a digest can separate one field "
            "from another by",
        )
    return normalised.encode("utf-8")


def canonical_double(subject: str, value: float) -> bytes:
    """The bytes of a floating point number that enters a digest."""
    number = float(value)
    if math.isnan(number):
        raise Refusal(
            "number-is-not-a-number",
            subject,
            "a range endpoint has to be a number the transform can be sized "
            "against, and this one is not",
        )
    if math.isinf(number):
        raise Refusal(
            "number-is-not-finite",
            subject,
            "a range endpoint has to be finite, because the width of the "
            "range is what the transform is drawn from",
        )
    # Negative zero and zero are the same number and different bytes. Writing
    # both as zero keeps the encoding a function of the value.
    if number == ZERO:
        number = ZERO
    return _DOUBLE.pack(number)


def frame(*fields: bytes) -> bytes:
    """Length-prefix each field so the concatenation is unambiguous."""
    return b"".join(_LENGTH.pack(len(field)) + field for field in fields)
