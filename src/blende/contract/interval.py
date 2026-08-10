"""The mapping from digest bytes to a number, specified byte for byte.

Issue #40 decides that turning a digest into a number is specified rather than
left to whatever a language does naturally, because that is the step where two
honest implementations stop agreeing. A keyed digest gives bytes and every
language reads bytes the same way; what it does with them afterwards is where
an instruction set, a compiler flag or a library version gets a vote.

## The mapping

Take the leading `DIGEST_BYTES` bytes of the digest. Read them as an unsigned
integer, big-endian. Divide by `DIVISOR`, which is two raised to `BITS`, as an
exact rational, giving a value in the half-open unit interval. Map that
affinely onto the interval the caller declares, still as an exact rational.
Convert once, at the end, to the nearest representable double.

Eight leading bytes rather than the whole digest. Issue #2 writes this contract
for an analysis in another language, and a large part of precision measurement
runs on C++. Eight bytes big-endian is a native unsigned integer there and in
every other language a collaboration is likely to use, and thirty-two bytes is
a big-integer library plus a reason not to bother. Sixty-four bits is also more
than a double carries, so the granularity of what can be drawn is the final
rounding rather than the byte count; four bytes would put the granularity in
the byte count instead and a reviewer would see it in a histogram.

Two digests that agree in those eight bytes therefore give one number. That is
a collision in sixty-four bits of a digest whose collisions are the thing it is
chosen to make infeasible, and it is stated because it is a consequence of the
byte count rather than something the byte count hides.

Big-endian, stated rather than assumed. A machine that reads the same eight
bytes the other way round produces a valid-looking number that is simply
different, and no artefact downstream carries anything that would say so.

Integers and exact rationals until the last step. Every floating point
operation before the conversion is a place where a fused multiply-add, an
extended-precision register or a library version can move the last bit, and a
last bit that differs is a different number. The arithmetic here has no such
freedom: the byte count is exact, the divisor is exact, and both endpoints are
doubles, which are exactly representable as rationals.

## Where the single conversion sits

"One conversion, at one stated point and no other" has two readings and they do
not produce the same number. Converting the unit value to a double first and
then doing the affine map in floating point is three rounded operations after
the conversion. Doing the whole affine map as an exact rational and converting
at the very end is one. This module takes the second, which is the reading the
issue's own sentence about integer arithmetic requires, and the difference is
not theoretical:

    disagreements: 125585 of 200000

over the digests of the first two hundred thousand integers mapped onto the
same interval by both readings, the first of them 1.9206328293744668 against
1.9206328293744663. The command is in the pull request that landed this.

The exact path also cannot overflow. An interval wide enough that its width is
not a finite double, which a declared range legitimately can be, gives an
infinite width under the first reading and a finite number under this one.

## The upper endpoint

The interval is half-open, and the issue says why: a closed interval makes one
endpoint reachable and the other not, or both, depending on rounding, and the
endpoints are where a reviewer looks for a bias in the derivation.

The arithmetic above is half-open and the conversion is not. The exact value is
always below the upper endpoint, and rounding to the nearest double can land on
it: the all-ones digest on the unit interval gives one minus two to the minus
sixty-four, whose nearest double is exactly one. So the mapping carries one
further rule, stated rather than left to the caller to notice. Where the
converted value is not below the upper endpoint, the number is the greatest
double below that endpoint, which `math.nextafter` names and the floating point
standard defines.

That rule is reachable only through the rounding. It is not a clamp over
arbitrary input, and it fires for a range of digests whose width is set by how
far the endpoint sits from its neighbour.

## What this module is not

It is not the derivation. The derivation is issue #37: what the digest is taken
over, which key it is taken under, and how the interval is sized against the
declared expected uncertainty. This module is the step after the digest and
before the transform, and it holds no contract identifier of its own for that
reason. Every constant here is inside the derivation's identifier, so a change
to the byte count, to the endianness or to the divisor is a change to that
identifier under issue #2.

Nor is it the factor for a scale parameter. That is the same integer path
followed by one exponentiation, and the exponentiation is not required by the
floating point standard to be correctly rounded, so it does not inherit the
reproducibility this module has. Issue #40 records the measurement and issue
#38 owns the transform.
"""

from __future__ import annotations

import math
from fractions import Fraction
from typing import Literal

from .canonical import canonical_double
from .refusal import Refusal

# The leading bytes taken from the digest, and the bit length that follows from
# them. Written as one number and one product rather than as two numbers, so a
# byte count changed here cannot leave a divisor behind that still matches the
# old one.
DIGEST_BYTES = 8
BITS = DIGEST_BYTES * 8
DIVISOR = 2**BITS

# The byte order, named rather than defaulted. `int.from_bytes` has taken a
# default since 3.11, which is this package's floor, so the argument below
# could be left off and the contract would then rest on an interpreter's
# choice rather than on this line.
BYTE_ORDER: Literal["big"] = "big"


def leading_integer(subject: str, digest: bytes) -> int:
    """The unsigned integer the leading bytes of a digest read as.

    `subject` names what is being derived and appears in a refusal. It is not
    part of the mapping.
    """
    if len(digest) < DIGEST_BYTES:
        raise Refusal(
            "digest-is-shorter-than-the-mapping-reads",
            subject,
            f"the mapping reads the leading {DIGEST_BYTES} bytes of a digest, "
            f"and a shorter input would be read to its end and produce a "
            f"number from fewer bits than the contract names",
        )
    return int.from_bytes(digest[:DIGEST_BYTES], BYTE_ORDER)


def _require_an_interval_to_map_into(subject: str, low: float, high: float) -> None:
    """Refuse an interval that has no width to map onto.

    The endpoints are put through the canonical encoding's own refusals rather
    than through a second pair written here, so what this mapping accepts as an
    endpoint and what a declaration can encode as one cannot disagree. The
    bytes are discarded and the refusals are what the calls are for, which is
    the idiom `Declaration.__post_init__` already uses for a name.
    """
    canonical_double(subject, low)
    canonical_double(subject, high)
    if not low < high:
        raise Refusal(
            "interval-is-not-ordered",
            subject,
            "the number is drawn from the width between the endpoints, and an "
            "interval whose lower endpoint is not below its upper one has no "
            "width to draw from",
        )


def into(subject: str, digest: bytes, low: float, high: float) -> float:
    """Map a digest onto the half-open interval between two endpoints."""
    _require_an_interval_to_map_into(subject, low, high)
    unit = Fraction(leading_integer(subject, digest), DIVISOR)
    # Exact throughout. `Fraction` of a double is that double and not an
    # approximation of it, so nothing has been rounded when this line ends.
    exact = Fraction(low) + (Fraction(high) - Fraction(low)) * unit
    # The one conversion. Everything above is a rational and everything below
    # is a comparison against an endpoint the caller supplied.
    value = float(exact)
    if value < high:
        return value
    # `exact` is below the upper endpoint, so this is the rounding and nothing
    # else. Half-open is a property of the mapping rather than of the
    # arithmetic that produced it.
    return math.nextafter(high, low)
