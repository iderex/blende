"""The mapping from digest bytes to a number.

Issue #40 decides the byte count, the endianness, the divisor and the single
conversion. Every case here is written against one of those four or against a
refusal, and the evidence that each guard bites for its own reason is in the
pull-request body, where each was deleted in a copy of this tree and the named
case watched go red.

The digests below are written out rather than derived, so a reader can check
the expected number by hand instead of trusting a second computation in this
file. The published vectors are issue #43 and are not these.
"""

from __future__ import annotations

import os
import subprocess
import sys
import unittest
from fractions import Fraction
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parent.parent
SOURCE = REPOSITORY / "src"

sys.path.insert(0, str(SOURCE))

from blende.contract.interval import (  # noqa: E402
    BITS,
    DIGEST_BYTES,
    DIVISOR,
    into,
    leading_integer,
)
from blende.contract.refusal import Refusal  # noqa: E402

SUBJECT = "a_parameter_name"

# A digest whose leading eight bytes are 0x8000000000000000, which is half of
# the divisor, so the unit value is exactly one half and the number on the unit
# interval is exactly one half however the arithmetic is arranged.
HALFWAY = bytes([0x80]) + bytes(31)

# The two extremes issue #40 names for the vector file.
ALL_ZERO = bytes(32)
ALL_ONES = bytes([0xFF]) * 32

# Eight bytes that are not a palindrome, so reading them the other way round
# gives a different number rather than the same one.
COUNTING_UP = bytes(range(1, 9)) + bytes(24)

# A digest on which the two readings of "one conversion" disagree. Found by
# walking the single repeated byte from zero: this is the first one, and most
# digests disagree, so it is an ordinary case rather than a rare one.
REPEATED_BYTE = bytes([0x0E]) * 32

PROGRAM = """
from blende.contract.interval import into

print(repr(into("a_parameter_name", bytes(range(1, 33)), -3.7, 11.3)))
"""


def number_in_a_separate_process(seed):
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(SOURCE)
    environment["PYTHONHASHSEED"] = seed
    finished = subprocess.run(
        [sys.executable, "-c", PROGRAM],
        capture_output=True,
        text=True,
        check=True,
        env=environment,
    )
    return finished.stdout.strip()


class LeadingIntegerTest(unittest.TestCase):
    def test_it_reads_the_leading_bytes_big_endian(self):
        # Read the other way round this is 0x0807060504030201, which is a
        # perfectly good number and the wrong one, and no artefact downstream
        # carries anything that would say so.
        self.assertEqual(0x0102030405060708, leading_integer(SUBJECT, COUNTING_UP))

    def test_it_reads_no_further_than_the_byte_count(self):
        # Stated as a case because it is a consequence of the byte count: two
        # digests agreeing in their leading eight bytes give one number.
        first = bytes(range(1, 9)) + bytes([0x00]) * 24
        second = bytes(range(1, 9)) + bytes([0xFF]) * 24
        self.assertEqual(
            leading_integer(SUBJECT, first), leading_integer(SUBJECT, second)
        )

    def test_the_extremes_are_the_ends_of_the_divisor(self):
        self.assertEqual(0, leading_integer(SUBJECT, ALL_ZERO))
        self.assertEqual(DIVISOR - 1, leading_integer(SUBJECT, ALL_ONES))

    def test_a_digest_at_the_byte_count_is_read(self):
        # The near miss in the admitting direction, so a comparison written one
        # out would refuse the shortest legal digest and this would see it.
        self.assertEqual(0, leading_integer(SUBJECT, bytes(DIGEST_BYTES)))

    def test_a_digest_one_byte_short_is_refused(self):
        with self.assertRaises(Refusal) as refused:
            leading_integer(SUBJECT, bytes(DIGEST_BYTES - 1))
        self.assertEqual(
            "digest-is-shorter-than-the-mapping-reads", refused.exception.rule
        )

    def test_the_divisor_is_two_to_the_bit_length(self):
        self.assertEqual(2**BITS, DIVISOR)
        self.assertEqual(DIGEST_BYTES * 8, BITS)


class MappingTest(unittest.TestCase):
    def test_a_digest_of_zero_bytes_lands_on_the_lower_endpoint(self):
        # The interval is closed at the bottom, so this endpoint is reachable
        # and is where a reviewer looks first.
        self.assertEqual(-3.7, into(SUBJECT, ALL_ZERO, -3.7, 11.3))

    def test_the_halfway_digest_lands_halfway(self):
        # Checkable by hand: 0x8000000000000000 over the divisor is one half,
        # and one half of the way from zero to one is one half.
        self.assertEqual(0.5, into(SUBJECT, HALFWAY, 0.0, 1.0))

    def test_a_digest_of_one_bytes_stays_below_the_upper_endpoint(self):
        # The near miss, and it is the rounding rather than a constructed case.
        # The exact value here is one minus two to the minus sixty-four, whose
        # nearest double is exactly one, so without the endpoint rule this
        # mapping returns a number outside the interval it promises.
        self.assertLess(into(SUBJECT, ALL_ONES, 0.0, 1.0), 1.0)

    def test_it_stays_inside_the_interval_for_every_digest_it_is_given(self):
        low, high = -3.7, 11.3
        for step in range(0, DIVISOR, DIVISOR // 512):
            digest = step.to_bytes(DIGEST_BYTES, "big") + bytes(24)
            value = into(SUBJECT, digest, low, high)
            self.assertGreaterEqual(value, low)
            self.assertLess(value, high)

    def test_the_conversion_happens_once_and_at_the_end(self):
        # The other reading of "one conversion" is to convert the unit value
        # first and do the affine map in floating point, which is three rounded
        # operations after it. The two readings disagree here, and the module
        # doc records how often over a larger set.
        digest = REPEATED_BYTE
        unit_as_a_double = leading_integer(SUBJECT, digest) / DIVISOR
        low, high = -3.7, 11.3
        self.assertNotEqual(
            low + (high - low) * unit_as_a_double, into(SUBJECT, digest, low, high)
        )

    def test_it_is_the_nearest_double_to_the_exact_rational(self):
        # What the module promises, written as the rational rather than as the
        # code that produces it.
        low, high = -3.7, 11.3
        unit = Fraction(leading_integer(SUBJECT, REPEATED_BYTE), DIVISOR)
        exact = Fraction(low) + (Fraction(high) - Fraction(low)) * unit
        self.assertEqual(float(exact), into(SUBJECT, REPEATED_BYTE, low, high))

    def test_an_interval_too_wide_to_subtract_in_floating_point_still_maps(self):
        # The width of this interval is not a finite double, so a reading that
        # subtracts the endpoints first works from an infinity. A declared
        # range is allowed to be this wide.
        #
        # The expected number is hand-checkable rather than recomputed: the
        # halfway digest is one half of the way from one endpoint to the other,
        # and half way between these two is zero. An assertion that the value
        # merely lands inside the interval would pass on the infinity as well,
        # because the endpoint rule below it catches whatever comes out.
        low, high = -1.5e308, 1.5e308
        self.assertEqual(float("inf"), high - low)
        self.assertEqual(0.0, into(SUBJECT, HALFWAY, low, high))

    def test_two_processes_with_different_seeds_agree(self):
        # Issue #17. The interpreter randomises its own string hash per
        # process, so a derivation that reaches it gives one answer within a
        # run and another in the next, and a single-process case cannot see it.
        # The two children are given different seeds deliberately: a comparison
        # where both are fixed is green for exactly the defect it is for.
        self.assertEqual(
            number_in_a_separate_process("0"), number_in_a_separate_process("1")
        )


class IntervalRefusalTest(unittest.TestCase):
    def test_an_interval_with_no_width_is_refused(self):
        with self.assertRaises(Refusal) as refused:
            into(SUBJECT, HALFWAY, 1.0, 1.0)
        self.assertEqual("interval-is-not-ordered", refused.exception.rule)

    def test_an_interval_the_wrong_way_round_is_refused(self):
        with self.assertRaises(Refusal) as refused:
            into(SUBJECT, HALFWAY, 11.3, -3.7)
        self.assertEqual("interval-is-not-ordered", refused.exception.rule)

    def test_a_lower_endpoint_that_is_not_a_number_is_refused(self):
        # Through the canonical encoding's own refusal rather than a second one
        # written beside it, so an endpoint this mapping accepts and an
        # endpoint a declaration can encode cannot come apart.
        with self.assertRaises(Refusal) as refused:
            into(SUBJECT, HALFWAY, float("nan"), 1.0)
        self.assertEqual("number-is-not-a-number", refused.exception.rule)

    def test_an_upper_endpoint_that_is_not_finite_is_refused(self):
        with self.assertRaises(Refusal) as refused:
            into(SUBJECT, HALFWAY, 0.0, float("inf"))
        self.assertEqual("number-is-not-finite", refused.exception.rule)

    def test_a_refusal_carries_no_part_of_what_it_refused(self):
        # Issue #18. The endpoints of an interval are the declared range, and a
        # refusal that printed them would print a statement about where the
        # true value was expected to lie.
        with self.assertRaises(Refusal) as refused:
            into(SUBJECT, HALFWAY, 11.3, -3.7)
        rendered = str(refused.exception)
        self.assertNotIn("11.3", rendered)
        self.assertNotIn("-3.7", rendered)


if __name__ == "__main__":
    unittest.main()
