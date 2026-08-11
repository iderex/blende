"""The bound on writing a blinded value and reading it back.

Issue #41 asks for a round-trip test that covers the declared range including
its endpoints and the values near zero where the relative loss is worst. This
module is that test, and it asserts the bound rather than exactness, which is
the whole of what the issue decides.

The sweep is deterministic. Generated inputs with a printed seed are issue #93
and belong in the slow opt-in suite; what is wanted here is a run whose failure
names the same value on every machine.

Two things are asserted rather than one. That no value in the declared range
moves further than the bound, which is the promise. And that at least one value
moves exactly the bound, which is what stops the promise being met by a number
so generous nobody could break it: a bound of one over the ulp of the largest
double would pass the first assertion for every declaration ever written.
"""

from __future__ import annotations

import math
import sys
import unittest
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parent.parent
SOURCE = REPOSITORY / "src"

sys.path.insert(0, str(SOURCE))

from blende.contract import round_trip  # noqa: E402
from blende.contract.canonical import ZERO  # noqa: E402
from blende.contract.declaration import Declaration, Kind, Transform  # noqa: E402
from blende.contract.derivation import offset  # noqa: E402
from blende.contract.refusal import Refusal  # noqa: E402

# Bytes of a fixed pattern rather than a phrase, for the reason
# `tests/test_derivation.py` gives: a phrase in a tracked file reads as a key
# somebody might use.
MATERIAL = bytes(range(32))

# How many points the sweep takes across a declared range, and across the
# interval an offset is drawn from, in addition to the endpoints and their
# neighbours.
POINTS_ACROSS_A_RANGE = 500
POINTS_ACROSS_AN_INTERVAL = 12

# The step the sweep walks the unit interval by, taken modulo one. An even
# spacing was the first thing written here and it is the wrong instrument: a
# range like 100 to 200 divided into four hundred parts lands on values whose
# binary expansions are short, the arithmetic on them is exact, and the sweep
# reported no loss at all on the very declaration this bound is tightest on.
# An irrational step lands on generic values instead, and it is deterministic,
# which a seeded generator is only by agreement. Seeded generation is issue #93
# and belongs in the opt-in suite.
IRRATIONAL_STEP = 0.6180339887498949

# What the largest observed loss is, as a fraction of the bound. One means the
# bound is attained rather than approached.
BOUND_IS_ATTAINED = 1.0


def _location(
    name: str,
    low: float,
    high: float,
    uncertainty: float,
    multiple: float | None = None,
) -> Declaration:
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


# Each one is a regime rather than an example. The last is the case issue #41
# asks to be refused and that nothing here refuses: a value known far more
# precisely than its own magnitude, where the round trip costs more than the
# measurement resolves. It is swept like the rest, because the bound has to be
# right about it before anything can decide what to do with it.
DECLARATIONS = (
    _location("mass", 100.0, 200.0, 2.0),
    _location("time-offset", -5.0, 5.0, 0.25),
    _location("energy", 0.0, 1000.0, 12.5),
    _location("small-shift", -1e-8, 1e-8, 1e-9),
    _location("distant-value", 1e10, 1.0000001e10, 1e-7),
)


def _unit_fractions(count: int) -> list[float]:
    """Points in the unit interval, spread by an irrational step."""
    return [((step + 1) * IRRATIONAL_STEP) % 1.0 for step in range(count)]


def _values_across(declaration: Declaration) -> list[float]:
    """The range at many points, at both endpoints, and around zero.

    The neighbours of the endpoints are in because an endpoint is where a
    reader of this test would suspect an off-by-one, and zero is in because
    the relative loss is worst there and a range that straddles it would
    otherwise be swept without ever landing on it.
    """
    low = declaration.low
    high = declaration.high
    if low is None or high is None:
        raise AssertionError("a swept declaration carries both endpoints")
    width = high - low
    values = [low, high, math.nextafter(low, high), math.nextafter(high, low)]
    values.extend(
        low + width * fraction for fraction in _unit_fractions(POINTS_ACROSS_A_RANGE)
    )
    if low < ZERO < high:
        values.extend([ZERO, math.nextafter(ZERO, high), math.nextafter(ZERO, low)])
    return [value for value in values if low <= value <= high]


def _offsets(declaration: Declaration) -> list[float]:
    """The drawn offset, and the interval it was drawn from, swept.

    The drawn offset is one number and the bound has to hold for every number
    the interval admits, so the interval is swept as well. A test that used
    only the drawn offset would pass on a bound that happened to cover the
    offset this key gives and no other.
    """
    half = declaration.half_width()
    swept = [
        offset(MATERIAL, declaration),
        half,
        -half,
        math.nextafter(half, ZERO),
    ]
    swept.extend(
        half * (fraction + fraction - 1.0)
        for fraction in _unit_fractions(POINTS_ACROSS_AN_INTERVAL)
    )
    return swept


class BoundIsDerivedFromTheDeclarationTest(unittest.TestCase):
    """The first clause: the bound comes from the declared interval."""

    def test_two_declarations_with_one_interval_have_one_bound(self):
        # Nothing but the range and the half-width may reach the bound. The
        # name changes the offset a key draws and must not change the promise.
        first = _location("mass", 100.0, 200.0, 2.0)
        second = _location("lifetime", 100.0, 200.0, 2.0)
        self.assertEqual(round_trip.bound(first), round_trip.bound(second))
        self.assertNotEqual(offset(MATERIAL, first), offset(MATERIAL, second))

    def test_a_wider_offset_costs_more_precision(self):
        # The sentence issue #41 opens with: the loss is at the level of the
        # offset rather than of the value, so a larger multiple costs more.
        narrow = _location("mass", 100.0, 200.0, 2.0, multiple=1.0)
        wide = _location("mass", 100.0, 200.0, 2.0, multiple=1e6)
        self.assertLess(round_trip.bound(narrow), round_trip.bound(wide))

    def test_the_magnitude_is_the_endpoint_and_the_half_width_together(self):
        declaration = _location("mass", 100.0, 200.0, 2.0)
        self.assertEqual(
            round_trip.blinded_magnitude(declaration),
            abs(declaration.high) + declaration.half_width(),
        )

    def test_the_larger_endpoint_in_magnitude_is_the_one_that_counts(self):
        # A range far below zero is the same distance from zero as its mirror,
        # and a bound taken on the upper endpoint alone would be too small.
        below = _location("mass", -200.0, -100.0, 2.0)
        above = _location("mass", 100.0, 200.0, 2.0)
        self.assertEqual(round_trip.bound(below), round_trip.bound(above))


class BoundHoldsAcrossTheRangeTest(unittest.TestCase):
    """The fifth clause: the sweep, its endpoints, and the values near zero."""

    def test_no_value_in_a_declared_range_moves_further_than_the_bound(self):
        for declaration in DECLARATIONS:
            limit = round_trip.bound(declaration)
            with self.subTest(parameter=declaration.name):
                for value in _values_across(declaration):
                    for shift in _offsets(declaration):
                        recovered = (value + shift) - shift
                        self.assertLessEqual(abs(recovered - value), limit)

    def test_the_bound_is_reached_rather_than_merely_respected(self):
        # A bound nothing comes near is a bound that proves nothing about the
        # arithmetic: one over the ulp of the largest double would pass the
        # assertion above for every declaration anybody will ever write. The
        # largest loss across the regimes above is the bound itself, on `mass`,
        # where the range and the half-width straddle a binade boundary so both
        # roundings are taken at the wider ulp.
        worst = ZERO
        for declaration in DECLARATIONS:
            limit = round_trip.bound(declaration)
            for value in _values_across(declaration):
                for shift in _offsets(declaration):
                    recovered = (value + shift) - shift
                    worst = max(worst, abs(recovered - value) / limit)
        self.assertEqual(worst, BOUND_IS_ATTAINED)

    def test_a_value_at_zero_comes_back_exactly(self):
        # Worth asserting rather than assuming. Zero plus an offset minus the
        # same offset is exact, so the value the relative loss is worst at is
        # the one value that loses nothing.
        declaration = _location("time-offset", -5.0, 5.0, 0.25)
        shift = offset(MATERIAL, declaration)
        self.assertEqual((ZERO + shift) - shift, ZERO)


class WhatIsNotRefusedTest(unittest.TestCase):
    """The clause of issue #41 this does not carry, asserted rather than claimed.

    The issue asks for a declaration whose bound is not negligible against the
    declared uncertainty to be refused. What counts as negligible is a number,
    nothing on the board fixes it, and one invented here would be a number two
    formats later disagree about. So the state is written as a passing test
    rather than as a sentence: the bound can exceed the declared uncertainty
    and the declaration is built and measured all the same.
    """

    def test_a_bound_can_exceed_the_uncertainty_it_is_measured_against(self):
        declaration = _location("distant-value", 1e10, 1.0000001e10, 1e-7)
        uncertainty = declaration.uncertainty
        if uncertainty is None:
            raise AssertionError("a blinded declaration carries an uncertainty")
        self.assertGreater(round_trip.bound(declaration), uncertainty)


class RefusalsTest(unittest.TestCase):
    """What has no bound, and is refused rather than given one."""

    def test_a_never_blinded_parameter_has_no_round_trip(self):
        declaration = Declaration(
            name="records-processed",
            kind=Kind.COUNT,
            low=None,
            high=None,
            uncertainty=None,
            half_width_multiple=None,
            transform=Transform.NONE,
            blinded=False,
            reason="a count is a bookkeeping number and blinding it breaks "
            "every consistency check an analyst runs",
        )
        with self.assertRaises(Refusal) as refused:
            round_trip.bound(declaration)
        self.assertEqual(refused.exception.rule, "never-blinded-has-no-round-trip")

    def test_a_blinded_value_that_could_not_be_written_is_refused(self):
        # Both fields are finite doubles and the half-width is their product,
        # so the magnitude overflows while every declared number is legal.
        declaration = _location("overflowing", 1e308, 1.5e308, 1e300, multiple=1e300)
        with self.assertRaises(Refusal) as refused:
            round_trip.bound(declaration)
        self.assertEqual(refused.exception.rule, "blinded-value-is-not-representable")

    def test_the_refusal_carries_no_value(self):
        # Issue #18's rule. The subject is the parameter name and the detail
        # is a sentence, and neither is a place a number can arrive.
        declaration = _location("overflowing", 1e308, 1.5e308, 1e300, multiple=1e300)
        with self.assertRaises(Refusal) as refused:
            round_trip.bound(declaration)
        self.assertEqual(refused.exception.subject, "overflowing")
        self.assertNotIn("1e+308", str(refused.exception))


if __name__ == "__main__":
    unittest.main()
