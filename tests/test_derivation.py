"""The offset a location parameter is blinded by.

Issue #37 decides that the offset is a keyed digest over a canonical context,
that it is drawn symmetrically about zero from a half-width the declaration
states, that the sign comes out of the digest rather than being fixed, and that
two parameters differing only in name are blinded by offsets that tell nothing
about each other.

Every refusal below is written as a case that trips it. What that proves is
bounded and worth saying: a case asserts that the refusal fires on the input it
was given, and the evidence that it fires for the reason it names is the
pull-request body, where each guard was deleted in a copy of this tree and the
run watched go red.

The construction is asserted against a digest this file computes from the
published pieces rather than against a number pasted in. A pasted number
records what the code did on the day it was written; a recomputation records
what the contract says, and the two differ exactly when somebody changes the
message and updates the constant beside it. The published vectors are issue #43
and are not these.
"""

from __future__ import annotations

import hmac
import math
import os
import subprocess
import sys
import unittest
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parent.parent
SOURCE = REPOSITORY / "src"

sys.path.insert(0, str(SOURCE))

from blende.contract import key as key_module  # noqa: E402
from blende.contract.canonical import canonical_text, frame  # noqa: E402
from blende.contract.declaration import (  # noqa: E402
    DEFAULT_HALF_WIDTH_MULTIPLE,
    Declaration,
    Kind,
    Transform,
)
from blende.contract.derivation import (  # noqa: E402
    CONTRACT,
    DIGEST,
    context,
    digest_for,
    offset,
)
from blende.contract.refusal import Refusal  # noqa: E402

# Material rather than a string, so the cases below are a function of the
# contract and not of the text entry point's normalisation, which has its own
# suite. Written as bytes of a fixed pattern rather than as a phrase, because a
# phrase in a tracked file reads as a key somebody might use.
MATERIAL = bytes(range(32))
OTHER_MATERIAL = bytes(range(1, 33))

MASS = Declaration(
    name="mass",
    kind=Kind.LOCATION,
    low=100.0,
    high=200.0,
    uncertainty=2.0,
    half_width_multiple=None,
    transform=Transform.OFFSET,
    blinded=True,
)
WIDTH = Declaration(
    name="width",
    kind=Kind.SCALE,
    low=0.5,
    high=5.0,
    uncertainty=0.25,
    half_width_multiple=None,
    transform=Transform.FACTOR,
    blinded=True,
)
PROCESSED = Declaration(
    name="records-processed",
    kind=Kind.COUNT,
    low=None,
    high=None,
    uncertainty=None,
    half_width_multiple=None,
    transform=Transform.NONE,
    blinded=False,
    reason="a bookkeeping number every consistency check is run against",
)

# How many name pairs the correlation case draws over, and the bound it holds.
# Under no relationship the sample correlation of that many pairs has a
# standard deviation of about one over the square root of the count, which is
# 0.031 here, so the bound below sits near five of those. What the case can
# refuse is a derivation in which the two are related; it cannot establish that
# they are independent, and no sample of any size could.
PAIRS = 1024
CORRELATION_BOUND = 0.15


def location(name, uncertainty=2.0, multiple=None):
    """A blinded location parameter differing from the next only in its name."""
    return Declaration(
        name=name,
        kind=Kind.LOCATION,
        low=100.0,
        high=200.0,
        uncertainty=uncertainty,
        half_width_multiple=multiple,
        transform=Transform.OFFSET,
        blinded=True,
    )


def correlation(first, second):
    """The sample Pearson correlation of two equally long sequences."""
    count = len(first)
    mean_first = sum(first) / count
    mean_second = sum(second) / count
    centred_first = [value - mean_first for value in first]
    centred_second = [value - mean_second for value in second]
    covariance = sum(a * b for a, b in zip(centred_first, centred_second))
    spread = math.sqrt(sum(a * a for a in centred_first)) * math.sqrt(
        sum(b * b for b in centred_second)
    )
    return covariance / spread


# Built in the child rather than passed in, so the child reaches the same
# module by an import and not by a value this process computed for it.
PROGRAM = """
from blende.contract.declaration import Declaration, Kind, Transform
from blende.contract.derivation import offset

print(
    repr(
        offset(
            bytes(range(32)),
            Declaration(
                "mass", Kind.LOCATION, 100.0, 200.0, 2.0, None, Transform.OFFSET, True
            ),
        )
    )
)
"""


def offset_in_a_separate_process(seed):
    """The same offset, drawn by an interpreter of its own."""
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


class ContextTest(unittest.TestCase):
    def test_it_carries_the_identifier_the_name_and_the_transform(self):
        bytes_of = context(MASS)
        self.assertEqual(
            frame(
                canonical_text("mass", CONTRACT),
                canonical_text("mass", "mass"),
                canonical_text("mass", Transform.OFFSET.value),
            ),
            bytes_of,
        )

    def test_the_name_is_inside_it(self):
        # The whole of the domain separation. Take the name out and every
        # parameter in an analysis shares one offset, which is a one-line
        # mistake no case over a single parameter can see.
        self.assertNotEqual(context(location("mass")), context(location("mass-fit")))

    def test_the_fields_are_framed_rather_than_concatenated(self):
        # A concatenation with no length in front of each field is ambiguous:
        # two different field lists reach one byte string and therefore one
        # offset. The length prefix is the only thing separating them, and it
        # is what an implementation reading this contract is most likely to
        # leave out.
        plain = (
            canonical_text("mass", CONTRACT)
            + canonical_text("mass", "mass")
            + canonical_text("mass", Transform.OFFSET.value)
        )
        self.assertNotEqual(plain, context(MASS))

    def test_two_spellings_of_one_name_are_one_context(self):
        # The normalisation is the canonical encoding's, and this case is here
        # because it is the derivation that would otherwise give two analysts
        # holding one declaration two different offsets. Both spellings are
        # written as escapes so this file stays ASCII and the difference is
        # visible in the source rather than in two identical-looking lines.
        self.assertEqual(context(location("m\u00fc")), context(location("mu\u0308")))


class ConstructionTest(unittest.TestCase):
    def test_the_digest_is_keyed_by_the_material_over_the_context(self):
        # Recomputed from the published pieces rather than pasted. The
        # direction is load-bearing: the blinding string is the key and the
        # context is the message, which is what makes the value move with the
        # key rather than with a constant.
        self.assertEqual(
            hmac.new(MATERIAL, context(MASS), DIGEST).digest(),
            digest_for(MATERIAL, MASS),
        )

    def test_a_different_key_gives_a_different_offset(self):
        self.assertNotEqual(offset(MATERIAL, MASS), offset(OTHER_MATERIAL, MASS))

    def test_the_offset_is_not_redrawn(self):
        # The constant is a function of the key and the declaration, so asking
        # twice is asking the same question. A derivation that drew from a
        # random source would pass every case above and fail this one.
        self.assertEqual(offset(MATERIAL, MASS), offset(MATERIAL, MASS))

    def test_a_key_object_hands_over_the_material_this_takes(self):
        # The derivation takes bytes so that it is a function of the contract
        # alone. This is the one case that binds it to the key module, so a
        # rename on either side is caught here rather than at a call site.
        held = key_module.from_bytes(MATERIAL)
        self.assertEqual(offset(MATERIAL, MASS), offset(held.material, MASS))


class IntervalTest(unittest.TestCase):
    def test_the_half_width_is_the_declared_one(self):
        # Five times the declared expected uncertainty, which is entry 8 of
        # issue #19. The bound is asserted over many names rather than one,
        # because a single draw says nothing about where the interval ends.
        half_width = DEFAULT_HALF_WIDTH_MULTIPLE * 2.0
        for index in range(PAIRS):
            drawn = offset(MATERIAL, location(f"parameter-{index}"))
            self.assertGreaterEqual(drawn, -half_width)
            self.assertLess(drawn, half_width)

    def test_an_override_moves_the_interval(self):
        narrow = location("mass", multiple=1.0)
        for index in range(PAIRS):
            drawn = offset(MATERIAL, location(f"parameter-{index}", multiple=1.0))
            self.assertGreaterEqual(drawn, -2.0)
            self.assertLess(drawn, 2.0)
        self.assertNotEqual(offset(MATERIAL, MASS), offset(MATERIAL, narrow))

    def test_the_sign_is_drawn_rather_than_fixed(self):
        # An offset that is always positive halves the search and tells the
        # analyst which direction the truth lies in. Both signs have to occur,
        # and over this many names a one-sided derivation cannot hide.
        drawn = [offset(MATERIAL, location(f"parameter-{i}")) for i in range(PAIRS)]
        self.assertTrue(any(value < 0.0 for value in drawn))
        self.assertTrue(any(value > 0.0 for value in drawn))

    def test_the_draws_are_spread_across_the_interval(self):
        # A mapping that landed every name in one half would pass the case
        # above on a single stray draw. The mean of a uniform draw over a
        # symmetric interval is zero, and the tolerance is the standard error
        # of the mean at this count, taken generously.
        half_width = DEFAULT_HALF_WIDTH_MULTIPLE * 2.0
        drawn = [offset(MATERIAL, location(f"parameter-{i}")) for i in range(PAIRS)]
        standard_error = half_width / math.sqrt(3.0 * PAIRS)
        self.assertLess(abs(sum(drawn) / PAIRS), 4.0 * standard_error)


class DomainSeparationTest(unittest.TestCase):
    def test_two_names_differing_by_one_character_give_different_offsets(self):
        self.assertNotEqual(
            offset(MATERIAL, location("mass")),
            offset(MATERIAL, location("masss")),
        )

    def test_two_parameters_differing_only_in_name_are_uncorrelated(self):
        # The pairs differ in one character and in nothing else: same kind,
        # same range, same uncertainty, same transform. A derivation that
        # dropped the name from the context correlates at one; a derivation
        # that mixed the name in weakly correlates measurably. What this case
        # refuses is a relationship between the two, and it cannot establish
        # that there is none.
        first = [offset(MATERIAL, location(f"parameter-{i}")) for i in range(PAIRS)]
        second = [offset(MATERIAL, location(f"parameter-{i}x")) for i in range(PAIRS)]
        self.assertNotEqual(first, second)
        self.assertLess(abs(correlation(first, second)), CORRELATION_BOUND)

    def test_the_transform_kind_separates_two_draws_over_one_name(self):
        # The kind is in the context, so the offset a location parameter draws
        # and the value the factor in issue #38 will draw for the same name
        # cannot land on one digest.
        as_offset = context(location("mass"))
        as_factor = frame(
            canonical_text("mass", CONTRACT),
            canonical_text("mass", "mass"),
            canonical_text("mass", Transform.FACTOR.value),
        )
        self.assertNotEqual(as_offset, as_factor)


class RefusalTest(unittest.TestCase):
    def test_a_never_blinded_parameter_draws_no_offset(self):
        with self.assertRaises(Refusal) as refused:
            offset(MATERIAL, PROCESSED)
        self.assertEqual(
            "never-blinded-parameter-draws-no-offset", refused.exception.rule
        )

    def test_a_transform_this_module_does_not_own_is_refused(self):
        with self.assertRaises(Refusal) as refused:
            offset(MATERIAL, WIDTH)
        self.assertEqual("transform-is-not-the-offset", refused.exception.rule)

    def test_the_refusal_carries_no_value_from_the_declaration(self):
        # Issue #18. The message names the parameter and what is wrong, and the
        # declared numbers stay out of it.
        with self.assertRaises(Refusal) as refused:
            offset(MATERIAL, WIDTH)
        rendered = str(refused.exception)
        self.assertNotIn("0.5", rendered)
        self.assertNotIn("0.25", rendered)


class AcrossProcessesTest(unittest.TestCase):
    def test_two_interpreters_with_different_seeds_agree(self):
        # The language randomises its own string hash per process, so a value
        # reaching that hash gives one answer inside a run and another in the
        # next. The two children are given different seeds deliberately.
        first = offset_in_a_separate_process("0")
        second = offset_in_a_separate_process("1")
        self.assertEqual(first, second)

    def test_the_child_agrees_with_this_process(self):
        self.assertEqual(
            repr(offset(MATERIAL, MASS)), offset_in_a_separate_process("0")
        )


if __name__ == "__main__":
    unittest.main()
