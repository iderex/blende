"""The parameter declaration, its refusals, and the digest over a set of them.

Issue #36 decides what a declaration carries, that the kind is a closed set,
that the kind constrains the transform, that a set of declarations serialises
canonically with a digest that is stable across processes, and that a set
disagreeing with the one the commitment names is refused.

Every refusal below is written as a case that trips it. What that proves is
bounded and worth saying: a case asserts that the refusal fires on the input it
was given, and the evidence that it fires for the reason it names is the
pull-request body, where each guard was deleted in a copy of this tree and the
run watched go red.

The digest cases run two interpreters rather than one. The language randomises
its own string hash per process, so a value reaching that hash gives one answer
inside a run and another in the next one, and a single-process comparison
cannot see it. The two subprocesses are given different seeds deliberately, and
one of them is given a fixed seed, because a suite that exports a fixed seed
turns the two-process comparison green for exactly the defect it exists to
find. That residual belongs to the determinism check in issue #30; here it is
answered by making the two processes disagree about the seed rather than by
assuming anything about the environment.
"""

from __future__ import annotations

import math
import os
import subprocess
import sys
import unittest
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parent.parent
SOURCE = REPOSITORY / "src"

sys.path.insert(0, str(SOURCE))

from blende.contract.canonical import (  # noqa: E402
    canonical_double,
    canonical_text,
    frame,
)
from blende.contract.declaration import (  # noqa: E402
    ADMISSIBLE,
    CONTRACT,
    Declaration,
    DeclarationSet,
    Kind,
    Transform,
    require_the_set_the_commitment_names,
)
from blende.contract.refusal import Refusal  # noqa: E402

# One valid declaration of each kind that admits a transform, so a case that
# needs a set has one that is not about the case.
MASS = Declaration(
    name="mass",
    kind=Kind.LOCATION,
    low=100.0,
    high=200.0,
    transform=Transform.OFFSET,
    blinded=True,
)
WIDTH = Declaration(
    name="width",
    kind=Kind.SCALE,
    low=0.5,
    high=5.0,
    transform=Transform.FACTOR,
    blinded=True,
)
EFFICIENCY = Declaration(
    name="efficiency",
    kind=Kind.BOUNDED_FRACTION,
    low=0.0,
    high=1.0,
    transform=Transform.LOGIT_OFFSET,
    blinded=True,
)
PROCESSED = Declaration(
    name="records-processed",
    kind=Kind.COUNT,
    low=None,
    high=None,
    transform=Transform.NONE,
    blinded=False,
    reason="a bookkeeping number every consistency check is run against",
)


def digest_in_a_separate_process(seed):
    """The digest of the same set, computed by an interpreter of its own."""
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


# Built in the child rather than passed in, so the child reaches the same
# module by an import and not by a value this process computed for it.
PROGRAM = """
from blende.contract.declaration import Declaration, DeclarationSet, Kind, Transform

print(
    DeclarationSet(
        (
            Declaration("mass", Kind.LOCATION, 100.0, 200.0, Transform.OFFSET, True),
            Declaration("width", Kind.SCALE, 0.5, 5.0, Transform.FACTOR, True),
        )
    ).digest()
)
"""


class DeclarationFieldsTest(unittest.TestCase):
    def test_a_declaration_carries_the_five_fields_and_the_reason(self):
        self.assertEqual("mass", MASS.name)
        self.assertIs(Kind.LOCATION, MASS.kind)
        self.assertEqual((100.0, 200.0), (MASS.low, MASS.high))
        self.assertIs(Transform.OFFSET, MASS.transform)
        self.assertTrue(MASS.blinded)
        self.assertEqual("", MASS.reason)

    def test_the_kind_set_is_closed_and_the_table_covers_it(self):
        # Both directions. A kind with no row would reach the table and find
        # nothing; a row for a kind outside the set would be a pairing rule
        # nothing can declare.
        self.assertEqual(
            sorted(kind.value for kind in Kind),
            sorted(kind.value for kind, _ in ADMISSIBLE),
        )

    def test_a_count_admits_no_transform_at_all(self):
        admitted = dict(ADMISSIBLE)[Kind.COUNT]
        self.assertEqual((), admitted)


class InadmissiblePairingTest(unittest.TestCase):
    def test_an_offset_on_a_scale_parameter_is_refused(self):
        with self.assertRaises(Refusal) as refused:
            Declaration("width", Kind.SCALE, 0.5, 5.0, Transform.OFFSET, True)
        self.assertEqual("kind-admits-no-such-transform", refused.exception.rule)

    def test_a_factor_on_a_location_parameter_is_refused(self):
        with self.assertRaises(Refusal) as refused:
            Declaration("mass", Kind.LOCATION, 100.0, 200.0, Transform.FACTOR, True)
        self.assertEqual("kind-admits-no-such-transform", refused.exception.rule)

    def test_an_offset_on_a_bounded_fraction_is_refused(self):
        with self.assertRaises(Refusal) as refused:
            Declaration(
                "efficiency", Kind.BOUNDED_FRACTION, 0.0, 1.0, Transform.OFFSET, True
            )
        self.assertEqual("kind-admits-no-such-transform", refused.exception.rule)

    def test_a_blinded_count_is_refused_by_the_kind_rather_than_the_pairing(self):
        # The distinction is the point. Every transform is inadmissible on a
        # count, and a message saying the pairing is wrong would send the
        # reader looking for the right one.
        for transform in (Transform.OFFSET, Transform.FACTOR, Transform.LOGIT_OFFSET):
            with self.assertRaises(Refusal) as refused:
                Declaration("records-processed", Kind.COUNT, 0.0, 1e9, transform, True)
            self.assertEqual("kind-admits-no-transform", refused.exception.rule)

    def test_the_refusal_names_no_value_from_the_declaration(self):
        # Issue #18. The message identifies the parameter by name and says what
        # is wrong; the range is a number the analyst declared and it stays out.
        with self.assertRaises(Refusal) as refused:
            Declaration("width", Kind.SCALE, 0.5, 5.0, Transform.OFFSET, True)
        rendered = str(refused.exception)
        self.assertNotIn("0.5", rendered)
        self.assertNotIn("5.0", rendered)


class NeverBlindedTest(unittest.TestCase):
    def test_a_never_blinded_parameter_carrying_a_transform_is_refused(self):
        with self.assertRaises(Refusal) as refused:
            Declaration(
                "records-processed",
                Kind.COUNT,
                None,
                None,
                Transform.OFFSET,
                False,
                "a bookkeeping number",
            )
        self.assertEqual("never-blinded-carries-no-transform", refused.exception.rule)

    def test_a_never_blinded_parameter_carrying_a_range_is_refused(self):
        # Issue #44. The range sizes a transform, and this parameter has none
        # for it to size. Requiring one made an operator invent two numbers
        # that then entered the canonical bytes, so two operators making the
        # same honest declaration reached different digests.
        with self.assertRaises(Refusal) as refused:
            Declaration(
                "records-processed",
                Kind.COUNT,
                0.0,
                1e9,
                Transform.NONE,
                False,
                "a bookkeeping number",
            )
        self.assertEqual("never-blinded-carries-no-range", refused.exception.rule)

    def test_one_endpoint_on_a_never_blinded_parameter_is_refused_too(self):
        # Both directions, because a rule that reads only `low` passes the
        # half of the case that arrives when somebody deletes one argument.
        for low, high in ((0.0, None), (None, 1e9)):
            with self.assertRaises(Refusal) as refused:
                Declaration(
                    "records-processed",
                    Kind.COUNT,
                    low,
                    high,
                    Transform.NONE,
                    False,
                    "a bookkeeping number",
                )
            self.assertEqual("never-blinded-carries-no-range", refused.exception.rule)

    def test_a_never_blinded_parameter_with_no_reason_is_refused(self):
        with self.assertRaises(Refusal) as refused:
            Declaration(
                "records-processed", Kind.COUNT, None, None, Transform.NONE, False
            )
        self.assertEqual("never-blinded-carries-a-reason", refused.exception.rule)

    def test_whitespace_is_not_a_reason(self):
        with self.assertRaises(Refusal) as refused:
            Declaration(
                "records-processed",
                Kind.COUNT,
                None,
                None,
                Transform.NONE,
                False,
                "   ",
            )
        self.assertEqual("never-blinded-carries-a-reason", refused.exception.rule)

    def test_a_blinded_parameter_carrying_a_reason_is_refused(self):
        with self.assertRaises(Refusal) as refused:
            Declaration(
                "mass", Kind.LOCATION, 100.0, 200.0, Transform.OFFSET, True, "because"
            )
        self.assertEqual(
            "reason-belongs-to-a-never-blinded-parameter", refused.exception.rule
        )

    def test_a_never_blinded_count_is_a_declaration_the_package_accepts(self):
        self.assertFalse(PROCESSED.blinded)
        self.assertIs(Transform.NONE, PROCESSED.transform)


class RangeTest(unittest.TestCase):
    def test_a_blinded_parameter_with_no_range_is_refused(self):
        with self.assertRaises(Refusal) as refused:
            Declaration("mass", Kind.LOCATION, None, None, Transform.OFFSET, True)
        self.assertEqual("blinded-carries-a-range", refused.exception.rule)

    def test_a_blinded_parameter_with_one_endpoint_is_refused(self):
        # Half a range is the case that arrives when a value is read out of a
        # file that had one of the two, and it sizes nothing.
        for low, high in ((100.0, None), (None, 200.0)):
            with self.assertRaises(Refusal) as refused:
                Declaration("mass", Kind.LOCATION, low, high, Transform.OFFSET, True)
            self.assertEqual("blinded-carries-a-range", refused.exception.rule)

    def test_an_absent_range_is_not_a_zero_range_in_the_bytes(self):
        # A never-blinded declaration writes its two endpoint fields empty.
        # The encoding somebody reaches for instead is the double zero, and
        # the two have to be different bytes, otherwise an absent range and a
        # range from zero to zero reach one digest. The length prefix in front
        # of each field is what separates them.
        name = "records-processed"
        zeroed = frame(
            canonical_text(name, name),
            canonical_text(name, Kind.COUNT.value),
            canonical_double(name, 0.0),
            canonical_double(name, 0.0),
            canonical_text(name, Transform.NONE.value),
            canonical_text(name, "never-blinded"),
            PROCESSED.reason.encode("utf-8"),
        )
        self.assertNotEqual(PROCESSED.canonical_bytes(), zeroed)
        # And the sixteen bytes the two endpoints occupy when they are there
        # are the whole of the difference.
        self.assertEqual(len(zeroed) - 16, len(PROCESSED.canonical_bytes()))

    def test_a_range_with_no_width_is_refused(self):
        with self.assertRaises(Refusal) as refused:
            Declaration("mass", Kind.LOCATION, 100.0, 100.0, Transform.OFFSET, True)
        self.assertEqual("range-is-not-ordered", refused.exception.rule)

    def test_a_reversed_range_is_refused(self):
        with self.assertRaises(Refusal) as refused:
            Declaration("mass", Kind.LOCATION, 200.0, 100.0, Transform.OFFSET, True)
        self.assertEqual("range-is-not-ordered", refused.exception.rule)

    def test_an_endpoint_that_is_not_a_number_is_refused(self):
        # It is the ordering rule that catches this one, because every
        # comparison against a value that is not a number is false. Recorded
        # here rather than left to be rediscovered: the encoder's own refusal
        # for it is unreachable through a declaration.
        with self.assertRaises(Refusal) as refused:
            Declaration("mass", Kind.LOCATION, 100.0, math.nan, Transform.OFFSET, True)
        self.assertEqual("range-is-not-ordered", refused.exception.rule)

    def test_an_infinite_endpoint_reaches_the_encoder_and_is_refused(self):
        declared = Declaration(
            "mass", Kind.LOCATION, 100.0, math.inf, Transform.OFFSET, True
        )
        with self.assertRaises(Refusal) as refused:
            declared.canonical_bytes()
        self.assertEqual("number-is-not-finite", refused.exception.rule)


class NameTest(unittest.TestCase):
    def test_an_empty_name_is_refused(self):
        with self.assertRaises(Refusal) as refused:
            Declaration("", Kind.LOCATION, 100.0, 200.0, Transform.OFFSET, True)
        self.assertEqual("text-is-empty", refused.exception.rule)

    def test_two_spellings_of_one_name_are_one_name(self):
        # The same name, composed and decomposed, written as escapes so
        # this file stays ASCII and the two spellings are visibly
        # different in the source instead of two identical-looking lines
        # a reader has to trust. Without the normalisation these are two
        # parameters to the package and one to every reader, and they
        # derive different offsets.
        composed = Declaration(
            "m\u00fc", Kind.LOCATION, 100.0, 200.0, Transform.OFFSET, True
        )
        decomposed = Declaration(
            "mu\u0308", Kind.LOCATION, 100.0, 200.0, Transform.OFFSET, True
        )
        self.assertEqual(composed.canonical_bytes(), decomposed.canonical_bytes())
        with self.assertRaises(Refusal) as refused:
            DeclarationSet((composed, decomposed))
        self.assertEqual(
            "declaration-set-names-a-parameter-twice", refused.exception.rule
        )

    def test_a_repeated_name_is_refused(self):
        with self.assertRaises(Refusal) as refused:
            DeclarationSet((MASS, MASS))
        self.assertEqual(
            "declaration-set-names-a-parameter-twice", refused.exception.rule
        )


class CanonicalBytesTest(unittest.TestCase):
    def test_the_order_the_declarations_were_written_in_does_not_reach_the_digest(self):
        one = DeclarationSet((MASS, WIDTH, EFFICIENCY))
        other = DeclarationSet((EFFICIENCY, MASS, WIDTH))
        self.assertEqual(one.digest(), other.digest())

    def test_the_identifier_is_inside_the_bytes(self):
        self.assertIn(
            CONTRACT.encode("utf-8"), DeclarationSet((MASS,)).canonical_bytes()
        )

    def test_the_reason_is_prose_and_the_name_is_not(self):
        # The two text fields of a declaration are encoded by different rules
        # and the module says so. The name is normalised, so two spellings of
        # it are one parameter, which is the case above. The reason is the
        # operator's own prose and enters the digest as its exact bytes, which
        # is issue #46's rule for prose under a commitment: changing a
        # document's bytes is what a commitment exists to detect, so a
        # normaliser here would let the text be edited without the digest
        # moving.
        #
        # Both spellings are written as escapes so this file stays ASCII and
        # the difference is visible in the source instead of two
        # identical-looking lines a reader has to trust.
        composed = "gemessene Gr\u00f6\u00dfe, extern kalibriert"
        decomposed = "gemessene Gro\u0308\u00dfe, extern kalibriert"
        self.assertNotEqual(composed.encode("utf-8"), decomposed.encode("utf-8"))

        def counted(reason):
            return DeclarationSet(
                (
                    Declaration(
                        name="records-processed",
                        kind=Kind.COUNT,
                        low=None,
                        high=None,
                        transform=Transform.NONE,
                        blinded=False,
                        reason=reason,
                    ),
                )
            ).digest()

        self.assertNotEqual(counted(composed), counted(decomposed))

        # The same pair of spellings in the name field is one digest, so what
        # is above is a difference between the two fields rather than a
        # property of the pair.
        def named(name):
            return DeclarationSet(
                (Declaration(name, Kind.LOCATION, 1.0, 2.0, Transform.OFFSET, True),)
            ).digest()

        self.assertEqual(named("m\u00fc"), named("mu\u0308"))

    def test_the_framing_is_what_makes_the_encoding_injective(self):
        # Two field lists whose plain concatenation is one byte string. The
        # length prefix is the only thing separating them, so this is the case
        # an implementation that leaves it out gets wrong.
        self.assertNotEqual(frame(b"ab", b"c"), frame(b"a", b"bc"))
        # And the prefix is eight bytes, big-endian, rather than whatever the
        # machine's word size happens to be.
        self.assertEqual(b"\x00\x00\x00\x00\x00\x00\x00\x02ab", frame(b"ab"))

    def test_a_changed_range_changes_the_digest(self):
        moved = Declaration("mass", Kind.LOCATION, 100.0, 200.5, Transform.OFFSET, True)
        self.assertNotEqual(
            DeclarationSet((MASS,)).digest(), DeclarationSet((moved,)).digest()
        )

    def test_a_renamed_parameter_changes_the_digest(self):
        renamed = Declaration(
            "mass-hypothesis", Kind.LOCATION, 100.0, 200.0, Transform.OFFSET, True
        )
        self.assertNotEqual(
            DeclarationSet((MASS,)).digest(), DeclarationSet((renamed,)).digest()
        )

    def test_whether_a_parameter_is_blinded_reaches_the_digest(self):
        # The same parameter, blinded and not. A commitment that could not
        # tell the two apart would let a parameter be quietly taken out of the
        # blinding after the plan was fixed.
        #
        # The two forms differ in more than the word now, because a
        # never-blinded declaration carries no range and a blinded one must.
        # So the word is asserted in the bytes as well, otherwise this case
        # would still pass if the word stopped being written at all.
        never = Declaration(
            "mass",
            Kind.LOCATION,
            None,
            None,
            Transform.NONE,
            False,
            "fixed by an external measurement",
        )
        self.assertNotEqual(
            DeclarationSet((MASS,)).digest(), DeclarationSet((never,)).digest()
        )
        self.assertIn(b"never-blinded", never.canonical_bytes())
        self.assertIn(b"blinded", MASS.canonical_bytes())


class DigestAcrossProcessesTest(unittest.TestCase):
    def test_two_interpreters_with_different_seeds_agree(self):
        first = digest_in_a_separate_process("0")
        second = digest_in_a_separate_process("1")
        self.assertEqual(first, second)
        self.assertEqual(64, len(first))

    def test_the_child_agrees_with_this_process(self):
        here = DeclarationSet((MASS, WIDTH)).digest()
        self.assertEqual(here, digest_in_a_separate_process("0"))


class TheSetTheCommitmentNamesTest(unittest.TestCase):
    def test_the_set_that_was_fixed_passes(self):
        declared = DeclarationSet((MASS, WIDTH))
        require_the_set_the_commitment_names(declared, declared.digest())

    def test_a_renamed_parameter_is_refused(self):
        fixed = DeclarationSet((MASS, WIDTH)).digest()
        renamed = DeclarationSet(
            (
                Declaration(
                    "mass-hypothesis",
                    Kind.LOCATION,
                    100.0,
                    200.0,
                    Transform.OFFSET,
                    True,
                ),
                WIDTH,
            )
        )
        with self.assertRaises(Refusal) as refused:
            require_the_set_the_commitment_names(renamed, fixed)
        self.assertEqual(
            "declaration-set-is-not-the-one-the-commitment-names",
            refused.exception.rule,
        )

    def test_a_dropped_parameter_is_refused(self):
        fixed = DeclarationSet((MASS, WIDTH)).digest()
        with self.assertRaises(Refusal) as refused:
            require_the_set_the_commitment_names(DeclarationSet((MASS,)), fixed)
        self.assertEqual(
            "declaration-set-is-not-the-one-the-commitment-names",
            refused.exception.rule,
        )

    def test_the_refusal_carries_no_declaration_of_its_own(self):
        fixed = DeclarationSet((MASS, WIDTH)).digest()
        with self.assertRaises(Refusal) as refused:
            require_the_set_the_commitment_names(DeclarationSet((MASS,)), fixed)
        self.assertNotIn("mass", str(refused.exception))


if __name__ == "__main__":
    unittest.main()
