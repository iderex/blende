"""The blinding string: its entry points, its refusals and its fingerprint.

Issue #42 decides that how the key becomes bytes is part of the contract, that
a raw byte entry point exists beside the text one, that an empty or too-short
string is refused, that the generator draws from the operating system's random
source, and that the fingerprint is a keyed digest under a published context.

Every case here is written against the guard it names, and the evidence that
each guard bites for its own reason is in the pull-request body, where each was
deleted in a copy of this tree and the named case watched go red.

Nothing in this module writes a key anywhere. The material used below is
assembled in the case that needs it, and the cases about disclosure assert on
what the package renders rather than on what it holds.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import subprocess
import sys
import unittest
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parent.parent
SOURCE = REPOSITORY / "src"

sys.path.insert(0, str(SOURCE))

from blende.contract.key import (  # noqa: E402
    FINGERPRINT_CONTEXT,
    MINIMUM_BYTES,
    MINIMUM_CHARACTERS,
    Source,
    from_bytes,
    from_text,
    generate,
)
from blende.contract.refusal import Refusal  # noqa: E402

# Long enough to clear the floor and obviously not drawn from anything. A
# phrase a person would type is exactly the case the module says it cannot
# judge, and this file is not the place that claim gets weakened.
PHRASE = "a-long-enough-string-of-text"

# Above the block size of the digest, which is where a keyed construction
# starts hashing its key. Sixty-six characters of ASCII, so the count is the
# same whether it is read as text or as the bytes it encodes to.
LONG_PHRASE = "a-string-of-text-long-enough-that-a-keyed-digest-hashes-it-first-x"

PROGRAM = """
from blende.contract.key import from_text

print(from_text("a-long-enough-string-of-text").fingerprint())
"""


def fingerprint_in_a_separate_process(seed):
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


class EntryPointTest(unittest.TestCase):
    def test_a_text_key_records_where_it_came_from(self):
        self.assertIs(Source.TEXT, from_text(PHRASE).source)

    def test_a_byte_key_records_where_it_came_from(self):
        self.assertIs(Source.BYTES, from_bytes(PHRASE.encode("utf-8")).source)

    def test_the_two_entry_points_agree_on_the_same_material(self):
        # The distinction is a statement about where the material came from
        # and never about what it derives, or two operators holding one key
        # would have artefacts that deny it.
        self.assertEqual(
            from_text(PHRASE).fingerprint(),
            from_bytes(PHRASE.encode("utf-8")).fingerprint(),
        )

    def test_two_spellings_of_one_string_are_one_key(self):
        # Composed and decomposed, written as escapes so this file stays ASCII.
        # Without the normalisation these two derive different offsets while
        # every reader calls them the same string.
        self.assertEqual(
            from_text("na\u00efve-string-of-text").fingerprint(),
            from_text("nai\u0308ve-string-of-text").fingerprint(),
        )


class RefusalTest(unittest.TestCase):
    def test_an_empty_string_is_refused(self):
        with self.assertRaises(Refusal) as refused:
            from_text("")
        self.assertEqual("text-is-too-short", refused.exception.rule)

    def test_a_string_one_character_below_the_floor_is_refused(self):
        with self.assertRaises(Refusal) as refused:
            from_text("a" * (MINIMUM_CHARACTERS - 1))
        self.assertEqual("text-is-too-short", refused.exception.rule)

    def test_a_string_at_the_floor_is_accepted(self):
        # The near miss in both directions, because a floor written with the
        # comparison one out refuses the shortest legal string or admits the
        # longest illegal one and no case with a round number would show it.
        self.assertIsNotNone(from_text("a" * MINIMUM_CHARACTERS))

    def test_byte_material_below_the_floor_is_refused(self):
        with self.assertRaises(Refusal) as refused:
            from_bytes(b"a" * (MINIMUM_BYTES - 1))
        self.assertEqual("material-is-too-short", refused.exception.rule)

    def test_byte_material_at_the_floor_is_accepted(self):
        self.assertIsNotNone(from_bytes(b"a" * MINIMUM_BYTES))

    def test_a_refusal_carries_no_part_of_what_it_refused(self):
        # Issue #18. A validator that refuses a value and prints it has
        # printed the key.
        refused_string = "x" * (MINIMUM_CHARACTERS - 1)
        with self.assertRaises(Refusal) as refused:
            from_text(refused_string)
        self.assertNotIn(refused_string, str(refused.exception))


class GeneratorTest(unittest.TestCase):
    def test_it_draws_something_different_every_time(self):
        self.assertNotEqual(generate().fingerprint(), generate().fingerprint())

    def test_what_it_draws_clears_the_floor_it_is_measured_against(self):
        self.assertGreaterEqual(len(generate().material), MINIMUM_BYTES)

    def test_it_comes_back_through_the_text_entry_point(self):
        # So a drawn key and a typed one are the same kind of thing to
        # everything downstream, rather than a second path nobody tests.
        self.assertIs(Source.TEXT, generate().source)


class FingerprintTest(unittest.TestCase):
    def test_it_is_a_keyed_digest_under_the_published_context(self):
        # What an outside reader recomputes: the context is published and is
        # the key, and the material is the message. Written out so a reader
        # can check the positions rather than trust them, because the
        # positions are what the case below is about.
        expected = hmac.new(
            FINGERPRINT_CONTEXT.encode("utf-8"), PHRASE.encode("utf-8"), "sha256"
        ).hexdigest()
        self.assertEqual(expected, from_text(PHRASE).fingerprint())

    def test_material_longer_than_the_block_size_is_not_its_own_digest(self):
        # The near miss, and it is one line of the module rather than a
        # constructed case. A keyed digest hashes a key longer than its block
        # size before using it, so with the material in the key position this
        # pair carries one fingerprint. Both members are accepted material,
        # both are keys somebody can hold, and their artefacts would say they
        # used the same one.
        material = LONG_PHRASE.encode("utf-8")
        self.assertGreater(len(material), hashlib.sha256().block_size)
        self.assertNotEqual(
            from_bytes(material).fingerprint(),
            from_bytes(hashlib.sha256(material).digest()).fingerprint(),
        )

    def test_it_carries_no_part_of_the_material(self):
        self.assertNotIn(PHRASE, from_text(PHRASE).fingerprint())

    def test_two_processes_with_different_seeds_agree(self):
        self.assertEqual(
            fingerprint_in_a_separate_process("0"),
            fingerprint_in_a_separate_process("1"),
        )

    def test_a_different_key_gives_a_different_fingerprint(self):
        self.assertNotEqual(
            from_text(PHRASE).fingerprint(),
            from_text(PHRASE + "-and-one-word-more").fingerprint(),
        )


class DisclosureTest(unittest.TestCase):
    def test_the_rendering_does_not_carry_the_material(self):
        rendered = repr(from_text(PHRASE))
        self.assertNotIn(PHRASE, rendered)
        self.assertNotIn(PHRASE.encode("utf-8").hex(), rendered)

    def test_the_printed_form_does_not_carry_the_material_either(self):
        self.assertNotIn(PHRASE, str(from_text(PHRASE)))

    def test_the_rendering_says_which_entry_point_and_names_the_fingerprint(self):
        rendered = repr(from_text(PHRASE))
        self.assertIn("text", rendered)
        self.assertIn(from_text(PHRASE).fingerprint()[:12], rendered)


if __name__ == "__main__":
    unittest.main()
