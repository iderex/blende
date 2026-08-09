"""The blinding string, how it becomes bytes, and what it may not be.

Issue #42 decides that the key is part of the contract rather than an
implementation detail, because everything derived is a function of it. Two
analysts with what they both call the same blinding string and two different
byte strings behind it get two different offsets and no message anywhere says
so, which is the failure issue #17 exists to prevent.

Two entry points. A string, normalised and encoded by `canonical`, so that two
spellings a human would call identical produce identical bytes. And raw bytes,
for an operator who would rather have no text encoding in the path at all. A
key records which entry point it came from, because the two are different
statements about where the material came from and issue #48's commitment file
is where that reaches a reader.

The two entry points do not derive different values from the same material.
The fingerprint is over the bytes alone, so an operator who types a string and
one who supplies the bytes that string encodes to hold the same key and their
artefacts say so, which is what the fingerprint is for.

## What is refused

An empty string. A string shorter than `MINIMUM_CHARACTERS`, and byte material
shorter than `MINIMUM_BYTES`.

The minimum is a floor on length and it is not a claim about entropy. A
memorable phrase has far less entropy than its length suggests and nothing here
can tell one from a drawn string, which is why `generate` exists and why the
documents say a string chosen by a person is weaker than it looks. What the
floor does refuse is the case that is not arguable: a key short enough that a
search over candidates of that length is cheaper than reading this sentence.
Sixteen characters and sixteen bytes are where it sits, chosen so that
`generate`'s own output clears it by a wide margin and so that a person who
types a passphrase meets it without thinking, and it can be raised later
without invalidating anything, because it constrains an input rather than
appearing in any derived value.

## What is not refused, and cannot be

A key derived from the data. The body of #42 says the package refuses this in
the one case it sees, which is a string handed to it by a function that also
received the dataset. A function that received two arguments has no way to tell
whether the second came from the first: the call carries values and nothing
about their provenance. So nothing here refuses it, the Done-when does not ask
for it, and this paragraph is the whole of the disclosure rather than a
placeholder for a check that is coming.

## The fingerprint

A keyed digest of the material under a fixed published context, so that two
artefacts can be shown to have used one key without the key being in either.

What the keying buys is domain separation and not work for a searcher. The
context is published and fixed, so anybody holding a candidate string computes
the fingerprint and compares, at the speed of the digest. The work of a search
against a fingerprint is exactly the work of enumerating candidate strings,
which is the search the length floor above cannot make infeasible on its own
and the drawn key can. The fingerprint inherits the entropy of the key and adds
none, and it is written here in those words because it is the one derived value
this project puts into published artefacts on purpose.

The construction is keyed by the material with the context as the message. The
other way round would make the fingerprint a function of a public constant
under a public key, which is a constant.
"""

from __future__ import annotations

import hmac
import secrets
import unicodedata
from enum import Enum

from .canonical import canonical_text
from .refusal import Refusal

# The identifier this material and its fingerprint are produced under. A change
# to any of the constants below is a change to it, under issue #2.
CONTRACT = "blende/blinding-key/1"

# Published, fixed and not secret. An outside reader recomputing a fingerprint
# from a candidate needs it, and issue #47's nonce is the opposite case: secret,
# and inside the committed bytes rather than beside them.
FINGERPRINT_CONTEXT = "blende/key-fingerprint/1"

# The digest primitive. Issue #46 fixes one primitive across the derivation,
# the commitment and the chain, and names it in the specification document; this
# line is what it cites or replaces.
DIGEST = "sha256"

MINIMUM_CHARACTERS = 16
MINIMUM_BYTES = 16

# What `generate` draws. Thirty-two bytes from the operating system's random
# source, rendered as text rather than handed back as bytes, because a key an
# operator has to store outside the analysis is a thing they will copy, paste
# and read aloud, and text that survives that goes through the same entry point
# as a key they typed themselves.
GENERATED_BYTES = 32


class Source(Enum):
    """Which entry point the material arrived through."""

    TEXT = "text"
    BYTES = "bytes"


class BlindingKey:
    """Key material, and where it came from.

    The rendering is the reason this is not a dataclass. A generated repr
    prints every field, so an object holding the key would put it into a
    traceback, a debugger line and any log that formats an object, which is
    issue #4's rule that the package never writes the string anywhere. The
    fingerprint is what stands in for it.
    """

    __slots__ = ("_material", "source")

    def __init__(self, material: bytes, source: Source) -> None:
        if len(material) < MINIMUM_BYTES:
            raise Refusal(
                "material-is-too-short",
                CONTRACT,
                f"key material shorter than {MINIMUM_BYTES} bytes is a search "
                f"rather than a secret",
            )
        self._material = bytes(material)
        self.source = source

    @property
    def material(self) -> bytes:
        """The bytes every derivation is a function of."""
        return self._material

    def fingerprint(self) -> str:
        """The value that goes into an artefact in place of the key."""
        return hmac.new(
            self._material, FINGERPRINT_CONTEXT.encode("utf-8"), DIGEST
        ).hexdigest()

    def __repr__(self) -> str:
        return f"<BlindingKey {self.source.value} {self.fingerprint()[:12]}>"

    __str__ = __repr__


def from_text(value: str) -> BlindingKey:
    """A key typed or pasted by an operator."""
    normalised = unicodedata.normalize("NFC", value)
    if len(normalised) < MINIMUM_CHARACTERS:
        raise Refusal(
            "text-is-too-short",
            CONTRACT,
            f"a blinding string shorter than {MINIMUM_CHARACTERS} characters "
            f"is short enough to enumerate, and the offset comes back out of a "
            f"published blinded value",
        )
    return BlindingKey(canonical_text(CONTRACT, value), Source.TEXT)


def from_bytes(value: bytes) -> BlindingKey:
    """A key an operator supplies as bytes, with no text encoding in the path."""
    return BlindingKey(value, Source.BYTES)


def generate() -> BlindingKey:
    """A key drawn from the operating system's random source.

    `secrets` is the standard library's interface to that source. It is not a
    generator this package wrote, deliberately: a random number generator
    written here would be a piece of security-deciding code with no review
    behind it, which is the argument issue #1 makes about dependencies pointed
    at this package's own source.
    """
    return from_text(secrets.token_urlsafe(GENERATED_BYTES))
