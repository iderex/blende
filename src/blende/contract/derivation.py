"""The offset for a location parameter, and the interval it is drawn from.

Issue #37 decides the common case: a parameter whose value is a position on a
scale gets a constant added to it, the constant is a function of the blinding
string and the parameter's own declaration, and it is never redrawn. This
module is that function.

## The construction

A keyed digest, with the key material as the key and a canonical context as the
message. The context carries the identifier below, the parameter name and the
transform kind, each length-prefixed by `canonical.frame`.

Keyed rather than a plain digest over a concatenation. A plain digest over
concatenated fields admits length extension, and a concatenation with no length
in front of it is ambiguous in the other direction: two different field lists
reach one byte string and therefore one offset. The framing answers the second
and the keying answers the first, and both are cheap enough that neither is
worth arguing about at the moment somebody is reading a blinded plot.

The name is inside the message rather than beside it, and that is the whole of
the domain separation. An analyst who learns one offset learns nothing about
the next, because the next is a digest under the same key over different bytes.
Take the name out and every parameter in an analysis shares one offset, which
is a one-line mistake that no test of a single parameter can see.

The transform kind is in the context as well, so the offset a location
parameter draws and the factor issue #38 will draw for a scale parameter cannot
land on one value even where a plan names the same parameter under both.

## The interval

Symmetric about zero, half-width `Declaration.half_width`, which is the
declared expected uncertainty multiplied by the declaration's own multiple.
Entry 8 of issue #19 fixed the default multiple at five on 2026-08-08 and made
it overridable per parameter; `declaration.DEFAULT_HALF_WIDTH_MULTIPLE` is
where that number lives, because it is inside the digested bytes of a plan.

Symmetric rather than one-sided, and the sign therefore falls out of the digest
rather than being fixed here. An offset that is always positive halves the
search and tells the analyst which direction the truth lies in, which is the
information that biases a cut.

The mapping from digest to number is `interval`, which is issue #40 and is
integer and exact-rational arithmetic with one conversion at the end. Nothing
here does floating point except that one multiplication of the uncertainty by
the multiple, and it happens before the interval rather than inside it.

## What this module does not do

It does not invert. Unblinding is milestone 08, and issue #41 is the bound on
what an inversion could promise in floating point.

It does not touch a scale parameter or a bounded fraction. The factor for a
scale parameter is issue #38 and the logit offset for a bounded fraction is the
transform the declaration already names for that kind; a declaration naming
either is refused here rather than quietly given an offset, because a transform
applied to a parameter whose kind does not admit it is a blinded value nobody
can unblind by the rule the plan names.

It does not know about groups. Issue #39 derives one value for a group of
parameters that are not independent and applies it under a stated rule, and
that is a construction over this one rather than a branch inside it.

The identifier is this module's own and not the declaration set's. A change to
the byte count, the endianness or the divisor in `interval` is a change to it,
which is what that module says about itself, and so is a change to the message
below or to the primitive.
"""

from __future__ import annotations

import hmac

from . import interval
from .canonical import canonical_text, frame
from .declaration import Declaration, Transform
from .refusal import Refusal

# The identifier every offset below is produced under, and it is inside the
# message rather than beside it, so a value drawn under a later identifier
# cannot collide with one drawn under this.
CONTRACT = "blende/location-offset/1"

# The digest primitive. Issue #46 fixes one primitive across the derivation,
# the commitment and the chain, and names it in the specification document;
# this line is what it cites or replaces. It agrees with `key.DIGEST` today and
# a second answer here would be an offset that disagreed with the fingerprint
# recorded beside it.
DIGEST = "sha256"


def context(declaration: Declaration) -> bytes:
    """The message the keyed digest is taken over.

    Written as its own function because it is the part an implementation in
    another language reproduces, and because a test that asserts what is in it
    is worth more than a test that asserts a number came out.
    """
    return frame(
        canonical_text(declaration.name, CONTRACT),
        canonical_text(declaration.name, declaration.name),
        canonical_text(declaration.name, declaration.transform.value),
    )


def _require_a_parameter_this_transform_reaches(declaration: Declaration) -> None:
    """Refuse a declaration whose own terms say it gets no offset."""
    if not declaration.blinded:
        raise Refusal(
            "never-blinded-parameter-draws-no-offset",
            declaration.name,
            "this parameter declares that it is never transformed, and an "
            "offset drawn for it would be a value no reader of the plan "
            "expects the artefact to carry",
        )
    if declaration.transform is not Transform.OFFSET:
        raise Refusal(
            "transform-is-not-the-offset",
            declaration.name,
            f"this module draws the offset a location parameter declares and "
            f"this declaration names {declaration.transform.value}, which is "
            f"drawn by the transform that owns it",
        )


def digest_for(key_material: bytes, declaration: Declaration) -> bytes:
    """The keyed digest an offset is read out of.

    Separated from the number so that a vector file under issue #43 can carry
    both, and so that the mapping in `interval` is fed by something a reader
    can check on its own.
    """
    _require_a_parameter_this_transform_reaches(declaration)
    return hmac.new(key_material, context(declaration), DIGEST).digest()


def offset(key_material: bytes, declaration: Declaration) -> float:
    """The constant added to a location parameter, for the life of the plan.

    `key_material` is `key.BlindingKey.material`. It is taken as bytes rather
    than as the key object so that this function is a function of the contract
    and nothing else, which is what an implementation in another language reads
    it as.
    """
    # The digest first, so a declaration this module does not reach is refused
    # by the rule that says so rather than by the half-width's own guard, which
    # would name the wrong thing.
    digest = digest_for(key_material, declaration)
    half_width = declaration.half_width()
    return interval.into(declaration.name, digest, -half_width, half_width)
