"""The parameter declaration, and the set of them that enters a commitment.

Issue #36 decides that nothing is blinded without a declaration and that the
declaration is the object that goes into the commitment. This module is that
object and the canonical bytes it is digested through.

What a declaration carries. A name, which is the domain separator in the
derivation and therefore part of the answer rather than a label. A kind, from a
closed set. A range the true value is expected to lie in, which is what the
transform is sized against. The transform to apply, which the kind constrains.
Whether the parameter is blinded at all, and the reason where it is not.

The range is carried by a blinded declaration and refused on a never-blinded
one, which is issue #44's field set rather than #36's. The range exists to size
a transform, and a parameter that is never blinded has no transform for it to
size: requiring one made an operator declaring a calibration constant, a
control region yield or a count of records invent two numbers to get past a
check whose own message says why they are not needed, and those two invented
numbers entered the canonical bytes and therefore the commitment, so two
operators making the same honest declaration committed to different digests. It
also cost a reader. A range beside a parameter in a plan reads as a statement
about where the true value was expected to lie, and for a never-blinded
parameter the operator never made that statement.

The kind decides which transform is admissible and the admissible set is small
on purpose. A location parameter admits an offset. A scale parameter admits a
factor, because an additive offset can send a positive quantity negative and
the fit then sits on a boundary the blinding put there, which is issue #38. A
bounded fraction is transformed on the logit so the blinded value stays inside
its bounds. A count admits nothing.

A count admitting nothing is a decision this module takes rather than defers,
and it is the one place it departs from the letter of #36. That issue leaves
the transform for a count deferred, on the grounds that a count is an integer
and an offset on it is visible in the last digit, which leaves a member of a
closed set with no admissible pairing and a refusal message that would say a
pairing is inadmissible when the truth is that nobody chose one. Issue #44
already contains the resolution and names a count of records processed as a
quantity that must not be blinded at all, because blinding it breaks every
consistency check an analyst runs. So a count is a kind whose only admissible
declaration is never-blinded, the pairing table closes with no gap, and the
refusal a user meets says what is actually wrong. If a blinded integer is ever
wanted, what a blinded integer is is a larger decision than a table entry and
belongs in its own issue.

The reason line on a never-blinded declaration is issue #44's field and it is
here because the alternative is a `blinded` flag set false with nothing behind
it, which is the absence that issue exists to turn into a positive statement.
It is the operator's own text and nothing sanitises it, in the same words issue
#14 uses about free text in a record entry.

## What the canonical bytes are

    <contract identifier>
    <count of declarations, decimal>
    for each declaration, ordered by the canonical bytes of its name:
        <name> <kind> <low> <high> <transform> <blinded> <reason>

every field length-prefixed by `canonical.frame`. The name, the kind, the
transform and the word for whether the parameter is blinded go through
`canonical.canonical_text`, which normalises to NFC; the two range endpoints go
through `canonical.canonical_double` where there is a range, and are written as
empty fields where there is not. An empty field is not the same field as eight
bytes of zero, because the length prefix in front of it says so, which is what
lets the absence of a range be part of the encoding rather than a hole in it.
The identifier and the count are written by this module rather than supplied by
anybody, and are encoded UTF-8 directly, where a normalisation would be the
identity. The reason is neither: it is the operator's own prose and it is
written as its exact UTF-8 bytes, unnormalised.

The reason being unnormalised is issue #46's rule for prose that enters a
commitment, and it is deliberate. Changing a document's bytes is what a
commitment exists to detect, so a normaliser that silently rewrote what
somebody typed would let the text be edited without the digest moving. There is
a second, mechanical reason the field could not go through
`canonical.canonical_text` as it stands: that function refuses an empty string,
and a blinded declaration carries an empty reason.

Both halves are stated because `contract/__init__.py` says a reader
implementing this in another language reads these modules as prose about bytes.
A reader who took the sentence above to cover every text field would normalise
the reason and reach a different digest for the same declaration set, which is
the failure the canonical encoding exists to prevent, and the reason line is
the field an operator types and pastes into.

The order is the canonical name bytes rather than
the order somebody wrote them in, so a set that was reordered in its file
digests the same, and UTF-8 byte order and code point order agree so an
implementation sorting either way gets the same sequence.

The identifier is inside the digested bytes rather than beside them. Issue #2
requires every artefact to record which contract produced it and no artefact
exists yet; what this layer can hold today is that a change to these bytes is a
change to the identifier, and a digest taken under one identifier can never
collide with the same declarations under another.

The identifier will move before a release, and saying so now is cheaper than
discovering it. Issue #37 sizes the offset against a declared expected
uncertainty, which entry 8 of issue #19 decided on 2026-08-08 at five times
that quantity, and no field here holds it. Adding it is a new identifier under
#2 rather than an edit to this one, and it costs nothing while no artefact
exists.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum

from .canonical import canonical_double, canonical_text, frame
from .refusal import Refusal

# The identifier these bytes are produced under. It is part of the digest, so
# two contracts cannot produce one digest.
#
# It reads 2 because a never-blinded declaration no longer carries a range, so
# the bytes of every such declaration moved. Issue #2 makes a changed contract
# a new identifier rather than an edit to the old one, and it asks nothing
# about whether anybody has read the old one. Nothing in this package writes an
# artefact yet, so the set of digests in the wild under version 1 is empty.
CONTRACT = "blende/declaration-set/2"

# The digest primitive over the canonical bytes. Issue #46 fixes the primitive
# for the commitment over a plan, and when it lands this line is what it cites
# or replaces; a second answer to the same question is how a digest ends up
# disagreeing with the offset it is supposed to bind.
DIGEST = "sha256"


class Kind(Enum):
    """The closed set of parameter kinds."""

    LOCATION = "location"
    SCALE = "scale"
    BOUNDED_FRACTION = "bounded-fraction"
    COUNT = "count"


class Transform(Enum):
    """The closed set of transforms, including the absence of one."""

    OFFSET = "offset"
    FACTOR = "factor"
    LOGIT_OFFSET = "logit-offset"
    NONE = "none"


# The pairing table, written as a sequence of pairs rather than as a mapping.
# A mapping keyed by an enum member is ordered by insertion in this
# interpreter and by nothing the language promises, and this table is read in
# order when a refusal has to say what the kind does admit.
ADMISSIBLE: tuple[tuple[Kind, tuple[Transform, ...]], ...] = (
    (Kind.LOCATION, (Transform.OFFSET,)),
    (Kind.SCALE, (Transform.FACTOR,)),
    (Kind.BOUNDED_FRACTION, (Transform.LOGIT_OFFSET,)),
    (Kind.COUNT, ()),
)


def admissible_transforms(kind: Kind) -> tuple[Transform, ...]:
    """What a kind admits, read out of the table rather than out of a mapping."""
    for candidate, transforms in ADMISSIBLE:
        if candidate is kind:
            return transforms
    raise Refusal(
        "kind-is-outside-the-closed-set",
        kind.value,
        "the set of kinds is closed and this is not in it",
    )


@dataclass(frozen=True)
class Declaration:
    """One parameter, declared before anything is blinded."""

    name: str
    kind: Kind
    # Both endpoints or neither. A blinded parameter carries the range its
    # transform is sized against; a never-blinded one is written with `None`
    # twice, so the absence is stated at every call site rather than defaulted
    # into.
    low: float | None
    high: float | None
    transform: Transform
    blinded: bool
    # Required where the parameter is never blinded, refused where it is.
    reason: str = ""

    def __post_init__(self) -> None:
        # Encoding the name here rather than at digest time, so a name that
        # cannot enter a digest is refused when it is written rather than when
        # a commitment is taken over it.
        canonical_text(self.name, self.name)
        if self.blinded:
            self._check_it_carries_the_range_its_transform_is_sized_against()
            self._check_the_kind_admits_the_transform()
            if self.reason:
                raise Refusal(
                    "reason-belongs-to-a-never-blinded-parameter",
                    self.name,
                    "the reason line says why a parameter is not blinded, so "
                    "carrying one on a blinded parameter makes the field mean "
                    "two things",
                )
            return
        if self.transform is not Transform.NONE:
            raise Refusal(
                "never-blinded-carries-no-transform",
                self.name,
                "a parameter declared as never blinded and carrying a "
                "transform is a declaration that disagrees with itself",
            )
        if self.low is not None or self.high is not None:
            raise Refusal(
                "never-blinded-carries-no-range",
                self.name,
                "the range is what a transform is sized against, so a "
                "parameter that is never transformed has nothing for it to "
                "size, and a range in a plan reads as a statement about where "
                "the true value was expected to lie",
            )
        if not self.reason.strip():
            raise Refusal(
                "never-blinded-carries-a-reason",
                self.name,
                "a parameter that is not blinded is a positive statement and "
                "the reason is what a referee reads when they ask why",
            )

    def _check_it_carries_the_range_its_transform_is_sized_against(self) -> None:
        low = self.low
        high = self.high
        if low is None or high is None:
            raise Refusal(
                "blinded-carries-a-range",
                self.name,
                "the transform is sized against the range the true value is "
                "expected to lie in, and a blinded parameter that declares "
                "one endpoint or neither has nothing to size it against",
            )
        if not low < high:
            raise Refusal(
                "range-is-not-ordered",
                self.name,
                "the range is what the transform is sized against, and a "
                "range whose lower endpoint is not below its upper one has no "
                "width to size anything against",
            )

    def _check_the_kind_admits_the_transform(self) -> None:
        admitted = admissible_transforms(self.kind)
        if self.transform in admitted:
            return
        if not admitted:
            raise Refusal(
                "kind-admits-no-transform",
                self.name,
                f"a {self.kind.value} is a bookkeeping number whose blinding "
                f"breaks the consistency checks an analyst runs, so it is "
                f"declared as never blinded rather than transformed",
            )
        raise Refusal(
            "kind-admits-no-such-transform",
            self.name,
            f"a {self.kind.value} parameter admits "
            f"{', '.join(sorted(one.value for one in admitted))} and this "
            f"declaration names {self.transform.value}",
        )

    def _endpoint_bytes(self, endpoint: float | None) -> bytes:
        """An endpoint's bytes, or an empty field where there is no range.

        The empty field is what the framing makes safe. `canonical.frame`
        writes a length in front of every field, so a field of no bytes is a
        field a reader can tell from eight bytes of zero, and the absence of a
        range is encoded rather than skipped.
        """
        if endpoint is None:
            return b""
        return canonical_double(self.name, endpoint)

    def canonical_bytes(self) -> bytes:
        """The bytes this declaration contributes to a digest."""
        return frame(
            canonical_text(self.name, self.name),
            canonical_text(self.name, self.kind.value),
            self._endpoint_bytes(self.low),
            self._endpoint_bytes(self.high),
            canonical_text(self.name, self.transform.value),
            # A boolean is written as a word rather than as a byte, so the
            # stream stays readable to somebody implementing this from the
            # module doc, and the two words differ in length as well as in
            # content.
            canonical_text(self.name, "blinded" if self.blinded else "never-blinded"),
            self.reason.encode("utf-8"),
        )


@dataclass(frozen=True)
class DeclarationSet:
    """Every parameter an analysis touches, in one object.

    The set is what enters the commitment, so it has one serialisation and one
    digest. Two entries under one name would give it two, which is why a
    repeated name is refused here rather than resolved by whichever entry was
    read last.
    """

    declarations: tuple[Declaration, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        seen: list[bytes] = []
        for declaration in self.declarations:
            key = canonical_text(declaration.name, declaration.name)
            if key in seen:
                raise Refusal(
                    "declaration-set-names-a-parameter-twice",
                    declaration.name,
                    "two entries under one name give the set two digests and "
                    "the analysis two answers about how that parameter is "
                    "blinded",
                )
            seen.append(key)

    def ordered(self) -> tuple[Declaration, ...]:
        """The declarations in the order the canonical bytes are written in."""
        return tuple(
            sorted(
                self.declarations,
                key=lambda declaration: canonical_text(
                    declaration.name, declaration.name
                ),
            )
        )

    def canonical_bytes(self) -> bytes:
        """The whole set as one byte string, injectively."""
        return frame(
            CONTRACT.encode("utf-8"),
            str(len(self.declarations)).encode("utf-8"),
            *(declaration.canonical_bytes() for declaration in self.ordered()),
        )

    def digest(self) -> str:
        """The digest a commitment carries for this set."""
        return hashlib.new(DIGEST, self.canonical_bytes()).hexdigest()


def require_the_set_the_commitment_names(
    declarations: DeclarationSet, digest: str
) -> None:
    """Refuse a declaration set that is not the one the commitment names.

    The name is part of the derived offset, so renaming a parameter changes its
    blinding. A group that renames one mid-analysis and reblinds has changed
    the blinding, and this is what stops that happening quietly. Changing a
    declaration on purpose is issue #65's path and not this one.

    The digest is passed in. What carries it is the commitment file, which is
    issue #48 and does not exist yet, so this refusal is complete and its
    input has one source fewer than it will have.
    """
    if declarations.digest() != digest:
        raise Refusal(
            "declaration-set-is-not-the-one-the-commitment-names",
            CONTRACT,
            "the declarations this run holds digest to something other than "
            "the value recorded when the analysis plan was fixed",
        )
