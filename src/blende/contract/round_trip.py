"""What a round trip through a file can promise, and the size of what it loses.

Issue #41 decides that adding an offset to a value and subtracting it again
does not always return the value, that this is arithmetic rather than a defect,
and that the package states a bound instead of claiming exactness. This module
is that bound.

## The two operations it is a bound on

A blinded value written to a file is `fl(v + o)`, where `fl` is the rounding
every double operation ends with. Reading it back and unblinding it is
`fl(fl(v + o) - o)`. Those two roundings are the whole of the loss, and the
bound below is over exactly them.

Nothing else in the analysis is covered, and that is a real limit rather than a
formality. A value that stays in memory is never round-tripped at all, which is
issue #41's own rule and the reason the archival path and the analysis path are
different paths.

## Where the bound comes from

Let `V` be the largest magnitude the true value can have inside the declared
range, so `V` is the larger of the two endpoints in magnitude. Let `H` be the
half-width the offset is drawn from, which `Declaration.half_width` states. The
blinded value has magnitude at most `M = V + H`, and so does the exact
difference the second operation rounds, because that difference is the true
value again to within the first rounding.

Each rounding moves a number by at most half an ulp at its own magnitude, and
both magnitudes are at most `M`, so the two together move the value by at most
one ulp at `M`. That is the bound, and it is the whole derivation:

    bound = ulp(M),  M = max(|low|, |high|) + half_width

`M` is computed as an exact rational and then rounded up to a double, so the
bound is never taken at a magnitude below the one it has to cover.

The bound is attained rather than generous, which matters because a bound
nothing comes near proves nothing. `tests/test_round_trip.py` sweeps five
declared ranges and the interval each offset is drawn from, and the largest
loss it finds is the bound itself. The declaration it is attained on is the
ordinary one, where the range and the half-width together straddle a binade
boundary so both roundings are taken at the wider ulp.

## What it says about the regime this package works in

The offset is large compared with the uncertainty on purpose, which is what
makes the loss worth a bound at all. `M` is set by the range and the
half-width together, so a parameter measured near ten to the tenth with an
uncertainty near a millionth has a round-trip bound larger than its own
uncertainty. Issue #41 asks for a declaration in that state to be refused, and
this module does not refuse it: what counts as negligible is a number, no issue
on the board fixes it, and a threshold invented here would be a number two
formats later disagree about. The bound is computed and returned; the line it
has to sit under is not drawn here.

## What is refused

A declaration whose blinded value could not be a double at all. The range
endpoints and the uncertainty are each finite, since the canonical encoding
refuses an infinity, and their sum still need not be: a half-width is a product
of two declared numbers and can overflow on its own. A bound of infinity is not
a promise, so the declaration is refused instead of one being returned.

## What this module is not

It is not an inverse. Nothing here subtracts an offset from anything, because
the writers and the readers this bound is about do not exist yet: the artefact
formats are milestones 04 and 05 and unblinding is milestone 08. The bound is
in force ahead of the layer it constrains, which is the order issue #41 asks
for, since a bound invented after a format exists is a bound fitted to the
format.

It does not travel with an artefact. Issue #41 asks for that too, and issue
#11 fixed where a fifth value in the artefact field would go and the rule for
appending one. Both are the writer's, and there is no writer.
"""

from __future__ import annotations

import math
from fractions import Fraction

from .declaration import Declaration
from .refusal import Refusal


def _require_a_magnitude_a_double_can_hold(subject: str, magnitude: float) -> None:
    """Refuse a blinded value that could not be written in the first place."""
    if math.isfinite(magnitude):
        return
    raise Refusal(
        "blinded-value-is-not-representable",
        subject,
        "the range and the half-width together reach past the largest double, "
        "so a blinded value of this parameter could not be written at all and "
        "no bound on reading it back would be a promise",
    )


def blinded_magnitude(declaration: Declaration) -> float:
    """The largest magnitude a blinded value of this parameter can have.

    Exact until the last step, then rounded up rather than to nearest. A
    magnitude rounded down would put the ulp below the one the bound has to
    cover, which is a bound that is wrong in the direction nobody checks.
    """
    low = declaration.low
    high = declaration.high
    if low is None or high is None:
        raise Refusal(
            "never-blinded-has-no-round-trip",
            declaration.name,
            "the bound is the loss on writing a blinded value and reading it "
            "back, and this parameter declares that it is never transformed",
        )
    half_width = declaration.half_width()
    # Before the exact arithmetic rather than after it. The half-width is a
    # product of two declared numbers and can overflow on its own, and a
    # rational cannot be taken over what that produces.
    _require_a_magnitude_a_double_can_hold(declaration.name, half_width)
    exact = max(Fraction(abs(low)), Fraction(abs(high))) + Fraction(half_width)
    magnitude = float(exact)
    if magnitude < exact:
        magnitude = math.nextafter(magnitude, math.inf)
    _require_a_magnitude_a_double_can_hold(declaration.name, magnitude)
    return magnitude


def bound(declaration: Declaration) -> float:
    """The most a value moves on the way out to a file and back.

    Two roundings, each at most half an ulp at a magnitude the blinded value
    does not exceed, so one ulp at that magnitude covers both.
    """
    return math.ulp(blinded_magnitude(declaration))
