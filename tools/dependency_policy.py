"""The advisory and license policy over the dependency set, and its proof.

Issue #26 asks for a check named `deny` that fails on a known vulnerability in
any resolved dependency and on a dependency whose license falls outside a
declared allow list, over a resolved set that is locked rather than a range,
with every acceptance carrying a date and a reason in a tracked file.

Three modes.

    python tools/dependency_policy.py
        Reads the tracked locks, asks the advisory database and the index
        about every pinned distribution, and refuses. Prints what it read and
        what it did not, so a green run cannot be quoted as covering more than
        it covered.

    python tools/dependency_policy.py --prove
        Reads `tests/policy-regressions/`, where every refusal has a scenario
        written to trip it. Each scenario names the refusal it is for. The
        mode refuses a refusal no scenario trips, a scenario naming a refusal
        that does not exist, a scenario that produced no refusal at all, and a
        scenario refused by something other than what it names. A refusal that
        has never been shown to bite is a branch nobody has taken.

    python tools/dependency_policy.py --relock
        Re-resolves both sets and rewrites the lock files. A developer action
        rather than a gate: it needs pip and the index, and its output is a
        diff a reviewer reads. The gate never relocks, because a gate that
        repairs its own input has stopped being a gate.

The means is Python from the standard library, plus pip for the resolution in
`--relock` alone. `tomllib` reads the metadata and the acceptance register,
`urllib` asks the two services, and nothing here is installed. A resolver is
the one thing the standard library does not carry, and pip is the installer
whose behaviour the lock is a statement about, so letting anything else decide
the versions would lock a set that is not the set that gets installed. That is
the forced means, held to the one mode that needs it.

## What the lock is a statement about, and what it is not

Both sets are resolved on the interpreter this package declares as its floor,
because that is the interpreter every gate in this tree installs, through
`.github/actions/declared-floor`. So the lock says what the gates install.

It does not say what an install of this package on somebody else's machine
resolves to. `pyproject.toml` declares `numpy` without a bound on purpose, and
a newer interpreter resolves a newer numpy than the floor can take: at the time
of writing numpy 2.5 requires 3.12 and the floor is 3.11. An advisory against a
version this lock does not carry is therefore outside what this check reads,
and the run prints that rather than leaving it to be discovered.

The build input set is a third set and it is not locked here.
`pyproject.toml` declares `hatchling>=1.27,<2` as a range and says pinning the
whole build input set is issue #91. This check reads what is locked, so the
build backend and everything it pulls in are outside it, and the run says so.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
import tomllib
import urllib.error
import urllib.request
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent

# Where the locks and the acceptance register live. One directory, so a reader
# looking for what is pinned has one place to look and a reviewer sees a
# resolution change as a diff in a file whose whole purpose is to carry one.
LOCK_DIRECTORY = "requirements"
ACCEPTANCES = "requirements/accepted.toml"

# Where the scenarios live. They are written to be refused, so nothing that
# walks the tree may read them as tracked input.
SCENARIOS = "tests/policy-regressions"

# The two services this check reads, and the reason each is the one asked.
#
# OSV is the aggregator the Python ecosystem's own advisory database publishes
# into, so asking it once covers both the GitHub advisories and the PyPI
# advisories rather than asking two services and merging them here.
#
# The index is asked for the license because the license of a distribution is a
# fact about the distribution as published, and reading it out of an install
# instead would mean installing every version this check judges.
OSV_QUERY = "https://api.osv.dev/v1/query"
INDEX_RELEASE = "https://pypi.org/pypi/{name}/{version}/json"

# A network read that hangs is a gate that never answers, which is the same
# thing as a gate that passes.
TIMEOUT_SECONDS = 30


# --------------------------------------------------------------------------
# The refusals
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Kind:
    """One thing this check refuses, why, and what it does not reach."""

    id: str
    # The issue that asked for it, so a reader argues with the decision rather
    # than with the code.
    issue: str
    # What a refusal of this kind means, printed when it bites.
    refuses: str
    # The residual, at the refusal rather than in a document beside it.
    blind_to: str


ADVISORY = Kind(
    id="advisory",
    issue="#26",
    refuses=(
        "a locked distribution carries a known advisory and no acceptance "
        "covers it. An advisory with no fixed version available is still a "
        "failure: it is resolved by a written acceptance with a date, and "
        "never by the check passing quietly"
    ),
    blind_to=(
        "an advisory against a version this lock does not carry, which is "
        "every version an install on a newer interpreter would resolve, and "
        "an advisory nobody has published yet. It is also blind to the build "
        "input set, which is a range rather than a resolution and is #91"
    ),
)

LICENSE_OUTSIDE_THE_ALLOW_LIST = Kind(
    id="license-outside-the-allow-list",
    issue="#26",
    refuses=(
        "a locked distribution declares a license this repository's own "
        "license cannot take, declares none at all, or declares one in a "
        "form this check cannot place. All three are outside an allow list, "
        "and the third is refused rather than guessed at"
    ),
    blind_to=(
        "a license that is declared correctly in the metadata and wrong in "
        "the source, and a distribution whose files carry terms the metadata "
        "does not mention. This reads what the index was told"
    ),
)

LOCK_DOES_NOT_MATCH_THE_DECLARED_INPUTS = Kind(
    id="lock-does-not-match-the-declared-inputs",
    issue="#26",
    refuses=(
        "a lock records that it was resolved from inputs the tree no longer "
        "declares. A dependency added, removed or bounded, or a floor that "
        "moved, changes what a resolution would produce, so the lock stops "
        "being a statement about what installs"
    ),
    blind_to=(
        "a resolution that would move while the inputs stand still, which is "
        "an unbounded requirement meeting a new release. That case is the "
        "lock doing its work rather than drifting, and it is caught by "
        "relocking on purpose"
    ),
)

PIN_OUTSIDE_THE_LOCK = Kind(
    id="pin-outside-the-lock",
    issue="#26",
    refuses=(
        "a workflow installs a distribution at a version no lock carries. A "
        "pin written in one place and locked in another is a pin that drifts, "
        "and the drift shows up as a gate running a tool this check never "
        "judged"
    ),
    blind_to=(
        'every spelling but `"name==${VARIABLE}"` inside a pip install line, '
        "whose variable is resolved from an env entry in the same file. A tool "
        "installed at a literal version, assembled from another string, or "
        "brought in by an action rather than by pip, is not seen here"
    ),
)

ACCEPTANCE_WITHOUT_A_DATE_AND_A_REASON = Kind(
    id="acceptance-without-a-date-and-a-reason",
    issue="#26",
    refuses=(
        "an entry in the acceptance register that does not carry the advisory "
        "it accepts, the distribution it is about, a date as YYYY-MM-DD and a "
        "reason. An acceptance nobody dated is one nobody can revisit"
    ),
    blind_to=(
        "whether the reason is a reason. A sentence that says nothing passes "
        "this and is what the review is for"
    ),
)

ACCEPTANCE_MATCHES_NO_FINDING = Kind(
    id="acceptance-matches-no-finding",
    issue="#26",
    refuses=(
        "an acceptance that covers nothing this run found. The register fails "
        "closed in both directions, because an acceptance left behind after "
        "the advisory was fixed is a standing permission nobody reviewed"
    ),
    blind_to=(
        "an acceptance that matches a finding for the wrong reason, which is "
        "an advisory reused under one identifier for two distributions"
    ),
)

KINDS: tuple[Kind, ...] = (
    ADVISORY,
    LICENSE_OUTSIDE_THE_ALLOW_LIST,
    LOCK_DOES_NOT_MATCH_THE_DECLARED_INPUTS,
    PIN_OUTSIDE_THE_LOCK,
    ACCEPTANCE_WITHOUT_A_DATE_AND_A_REASON,
    ACCEPTANCE_MATCHES_NO_FINDING,
)


@dataclass(frozen=True)
class Finding:
    kind: Kind
    subject: str
    detail: str


# --------------------------------------------------------------------------
# The allow list
# --------------------------------------------------------------------------

# What this repository's own license can take. The maintainer decided AGPL-3.0
# on 2026-08-08, in issue #19 entry 1, and that decision is what makes this
# list writable at all: an allow list is a statement about compatibility with
# a named license, so it could not exist while the name was open.
#
# Everything here is either permissive, weakly reciprocal, or reciprocal in a
# direction AGPL-3.0 can absorb. What is deliberately absent is the case the
# list exists for: GPL-2.0-only, which is one-way incompatible with
# AGPL-3.0, anything proprietary, and anything the index carries no license
# for. Absence is the refusal; there is no deny list to keep in step with this
# one, because a second list is a second thing to forget.
ALLOWED_LICENSES = frozenset(
    {
        # Permissive, no reciprocity.
        "0BSD",
        "Apache-2.0",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "CC0-1.0",
        "ISC",
        "MIT",
        "MIT-0",
        "PSF-2.0",
        "Python-2.0",
        "Unlicense",
        "Zlib",
        # File-level and library-level reciprocity, which AGPL-3.0 combines
        # with in the direction this repository needs.
        "MPL-2.0",
        "LGPL-2.1-only",
        "LGPL-2.1-or-later",
        "LGPL-3.0-only",
        "LGPL-3.0-or-later",
        # Strong reciprocity that is compatible in this direction. GPL-2.0
        # appears only in its `or-later` form, which can be taken forward to
        # GPL-3.0 and from there is compatible; `GPL-2.0-only` cannot and is
        # absent for that reason.
        "GPL-2.0-or-later",
        "GPL-3.0-only",
        "GPL-3.0-or-later",
        "AGPL-3.0-only",
        "AGPL-3.0-or-later",
    }
)

# The index still serves a free-text license field for distributions whose
# metadata predates PEP 639, and a free-text field cannot be evaluated as an
# expression. This maps the exact strings this check has met to the identifier
# they mean. It is not a general parser and is not meant to become one:
# anything not here is refused as a license the check cannot place, which is a
# refusal a person resolves by reading the distribution and adding a line.
LEGACY_LICENSE_TEXT = {
    "MIT": "MIT",
    "MIT License": "MIT",
    "BSD": "BSD-3-Clause",
    "BSD License": "BSD-3-Clause",
    "BSD-3-Clause": "BSD-3-Clause",
    "Apache 2.0": "Apache-2.0",
    "Apache-2.0": "Apache-2.0",
    "Apache Software License": "Apache-2.0",
    "ISC": "ISC",
    "MPL-2.0": "MPL-2.0",
    "PSF-2.0": "PSF-2.0",
    # The string this check was proved against. mysqlclient carries it, and it
    # is GPL version 2 with no `or later`, which is the case the allow list
    # exists to refuse.
    "GNU General Public License v2 (GPLv2)": "GPL-2.0-only",
    "GPL-2.0": "GPL-2.0-only",
    "GPLv2": "GPL-2.0-only",
}


def spdx_tokens(expression: str) -> list[str]:
    """Split an SPDX expression into identifiers, operators and parentheses."""
    return re.findall(r"\(|\)|[A-Za-z0-9.+:_-]+", expression)


class Unreadable(Exception):
    """An expression this check will not guess at."""


def evaluate_spdx(expression: str) -> bool:
    """Whether every branch an SPDX expression allows is one this list allows.

    A recursive descent over the small grammar the index actually serves:
    identifiers, `WITH`, `AND`, `OR` and parentheses. `OR` is a real choice, so
    one allowed branch is enough; `AND` binds every branch at once, so all of
    them have to be allowed. `WITH` attaches an exception to an identifier and
    the pair is treated as one atom, which means an exception this list has
    never seen makes the atom unknown rather than making it disappear.

    An expression this function cannot parse raises rather than returning
    False, so `cannot place` and `not allowed` stay two different answers.
    """
    tokens = spdx_tokens(expression)
    if not tokens:
        raise Unreadable("the expression is empty")
    position = 0

    def peek() -> str | None:
        return tokens[position] if position < len(tokens) else None

    def take() -> str:
        nonlocal position
        if position >= len(tokens):
            raise Unreadable("the expression ends where a term was expected")
        token = tokens[position]
        position += 1
        return token

    def atom() -> bool:
        token = take()
        if token == "(":
            inner = disjunction()
            if take() != ")":
                raise Unreadable("a parenthesis is not closed")
            return inner
        if token in {")", "AND", "OR", "WITH"}:
            raise Unreadable(f"{token} appears where an identifier was expected")
        identifier = token
        if peek() == "WITH":
            take()
            identifier = f"{identifier} WITH {take()}"
        return identifier in ALLOWED_LICENSES

    def conjunction() -> bool:
        allowed = atom()
        while peek() == "AND":
            take()
            allowed = atom() and allowed
        return allowed

    def disjunction() -> bool:
        allowed = conjunction()
        while peek() == "OR":
            take()
            allowed = conjunction() or allowed
        return allowed

    result = disjunction()
    if position != len(tokens):
        raise Unreadable(f"{tokens[position]} is left over at the end")
    return result


# --------------------------------------------------------------------------
# What a scenario is
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Pin:
    """One distribution at one version, and where the version was written."""

    name: str
    version: str
    written_in: str

    @property
    def key(self) -> str:
        return f"{canonical(self.name)}=={self.version}"


@dataclass(frozen=True)
class Acceptance:
    """One advisory somebody wrote down a reason and a date for."""

    advisory: str
    distribution: str
    date: str
    reason: str
    where: str


@dataclass(frozen=True)
class Scenario:
    """Everything the evaluation reads, from the tree or from a sample.

    One object for both, so a scenario proves the code the gate runs rather
    than a copy of it written for the proof.
    """

    # Lock set name to the requirement strings the tree declares for it.
    declared: dict[str, tuple[str, ...]]
    # Lock set name to the requirement strings that lock records as its input.
    recorded: dict[str, tuple[str, ...]]
    # Lock set name to what that lock pins.
    locked: dict[str, tuple[Pin, ...]]
    # Versions written anywhere else in the tree that ought to be in a lock.
    pins: tuple[Pin, ...]
    acceptances: tuple[Acceptance, ...]


@dataclass
class Judgement:
    findings: list[Finding] = field(default_factory=list)
    # What was read, printed by a green run so it says what it covered.
    read: list[str] = field(default_factory=list)


def canonical(name: str) -> str:
    """The distribution name in the one form two spellings of it share."""
    return re.sub(r"[-_.]+", "-", name).lower()


DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


# --------------------------------------------------------------------------
# The index and the advisory database
# --------------------------------------------------------------------------


class ServiceFailed(Exception):
    """A service could not be read, so nothing may be reported about it."""


def read_json(request: urllib.request.Request) -> dict:
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            return json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, ValueError) as failure:
        raise ServiceFailed(f"{request.full_url}: {failure}") from failure


def advisories_against(pin: Pin) -> list[str]:
    """Every advisory identifier the database holds against exactly this pin."""
    body = json.dumps(
        {
            "package": {"name": pin.name, "ecosystem": "PyPI"},
            "version": pin.version,
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        OSV_QUERY, data=body, headers={"Content-Type": "application/json"}
    )
    answer = read_json(request)
    return sorted(entry["id"] for entry in answer.get("vulns", []))


def declared_license(pin: Pin) -> tuple[str | None, str]:
    """The license the index holds for this pin, and where it was read.

    Two fields rather than one. `license_expression` is the PEP 639 field and
    is an SPDX expression by construction. `license` is the free-text field it
    replaced, and is read only when the first is absent.
    """
    answer = read_json(
        urllib.request.Request(INDEX_RELEASE.format(name=pin.name, version=pin.version))
    )
    info = answer.get("info", {})
    expression = info.get("license_expression")
    if isinstance(expression, str) and expression.strip():
        return expression.strip(), "license_expression"
    legacy = info.get("license")
    if isinstance(legacy, str) and legacy.strip():
        return legacy.strip(), "license"
    return None, "neither field"


# --------------------------------------------------------------------------
# The evaluation
# --------------------------------------------------------------------------


def judge_the_locks(scenario: Scenario, judgement: Judgement) -> None:
    """Refuse a lock whose recorded inputs are not what the tree declares."""
    for name in sorted(set(scenario.declared) | set(scenario.recorded)):
        declared = tuple(sorted(scenario.declared.get(name, ())))
        recorded = tuple(sorted(scenario.recorded.get(name, ())))
        if declared == recorded:
            judgement.read.append(
                f"lock {name}: resolved from {', '.join(declared) or 'nothing'}"
            )
            continue
        judgement.findings.append(
            Finding(
                kind=LOCK_DOES_NOT_MATCH_THE_DECLARED_INPUTS,
                subject=f"lock {name}",
                detail=(
                    f"The tree declares {', '.join(declared) or 'nothing'} and "
                    f"the lock records {', '.join(recorded) or 'nothing'}. "
                    "Re-resolve with --relock and read the diff."
                ),
            )
        )


def judge_the_pins(scenario: Scenario, judgement: Judgement) -> None:
    """Refuse a version written outside a lock that no lock carries."""
    inside = {pin.key for pins in scenario.locked.values() for pin in pins}
    for pin in scenario.pins:
        if pin.key in inside:
            judgement.read.append(f"pin {pin.key} in {pin.written_in}: locked")
            continue
        judgement.findings.append(
            Finding(
                kind=PIN_OUTSIDE_THE_LOCK,
                subject=pin.key,
                detail=(
                    f"{pin.written_in} installs it and no lock carries that "
                    "version, so this check has judged neither its advisories "
                    "nor its license."
                ),
            )
        )


def judge_the_acceptances(
    scenario: Scenario, matched: set[str], judgement: Judgement
) -> None:
    """Refuse an incomplete acceptance, and one that covers nothing found."""
    for acceptance in scenario.acceptances:
        missing = [
            field_name
            for field_name, value in (
                ("advisory", acceptance.advisory),
                ("distribution", acceptance.distribution),
                ("date", acceptance.date),
                ("reason", acceptance.reason),
            )
            if not value.strip()
        ]
        if not missing and not DATE.match(acceptance.date):
            missing.append("date as YYYY-MM-DD")
        if missing:
            judgement.findings.append(
                Finding(
                    kind=ACCEPTANCE_WITHOUT_A_DATE_AND_A_REASON,
                    subject=f"{acceptance.where}: {acceptance.advisory or 'an entry'}",
                    detail=f"It carries no {', no '.join(missing)}.",
                )
            )
            continue
        key = f"{acceptance.advisory}@{canonical(acceptance.distribution)}"
        if key in matched:
            judgement.read.append(f"acceptance {key}: covers a finding of this run")
            continue
        judgement.findings.append(
            Finding(
                kind=ACCEPTANCE_MATCHES_NO_FINDING,
                subject=key,
                detail=(
                    f"Written {acceptance.date} and nothing this run found "
                    "matches it. Remove it, or say why the advisory it names "
                    "is no longer reported."
                ),
            )
        )


def refuse_the_license(pin: Pin, detail: str) -> Finding:
    return Finding(kind=LICENSE_OUTSIDE_THE_ALLOW_LIST, subject=pin.key, detail=detail)


def judge_the_advisories(
    pin: Pin, accepted: set[str], matched: set[str], judgement: Judgement
) -> None:
    """Refuse every advisory against one pin that no acceptance covers."""
    found = advisories_against(pin)
    outstanding = []
    for advisory in found:
        key = f"{advisory}@{canonical(pin.name)}"
        if key in accepted:
            matched.add(key)
        else:
            outstanding.append(advisory)
    if outstanding:
        judgement.findings.append(
            Finding(
                kind=ADVISORY,
                subject=pin.key,
                detail=(
                    f"{', '.join(outstanding)}. Fix the version, or write an "
                    f"acceptance into {ACCEPTANCES} carrying the advisory, the "
                    "distribution, a date and a reason."
                ),
            )
        )
    judgement.read.append(
        f"advisories {pin.key}: {', '.join(found) if found else 'none'}"
    )


def judge_the_license(pin: Pin, judgement: Judgement) -> None:
    """Refuse a license outside the allow list, absent, or unplaceable.

    Three ways out and each is its own refusal message, because the repair
    differs: a refused identifier means dropping the dependency, an absent one
    means reading the distribution, and an unplaceable string means teaching
    this tool one line.
    """
    expression, source = declared_license(pin)
    if expression is None:
        judgement.findings.append(
            refuse_the_license(
                pin,
                "The index holds no license for it, in either metadata field. "
                "An undeclared license is outside every allow list rather than "
                "inside this one.",
            )
        )
        return

    resolved = expression
    if source == "license":
        placed = LEGACY_LICENSE_TEXT.get(expression)
        if placed is None:
            judgement.findings.append(
                refuse_the_license(
                    pin,
                    f"Its free-text license field reads {expression!r}, which "
                    "this check cannot place as an identifier. Read the "
                    "distribution and add the string to the table in this "
                    "tool, or drop the dependency.",
                )
            )
            return
        resolved = placed

    try:
        allowed = evaluate_spdx(resolved)
    except Unreadable as failure:
        judgement.findings.append(
            refuse_the_license(
                pin,
                f"Its license reads {resolved!r} and this check cannot read it "
                f"as an expression: {failure}.",
            )
        )
        return

    if not allowed:
        judgement.findings.append(
            refuse_the_license(
                pin,
                f"Its license is {resolved!r}, read from the {source} field, "
                "and the allow list does not carry it.",
            )
        )
        return

    judgement.read.append(f"license {pin.key}: {resolved} ({source})")


def judge_a_scenario(scenario: Scenario) -> Judgement:
    """Every refusal, over one scenario, in one pass."""
    judgement = Judgement()
    judge_the_locks(scenario, judgement)
    judge_the_pins(scenario, judgement)

    # An acceptance is keyed by the advisory and the distribution together. An
    # identifier alone would let an acceptance written for one distribution
    # cover the same advisory reported against another.
    accepted = {
        f"{acceptance.advisory}@{canonical(acceptance.distribution)}"
        for acceptance in scenario.acceptances
        if acceptance.advisory.strip() and acceptance.distribution.strip()
    }
    matched: set[str] = set()

    for name in sorted(scenario.locked):
        for pin in scenario.locked[name]:
            judge_the_advisories(pin, accepted, matched, judgement)
            judge_the_license(pin, judgement)

    judge_the_acceptances(scenario, matched, judgement)
    return judgement


# --------------------------------------------------------------------------
# Reading the tree
# --------------------------------------------------------------------------

# A lock is a pip requirements file that pip can install with
# `--require-hashes`, and the inputs it was resolved from are comments, because
# the floor is not a requirement pip installs. The two shapes read below are
# the two this tool writes.
RECORDED_INPUT = re.compile(r"^#\s*resolved-from:\s*(?P<requirement>\S.*?)\s*$")
LOCKED_PIN = re.compile(r"^(?P<name>[A-Za-z0-9._-]+)==(?P<version>[^\s\\]+)")

# A workflow installing a pinned distribution, and the env entry that carries
# the version. Only this spelling is read, which is what PIN_OUTSIDE_THE_LOCK
# declares itself blind beyond.
WORKFLOW_INSTALL = re.compile(
    r"pip install[^\n]*?[\"']"
    r"(?P<name>[A-Za-z0-9._-]+)==\$\{(?P<variable>[A-Z0-9_]+)\}[\"']"
)
WORKFLOW_VERSION = re.compile(
    r"^\s*(?P<variable>[A-Z0-9_]+):\s*[\"'](?P<version>[0-9][^\"']*)[\"']\s*$"
)


def declared_inputs(root: Path) -> dict[str, tuple[str, ...]]:
    """What the tree declares each lock set should be resolved from.

    The floor is one of them. A lock resolved on 3.11 is not a statement about
    a resolution on 3.12, so a floor that moves has to move the lock with it,
    and the only way that is refused is by the floor being part of the input.
    """
    with (root / "pyproject.toml").open("rb") as handle:
        metadata = tomllib.load(handle)
    floor = metadata["project"].get("requires-python", "").strip()
    runtime = tuple(metadata["project"].get("dependencies", []))
    tooling = tuple(
        line.strip()
        for line in (root / LOCK_DIRECTORY / "tooling.in")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip() and not line.startswith("#")
    )
    return {
        "runtime": (f"python{floor}", *runtime),
        "tooling": (f"python{floor}", *tooling),
    }


def read_lock(path: Path) -> tuple[tuple[str, ...], tuple[Pin, ...]]:
    """The inputs a lock records, and the pins it carries."""
    recorded: list[str] = []
    pins: list[Pin] = []
    where = path.name
    for line in path.read_text(encoding="utf-8").splitlines():
        match = RECORDED_INPUT.match(line)
        if match is not None:
            recorded.append(match.group("requirement"))
            continue
        match = LOCKED_PIN.match(line)
        if match is not None:
            pins.append(
                Pin(
                    name=match.group("name"),
                    version=match.group("version"),
                    written_in=where,
                )
            )
    return tuple(recorded), tuple(pins)


def read_workflow_pins(root: Path) -> tuple[Pin, ...]:
    """Every distribution a workflow installs at a version written beside it."""
    pins: list[Pin] = []
    for workflow in sorted((root / ".github" / "workflows").glob("*.yml")):
        text = workflow.read_text(encoding="utf-8")
        versions = {
            match.group("variable"): match.group("version")
            for match in (WORKFLOW_VERSION.match(line) for line in text.splitlines())
            if match is not None
        }
        for match in WORKFLOW_INSTALL.finditer(text):
            version = versions.get(match.group("variable"))
            if version is None:
                # The variable is set somewhere this reader cannot see, so the
                # pin cannot be judged. Refusing here would refuse a shape
                # nobody has written; the blind spot is declared instead.
                continue
            pins.append(
                Pin(
                    name=match.group("name"),
                    version=version,
                    written_in=f".github/workflows/{workflow.name}",
                )
            )
    # Deduplicated. Two jobs in one file install the same pinned tool on
    # purpose, and reporting it twice would read as two pins to reconcile.
    return tuple(sorted(set(pins), key=lambda pin: (pin.written_in, pin.key)))


def read_acceptances(path: Path) -> tuple[Acceptance, ...]:
    """The acceptance register, whatever shape its entries are in.

    Nothing is dropped for being incomplete. An entry missing a field is read
    with that field empty so the refusal can name it, because silently skipping
    a malformed entry is how a register reports that it is clean.
    """
    if not path.exists():
        return ()
    with path.open("rb") as handle:
        register = tomllib.load(handle)
    where = path.name
    entries = register.get("acceptance", [])
    return tuple(
        Acceptance(
            advisory=str(entry.get("advisory", "")),
            distribution=str(entry.get("distribution", "")),
            date=str(entry.get("date", "")),
            reason=str(entry.get("reason", "")),
            where=where,
        )
        for entry in entries
    )


def scenario_from_the_tree(root: Path) -> Scenario:
    recorded: dict[str, tuple[str, ...]] = {}
    locked: dict[str, tuple[Pin, ...]] = {}
    for lock in sorted((root / LOCK_DIRECTORY).glob("*.lock")):
        inputs, pins = read_lock(lock)
        recorded[lock.stem] = inputs
        locked[lock.stem] = pins
    return Scenario(
        declared=declared_inputs(root),
        recorded=recorded,
        locked=locked,
        pins=read_workflow_pins(root),
        acceptances=read_acceptances(root / ACCEPTANCES),
    )


# --------------------------------------------------------------------------
# Reading a scenario written to be refused
# --------------------------------------------------------------------------

DECLARES = re.compile(r"^#\s*refusal:\s*(?P<id>[a-z0-9-]+)\s*$")


def scenario_from_a_sample(path: Path) -> tuple[str | None, Scenario]:
    """The refusal a sample names, and the scenario it describes."""
    declares = None
    for line in path.read_text(encoding="utf-8").splitlines():
        match = DECLARES.match(line)
        if match is not None:
            declares = match.group("id")
            break
    with path.open("rb") as handle:
        written = tomllib.load(handle)

    def pins_of(entries: Iterable[str], where: str) -> tuple[Pin, ...]:
        out = []
        for entry in entries:
            name, _, version = entry.partition("==")
            out.append(Pin(name=name, version=version, written_in=where))
        return tuple(out)

    locked = {
        name: pins_of(entries, f"{path.name}:{name}")
        for name, entries in written.get("locked", {}).items()
    }
    return declares, Scenario(
        declared={
            name: tuple(entries)
            for name, entries in written.get("declared", {}).items()
        },
        recorded={
            name: tuple(entries)
            for name, entries in written.get("recorded", {}).items()
        },
        locked=locked,
        pins=pins_of(written.get("pins", []), path.name),
        acceptances=tuple(
            Acceptance(
                advisory=str(entry.get("advisory", "")),
                distribution=str(entry.get("distribution", "")),
                date=str(entry.get("date", "")),
                reason=str(entry.get("reason", "")),
                where=path.name,
            )
            for entry in written.get("acceptance", [])
        ),
    )


# --------------------------------------------------------------------------
# The modes
# --------------------------------------------------------------------------


def say_what_this_reads() -> None:
    print(f"{len(KINDS)} refusal(s) in force:")
    for kind in KINDS:
        print(f"  {kind.id}  ({kind.issue})")
        print(f"      blind to {kind.blind_to}.")
    print()
    print(
        "Outside this check entirely: the build input set, which "
        "pyproject.toml declares as a range rather than a resolution and "
        "which issue #91 holds; and every version an install resolves on an "
        "interpreter above the declared floor, because both locks are "
        "resolved on the floor."
    )
    print()


def report(judgement: Judgement) -> int:
    for line in judgement.read:
        print(f"  {line}")
    print()
    for finding in judgement.findings:
        print(
            f"::error::{finding.kind.id}: {finding.subject}. "
            f"{finding.kind.refuses}. {finding.detail}",
            file=sys.stderr,
        )
    if judgement.findings:
        print(f"{len(judgement.findings)} refusal(s).", file=sys.stderr)
        return 1
    print("Nothing refused.")
    return 0


def check_the_tree() -> int:
    say_what_this_reads()
    scenario = scenario_from_the_tree(REPOSITORY_ROOT)
    if not any(scenario.locked.values()):
        print(
            f"::error::{LOCK_DIRECTORY} holds no pinned distribution. "
            "Refusing to report a clean dependency set from a run that read "
            "nothing.",
            file=sys.stderr,
        )
        return 1
    try:
        judgement = judge_a_scenario(scenario)
    except ServiceFailed as failure:
        print(
            f"::error::A service this check depends on could not be read: "
            f"{failure}. Both halves fail closed, so this is a refusal rather "
            "than an empty set of findings.",
            file=sys.stderr,
        )
        return 1
    return report(judgement)


def prove_every_refusal_bites() -> int:
    samples = sorted((REPOSITORY_ROOT / SCENARIOS).glob("*.toml"))
    if not samples:
        print(
            f"::error::{SCENARIOS} holds no scenario. Refusing to report that "
            "every refusal bites when none was tried.",
            file=sys.stderr,
        )
        return 1

    known = {kind.id for kind in KINDS}
    proved: set[str] = set()
    failures: list[str] = []

    for sample in samples:
        relative = sample.relative_to(REPOSITORY_ROOT).as_posix()
        declares, scenario = scenario_from_a_sample(sample)
        if declares is None:
            failures.append(
                f"{relative} names no refusal. Add a line reading "
                "`# refusal: <id>` so the proof says what it proves."
            )
            continue
        if declares not in known:
            failures.append(
                f"{relative} names refusal {declares}, which does not exist. "
                f"They are: {', '.join(sorted(known))}."
            )
            continue
        try:
            judgement = judge_a_scenario(scenario)
        except ServiceFailed as failure:
            failures.append(
                f"{relative} could not be judged: {failure}. A proof that "
                "could not run is not a proof that passed."
            )
            continue
        raised = sorted({finding.kind.id for finding in judgement.findings})
        if raised != [declares]:
            failures.append(
                f"{relative} names refusal {declares} and this run refused "
                f"{', '.join(raised) if raised else 'nothing'}. A scenario "
                "that refuses nothing proves no branch, and one that refuses "
                "something else proves the wrong branch."
            )
            continue
        proved.add(declares)
        print(f"{declares}: refused {relative}")

    unproved = sorted(known - proved)
    if unproved:
        failures.append(
            "These refusals are in force and no scenario under "
            f"{SCENARIOS} trips them: {', '.join(unproved)}. A refusal that "
            "has never been shown to bite is a branch nobody has taken."
        )

    for failure in failures:
        print(f"::error::{failure}", file=sys.stderr)
    if failures:
        return 1
    print(
        f"{len(known)} refusal(s), each tripped by a scenario that trips nothing else."
    )
    return 0


def resolve(requirements: list[str], floor: str) -> list[tuple[str, str]]:
    """Ask pip what the requirements resolve to on the declared floor."""
    with tempfile.TemporaryDirectory(prefix="blende-relock-") as scratch:
        report_path = Path(scratch) / "report.json"
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "--dry-run",
                "--quiet",
                "--ignore-installed",
                "--only-binary=:all:",
                "--python-version",
                floor,
                "--target",
                str(Path(scratch) / "target"),
                "--report",
                str(report_path),
                *requirements,
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode != 0:
            raise ServiceFailed(f"pip could not resolve: {completed.stderr.strip()}")
        answer = json.loads(report_path.read_text(encoding="utf-8"))
    return sorted(
        (entry["metadata"]["name"], entry["metadata"]["version"])
        for entry in answer["install"]
    )


def hashes_for(name: str, version: str) -> list[str]:
    """Every sha256 the index publishes for one release.

    Every file rather than the one this resolution picked. pip checks the
    artefact it chooses, and which artefact that is depends on the platform, so
    a lock carrying one wheel's digest installs on one runner and refuses on
    the next.
    """
    answer = read_json(
        urllib.request.Request(INDEX_RELEASE.format(name=name, version=version))
    )
    digests = sorted(
        entry["digests"]["sha256"]
        for entry in answer.get("urls", [])
        if entry.get("digests", {}).get("sha256")
    )
    if not digests:
        raise ServiceFailed(f"the index publishes no sha256 for {name} {version}")
    return digests


def relock() -> int:
    declared = declared_inputs(REPOSITORY_ROOT)
    with (REPOSITORY_ROOT / "pyproject.toml").open("rb") as handle:
        floor = tomllib.load(handle)["project"]["requires-python"].strip()
    bare_floor = floor.removeprefix(">=").strip()

    for name, inputs in declared.items():
        requirements = [entry for entry in inputs if not entry.startswith("python")]
        resolved = resolve(requirements, bare_floor)
        lines = [
            "# Resolved by tools/dependency_policy.py --relock. Not written by",
            "# hand: a version edited here is a version nothing resolved.",
            "#",
            "# The inputs below are what the tree declared when this ran. The",
            "# `deny` check refuses a lock whose inputs are no longer what the",
            "# tree declares, so this header is read rather than decoration.",
            "#",
        ]
        lines += [f"# resolved-from: {entry}" for entry in inputs]
        lines.append("")
        for distribution, version in resolved:
            digests = hashes_for(distribution, version)
            lines.append(f"{distribution}=={version} \\")
            lines += [f"    --hash=sha256:{digest} \\" for digest in digests[:-1]]
            lines.append(f"    --hash=sha256:{digests[-1]}")
        path = REPOSITORY_ROOT / LOCK_DIRECTORY / f"{name}.lock"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"{path.relative_to(REPOSITORY_ROOT).as_posix()}: {len(resolved)} pin(s)")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--prove",
        action="store_true",
        help="Run every scenario and refuse a refusal no scenario trips.",
    )
    mode.add_argument(
        "--relock",
        action="store_true",
        help="Re-resolve both sets and rewrite the locks. Needs pip.",
    )
    arguments = parser.parse_args(argv)

    sys.dont_write_bytecode = True

    if arguments.prove:
        return prove_every_refusal_bites()
    if arguments.relock:
        try:
            return relock()
        except ServiceFailed as failure:
            print(f"::error::{failure}", file=sys.stderr)
            return 1
    return check_the_tree()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
