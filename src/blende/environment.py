"""What this environment resolved blende's declarations to.

A dependency set is a property of an installed distribution in an environment,
not of a project file. The two disagree exactly when it matters: an install
that did not do what the file said, a name that resolved to a different
version, a package the environment was assumed to already carry. So everything
below is read out of the installed metadata through `importlib.metadata`, and
the project file is never read at runtime.

Four things are refused instead of guessed. Each one exists because the
alternative is a report that reads like an environment with nothing wrong with
it:

  * no installed distribution at all, which is what running from a source
    checkout looks like. Falling back to the project file there would print
    what somebody wrote and label it what the interpreter resolved;
  * metadata that declares no interpreter floor, which is a distribution
    claiming to install on every interpreter that will ever exist. Issue #1
    requires the floor to be pinned, and this is the reading that refuses a
    build where it went missing;
  * a required dependency that is not installed. Dropping it from the listing
    would turn an incomplete environment into a clean report;
  * a requirement line this module cannot place. It reports the set it
    resolved, so a line it could not read may not be silently absent from that
    set.

The listing is the declared dependencies of this distribution and the version
each one resolved to here. It is not the transitive closure of the install,
which is a different question and one `pip` already answers.
"""

from __future__ import annotations

import platform
import re
import sys
from dataclasses import dataclass
from importlib import metadata

DISTRIBUTION = "blende"

# A PEP 508 requirement string starts with the distribution name and ends it at
# the first character that can begin a version specifier, an extras list, a
# parenthesised specifier, an environment marker or a separator.
_NAME_END = " \t\r\n<>=!~^([;,"

_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

# The only environment marker this module reads. An extras marker selects a
# requirement that an install pulls in only when the extra was asked for, which
# is a fact about the declaration. Every other marker is a condition on the
# environment, and deciding whether it holds is evaluating a marker language
# the standard library does not implement.
_EXTRA_MARKER = re.compile(r"""^\(?\s*extra\s*==\s*(["'])([A-Za-z0-9._-]+)\1\s*\)?$""")


class Unplaceable(Exception):
    """A declared requirement this module will not guess at."""


@dataclass(frozen=True)
class Requirement:
    """One `Requires-Dist` line, reduced to what the report says about it."""

    name: str
    extra: str | None
    declaration: str


def parse_requirement(declaration: str) -> Requirement:
    """Read one `Requires-Dist` line, or refuse it.

    Refusing is the point. A line carrying a marker other than an extra is a
    conditionally required dependency, and reporting it as required or as
    optional would both be wrong without evaluating the marker.
    """
    text = declaration.strip()
    head, sep, marker = text.partition(";")

    name = head.strip()
    for index, character in enumerate(name):
        if character in _NAME_END:
            name = name[:index]
            break
    name = name.strip()
    if not _NAME.match(name):
        raise Unplaceable(f"no distribution name could be read from {declaration!r}")

    extra: str | None = None
    if sep:
        match = _EXTRA_MARKER.match(marker.strip())
        if match is None:
            raise Unplaceable(
                f"{declaration!r} carries an environment marker that is not an "
                "extra, and this report does not evaluate markers"
            )
        extra = match.group(2)

    return Requirement(name=name, extra=extra, declaration=text)


def declared_requirements(distribution: metadata.Distribution) -> list[Requirement]:
    """Every `Requires-Dist` line of an installed distribution, in order."""
    return [parse_requirement(line) for line in distribution.requires or ()]


def installed_version(name: str) -> str | None:
    """The version `name` resolved to here, or `None` if it resolved to nothing."""
    try:
        return metadata.version(name)
    except metadata.PackageNotFoundError:
        return None


def _interpreter() -> str:
    return f"{platform.python_implementation()} {platform.python_version()}"


def main(argv: list[str] | None = None) -> int:
    """Print the report. Returns the exit status; nothing here raises for it."""
    del argv  # No options. Issue #84 owns the command line this is not.

    try:
        distribution = metadata.distribution(DISTRIBUTION)
    except metadata.PackageNotFoundError:
        print(
            f"{DISTRIBUTION} is not installed for {sys.executable}.",
            file=sys.stderr,
        )
        print(
            "A dependency set is what an install resolved, so a source "
            "checkout has nothing to report. Install the project and run this "
            "again.",
            file=sys.stderr,
        )
        return 2

    version = distribution.metadata["Version"]
    floor = distribution.metadata["Requires-Python"]

    lines = [
        f"{DISTRIBUTION} {version}",
        f"running interpreter: {_interpreter()}",
    ]

    failed = False

    if not floor:
        print(
            f"{DISTRIBUTION} {version} declares no interpreter floor. The "
            "oldest supported interpreter is pinned in the package metadata, "
            "and this install carries no such pin.",
            file=sys.stderr,
        )
        failed = True
    else:
        lines.append(f"declared interpreter floor: {floor}")

    try:
        requirements = declared_requirements(distribution)
    except Unplaceable as refusal:
        print(
            f"{DISTRIBUTION} {version} declares a requirement this report "
            f"cannot place: {refusal}",
            file=sys.stderr,
        )
        for line in lines:
            print(line)
        return 1

    lines.append("resolved dependency set:")
    if not requirements:
        lines.append("  (nothing declared)")
    for requirement in requirements:
        where = "required" if requirement.extra is None else f"optional [{requirement.extra}]"
        resolved = installed_version(requirement.name)
        if resolved is None:
            lines.append(f"  {where} {requirement.name}: not installed")
            if requirement.extra is None:
                failed = True
        else:
            lines.append(f"  {where} {requirement.name}: {resolved}")

    for line in lines:
        print(line)

    if failed:
        print(
            "This environment does not satisfy what the distribution declares. "
            "The lines above say which part.",
            file=sys.stderr,
        )
        return 1
    return 0
