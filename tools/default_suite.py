"""The default suite, the guards it runs under, and the suites it does not run.

Issue #23 asks for a check named `test` that runs the default suite and
nothing else, and that fails a default-suite test doing any of the three
things issue #12 forbids: binding a socket, reaching the network, or writing
outside its own temporary directory. The guard is here rather than in a
reviewer's head, because a test that reaches the network passes on a developer
machine, fails in a runner, and sometimes passes in both while depending on
somebody else's service.

Three modes.

    python tools/default_suite.py
        Fixes the temporary directory, installs the guards, discovers and runs
        `tests/`, and prints which opt-in suites did not run and what running
        each would need. Zero failures is the expected result and is what every
        commit on the default branch has to produce.

    python tools/default_suite.py --prove
        Reads `tests/harness-regressions/`, where every guard has a sample
        written to trip it. Each sample names the guard it is for on a line of
        its own. The mode refuses a guard no sample trips, a sample naming a
        guard that does not exist, a sample that ran to completion instead of
        being refused, and a sample refused by a guard other than the one it
        names. A guard that has never been shown to bite is a branch nobody has
        taken, and this is what stops one shipping.

    python tools/default_suite.py --run-sample PATH
        What `--prove` spawns per sample. Installs the guards and executes the
        sample, so the sample meets the same guards a default-suite test meets
        rather than a copy of them written for the proof.

The means is Python from the standard library, run under the interpreter the
package metadata already declares. `unittest` discovers and runs the suite and
`sys.addaudithook` carries the guards, so the check adds no dependency to a
repository whose one required dependency is numpy. An audit hook is what the
interpreter offers here that a wrapper around `socket` and `open` does not: it
cannot be removed once installed, and it sees the operation rather than the
name a test imported it under, so a test reaching `os.open` directly meets the
same refusal as one calling `open`.

What the guards do not reach is written at each guard rather than in a
document beside them. The largest residual is shared by all three: an audit
hook holds for the process it is installed in, and a child process is not that
process. `tests/test_environment.py` spawns interpreters on purpose, and what
those children do is outside every refusal below.
"""

from __future__ import annotations

import argparse
import os
import re
import runpy
import subprocess
import sys
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent

# The default suite. One directory, discovered by the standard pattern, so a
# module is in the suite because of where it sits and what it is called rather
# than because somebody remembered a marker.
DEFAULT_SUITE = "tests"

# Where the samples live. They are written to be refused, so the default suite
# has to skip them or the run is red by construction. Discovery reads `test*.py`
# and no sample is named that way, which is the same arrangement the lint gate
# uses for `tests/lint-regressions`.
#
# They are not under `tests/fixtures/`. That directory is declared binary in
# `.gitattributes` and every file in it carries a recorded digest, which is the
# contract for bytes whose exactness is the point. A sample here is read as
# text and is edited whenever the guard it proves is revisited.
SAMPLES = "tests/harness-regressions"

# The line a sample uses to say which guard it is for, written as a comment so
# the sample is still a readable module.
DECLARES = re.compile(r"^#\s*guard:\s*(?P<id>[a-z0-9-]+)\s*$")


@dataclass(frozen=True)
class Guard:
    """One forbidden action, what refusing it prevents, and what it misses."""

    id: str
    # The issue that asked for this guard, so a reader can argue with the
    # decision rather than with the hook.
    issue: str
    # What a refusal means, printed when the guard bites.
    refusal: str
    # The residual, at the guard rather than in a document beside it.
    blind_to: str


BINDS_A_SOCKET = Guard(
    id="binds-a-socket",
    issue="#12",
    refusal=(
        "a default-suite test bound a socket. On a Windows host a bind off "
        "loopback raises a firewall dialog only an administrator can answer, "
        "which turns one test into a prompt nobody sees in a pipeline"
    ),
    blind_to=(
        "a socket created and never bound or connected, which reaches nothing "
        "and is left alone, and a bind performed inside a child process or by "
        "an extension module that raises no audit event"
    ),
)

REACHES_THE_NETWORK = Guard(
    id="reaches-the-network",
    issue="#13",
    refusal=(
        "a default-suite test reached the network. The only path in this "
        "project that sends anything off the host is the timestamp request, "
        "and it has an opt-in suite of its own"
    ),
    blind_to=(
        "a connection opened by a child process, and a name resolved through "
        "a cache the interpreter never asks the network for. A test that "
        "passes because the answer was cached is a test that fails on a "
        "machine where it is not"
    ),
)

WRITES_OUTSIDE_THE_TEMPORARY_DIRECTORY = Guard(
    id="writes-outside-the-temporary-directory",
    issue="#12",
    refusal=(
        "a default-suite test wrote outside the temporary directory this run "
        "fixed. A suite that leaves files behind is a suite whose second run "
        "reads the first one's output"
    ),
    blind_to=(
        "a write from a child process, a write through a file descriptor "
        "opened before this hook was installed, a path given relative to a "
        "directory descriptor, which this hook cannot name and passes over, "
        "and a path resolved by string rather than by following every symlink "
        "on it. Reads are not touched: the suite reads the tracked tree on "
        "purpose"
    ),
)

GUARDS: tuple[Guard, ...] = (
    BINDS_A_SOCKET,
    REACHES_THE_NETWORK,
    WRITES_OUTSIDE_THE_TEMPORARY_DIRECTORY,
)


@dataclass(frozen=True)
class OptIn:
    """A suite the default run does not run, named for what it needs."""

    id: str
    issue: str
    # What running it would need, in the words a contributor can act on.
    needs: str


# The three suites separated out of the default run. Issue #12 sets out the
# split and issue #13 says what the two hardware-adjacent ones are. The set is
# here rather than derived from whichever directories happen to exist, because
# a print derived from the tree says nothing about a suite nobody has written
# yet, and a suite nobody has written yet is exactly the one a reader of a
# green run would otherwise assume had passed.
OPT_IN_SUITES: tuple[OptIn, ...] = (
    OptIn(
        id="needs-a-key-outside-the-process",
        issue="#13",
        needs=(
            "a smartcard or a hardware security module present on the host, "
            "with the blinding key already loaded onto it. Neither this suite "
            "nor its default-suite counterpart is written: the key module "
            "takes material and hands it back, so there is no interface for a "
            "device to sit behind, and issue #4 is where one arrives. Once it "
            "does, the default suite covers it with a software implementation "
            "that defines the result and this suite proves the device path "
            "only"
        ),
    ),
    OptIn(
        id="needs-a-network-timestamp-authority",
        issue="#13",
        needs=(
            "a network connection and an authority to contact, which is the "
            "one path in this project that sends anything off the host. "
            "Neither this suite nor the recorded exchange that would stand in "
            "for it is written, so the parsing and the verification are "
            "uncovered here as well as the connection. Once the recording "
            "lands in the default suite, the connection is what is left"
        ),
    ),
    OptIn(
        id="needs-minutes-rather-than-seconds",
        issue="#12",
        needs=(
            "minutes of runtime rather than seconds, for the property runs "
            "and the large synthetic datasets. It is separated for cost and "
            "not for a resource the runner lacks"
        ),
    ),
)


class Refused(Exception):
    """A default-suite test did something the split forbids."""

    def __init__(self, guard: Guard, detail: str) -> None:
        super().__init__(f"{guard.id}: {guard.refusal}. {detail}")
        self.guard = guard


# The events the hook answers for, grouped by the guard that answers for them.
# Everything else is passed over on the first comparison, which matters: an
# audit hook is called for every import, call and compile in the process.
SOCKET_BIND = "socket.bind"
SOCKET_CONNECT = "socket.connect"
SOCKET_RESOLVE = "socket.getaddrinfo"
FILE_OPEN = "open"

# One row per event the network guards refuse: the guard that answers for it,
# the position of the argument naming what it reached, and how to say so.
#
# A table rather than a chain of comparisons, for two reasons found by taking
# the chain apart. Written as a chain with a set beside it, an event whose own
# branch was deleted fell through to the write guard and was refused as a stray
# write naming a host as its path. Written as a chain with a catch-all instead,
# deleting one branch left the catch-all refusing under the same guard id, so
# the samples stayed green and no arm could be proved on its own. Here the set
# of watched events is the keys, so deleting a row stops the event being
# watched at all, the sample for it runs to completion, and `--prove` says
# which arm went.
NETWORK_ARMS: dict[str, tuple[Guard, int, str]] = {
    SOCKET_BIND: (BINDS_A_SOCKET, 1, "The address was {reached!r}."),
    SOCKET_CONNECT: (REACHES_THE_NETWORK, 1, "The address was {reached!r}."),
    SOCKET_RESOLVE: (REACHES_THE_NETWORK, 0, "The name was {reached!r}."),
}

# One row per event the write guard reads: the position of the argument
# carrying the path it acts on, and the position of the directory descriptor
# that path may be relative to.
#
# The second number is not decoration. `shutil.rmtree` walks a tree by
# descriptor and calls `os.unlink(name, dir_fd=fd)` with a bare entry name, so
# a hook resolving that name against the working directory names a file in the
# checkout that nothing touched. Read against the working directory, the
# cleanup of this run's own temporary directory was refused as a write into the
# tracked tree, on a runner and not on the machine the guard was written on,
# because the same call on Windows does not take the descriptor route.
#
# Where a path arrives relative to a descriptor it is passed over rather than
# resolved, and the write guard says so. Naming the directory behind a
# descriptor means reading `/proc`, which is one operating system's answer to a
# question the others answer differently, and a guard that refuses more on
# Linux than on Windows is the failure this whole check exists to prevent read
# backwards.
#
# `shutil.rmtree` is watched for exactly that reason: the descriptor walk is
# invisible to this hook, so the call that starts it is read instead, where the
# path is still whole.
AT_FDCWD = getattr(os, "AT_FDCWD", -100)
PATH_EVENTS: dict[str, tuple[int, int | None]] = {
    "os.mkdir": (0, 2),
    # The destination rather than the source. A test moving a file into the
    # tracked tree is the direction that leaves something behind.
    "os.rename": (1, 3),
    "os.remove": (0, 1),
    "os.rmdir": (0, 1),
    "os.symlink": (1, 2),
    "os.link": (1, 3),
    "os.truncate": (0, None),
    "shutil.rmtree": (0, 1),
}


def argument(args: tuple[object, ...], position: int | None) -> object:
    """One argument of an audit event, or None where it was not passed.

    The tuple an event carries has grown between interpreter versions:
    `shutil.rmtree` gained its directory descriptor in 3.12 and this package
    supports 3.11. Reading by position with a length check keeps the table
    above one table rather than one per version.
    """
    if position is None or position >= len(args):
        return None
    return args[position]


# A mode string carrying any of these opens the file for writing. `+` is in the
# set because `r+` writes.
WRITE_MODES = frozenset("wax+")

# The same question asked of the integer flags `os.open` takes. O_RDONLY is
# zero, so a read trips none of these.
WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_TRUNC


def opens_for_writing(mode: object, flags: object) -> bool:
    """Whether an `open` event is a write.

    The event carries the mode string when `builtins.open` raised it and the
    integer flags when `os.open` did, and either can be absent. Both are read
    rather than one, because a test reaching `os.open` directly is the case a
    guard written against the mode string alone would miss.
    """
    if isinstance(mode, str) and set(mode) & WRITE_MODES:
        return True
    return isinstance(flags, int) and bool(flags & WRITE_FLAGS)


def install_guards(sandbox: Path) -> None:
    """Install the three refusals for the rest of this process.

    An audit hook cannot be removed once added, which is the property wanted
    here: a test cannot turn the guard off, and neither can a library it
    imports.
    """
    permitted = tuple({os.path.abspath(str(sandbox)), os.path.realpath(str(sandbox))})
    devnull = os.path.abspath(os.devnull)

    def outside_the_sandbox(path: object) -> str | None:
        """The absolute path, or None where this hook may not judge it.

        A file descriptor rather than a path is passed over. `open` raises the
        event with the descriptor when a caller reopens one, and a descriptor
        that already exists was judged when it was opened, or was inherited,
        which is the residual the write guard declares.
        """
        if not isinstance(path, (str, bytes, os.PathLike)):
            return None
        resolved = os.path.abspath(os.fsdecode(path))
        if resolved == devnull:
            return None
        for root in permitted:
            if resolved == root or resolved.startswith(root + os.sep):
                return None
        return resolved

    def audit(event: str, args: tuple[object, ...]) -> None:
        arm = NETWORK_ARMS.get(event)
        if arm is not None:
            guard, position, detail = arm
            raise Refused(guard, detail.format(reached=args[position]))
        if event == FILE_OPEN:
            path, mode, flags = args
            if not opens_for_writing(mode, flags):
                return
        elif event in PATH_EVENTS:
            position, descriptor = PATH_EVENTS[event]
            relative_to = argument(args, descriptor)
            if isinstance(relative_to, int) and relative_to != AT_FDCWD:
                # Relative to a directory this hook cannot name. Passed over
                # rather than guessed at, and declared by the guard.
                return
            path = argument(args, position)
        else:
            return
        stray = outside_the_sandbox(path)
        if stray is not None:
            raise Refused(
                WRITES_OUTSIDE_THE_TEMPORARY_DIRECTORY,
                f"The path was {stray}, and {event} was the operation. "
                f"The directory this run fixed is {sandbox}.",
            )

    sys.addaudithook(audit)


def fix_the_temporary_directory(sandbox: Path) -> None:
    """Point every route to a temporary file at one directory.

    Three routes rather than one. `tempfile` reads the environment the first
    time it is asked and caches the answer, a child process reads the
    environment for itself, and a test that reads `TMPDIR` by hand reads the
    environment too. Setting the module attribute alone would leave the second
    and third pointing at the host's default.
    """
    for name in ("TMPDIR", "TEMP", "TMP"):
        os.environ[name] = str(sandbox)
    tempfile.tempdir = str(sandbox)


def announce_the_suites_that_did_not_run() -> None:
    """Say what a green run did not cover, and what covering it would need."""
    print()
    print(
        f"{len(OPT_IN_SUITES)} opt-in suite(s) did not run here. A green "
        "default run is not a run that covered everything:"
    )
    for suite in OPT_IN_SUITES:
        print(f"  {suite.id}  ({suite.issue})")
        print(f"      needs {suite.needs}.")
    print(
        "  None of the three has a test in it yet, so this print is what the "
        "default run does not cover rather than a report on work that was "
        "skipped."
    )


def run_the_default_suite(sandbox: Path) -> int:
    """Discover and run `tests/` under the guards."""
    fix_the_temporary_directory(sandbox)
    print(f"Temporary directory fixed at {sandbox}.")
    print(f"{len(GUARDS)} guard(s) installed for this process:")
    for guard in GUARDS:
        print(f"  {guard.id}  ({guard.issue})")
        print(f"      blind to {guard.blind_to}.")
    print()

    install_guards(sandbox)
    discovered = unittest.defaultTestLoader.discover(
        str(REPOSITORY_ROOT / DEFAULT_SUITE)
    )
    result = unittest.TextTestRunner(verbosity=2).run(discovered)
    announce_the_suites_that_did_not_run()
    return 0 if result.wasSuccessful() else 1


def declared_guard(path: Path) -> str | None:
    """The guard a sample names, read from its own text."""
    for line in path.read_text(encoding="utf-8").splitlines():
        match = DECLARES.match(line)
        if match is not None:
            return match.group("id")
    return None


def run_one_sample(path: Path) -> int:
    """Execute a sample under the guards, and report which one refused it.

    The sample runs in this process after the hook is installed, so it meets
    the guards a default-suite test meets. It is spawned rather than imported
    by `--prove` for the same reason: the hook cannot be removed, so one
    process can carry exactly one sample.
    """
    with tempfile.TemporaryDirectory(prefix="blende-sample-") as scratch:
        sandbox = Path(scratch)
        fix_the_temporary_directory(sandbox)
        install_guards(sandbox)
        try:
            runpy.run_path(str(path), run_name="__main__")
        except Refused as refusal:
            print(refusal.guard.id)
            print(refusal, file=sys.stderr)
            return 1
    print(f"{path} ran to completion and no guard refused it.", file=sys.stderr)
    return 0


def prove_every_guard_bites() -> int:
    """Refuse a guard no sample trips, and a sample that no longer trips one."""
    samples = sorted((REPOSITORY_ROOT / SAMPLES).glob("*.py"))
    if not samples:
        print(
            f"::error::{SAMPLES} holds no sample. Refusing to report that "
            "every guard bites when none was tried.",
            file=sys.stderr,
        )
        return 1

    known = {guard.id: guard for guard in GUARDS}
    proved: set[str] = set()
    failures: list[str] = []

    for sample in samples:
        relative = sample.relative_to(REPOSITORY_ROOT).as_posix()
        declares = declared_guard(sample)
        if declares is None:
            failures.append(
                f"{relative} names no guard. Add a line reading "
                f"`# guard: <id>` so the proof says what it proves."
            )
            continue
        if declares not in known:
            failures.append(
                f"{relative} names guard {declares}, which does not exist. "
                f"The guards are: {', '.join(sorted(known))}."
            )
            continue

        # A separate process per sample. The hook the sample has to meet
        # cannot be uninstalled, so a second sample in the same process would
        # be judged by a guard the first one already tripped.
        completed = subprocess.run(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                "--run-sample",
                str(sample),
            ],
            capture_output=True,
            text=True,
            check=False,
            cwd=str(REPOSITORY_ROOT),
        )
        if completed.returncode == 0:
            failures.append(
                f"{relative} names guard {declares} and ran to completion. A "
                f"sample that stopped being refused is a guard nobody is "
                f"proving. Output: {completed.stdout.strip()!r}"
            )
            continue
        refused_by = completed.stdout.strip().splitlines()
        if not refused_by or refused_by[-1] != declares:
            failures.append(
                f"{relative} names guard {declares} and was refused by "
                f"{refused_by[-1] if refused_by else 'nothing this mode could read'}. "
                f"A sample refused by the wrong guard proves the wrong thing. "
                f"Detail: {completed.stderr.strip()!r}"
            )
            continue
        proved.add(declares)
        print(f"{declares}: refused {relative}")

    # The same statement read a second way. Every sample above was refused
    # before it could act, so the directory it ran from holds the samples and
    # nothing else. A file left behind means a guard reported a refusal after
    # the operation it was refusing had already happened.
    residue = sorted(
        entry.name
        for entry in (REPOSITORY_ROOT / SAMPLES).iterdir()
        if entry.suffix != ".py"
    )
    if residue:
        failures.append(
            f"{SAMPLES} holds {', '.join(residue)} after the run. A refusal "
            "that arrives once the write has happened is a report rather than "
            "a guard."
        )

    unproved = sorted(set(known) - proved)
    if unproved:
        failures.append(
            "These guards are installed and no sample under "
            f"{SAMPLES} trips them: {', '.join(unproved)}. A guard that has "
            "never been shown to bite is a branch nobody has taken."
        )

    for failure in failures:
        print(f"::error::{failure}", file=sys.stderr)
    if failures:
        return 1
    print(f"{len(known)} guard(s), each tripped by a sample.")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--prove",
        action="store_true",
        help="Run every sample and refuse a guard no sample trips.",
    )
    mode.add_argument(
        "--run-sample",
        metavar="PATH",
        help="Execute one sample under the guards. What --prove spawns.",
    )
    arguments = parser.parse_args(argv)

    # Before anything imports a test module. A written bytecode cache is a
    # write into the tracked tree, and the guard would refuse the suite for
    # something the interpreter did rather than something a test did.
    sys.dont_write_bytecode = True

    if arguments.prove:
        return prove_every_guard_bites()
    if arguments.run_sample:
        return run_one_sample(Path(arguments.run_sample).resolve())

    with tempfile.TemporaryDirectory(prefix="blende-default-suite-") as scratch:
        return run_the_default_suite(Path(scratch))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
