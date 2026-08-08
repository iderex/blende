"""The environment report, and the four things it refuses.

Every case here builds a synthetic installed distribution in a temporary
directory and puts it on `PYTHONPATH`, so the real `importlib.metadata` does
the real lookup and nothing is stubbed out. That keeps the whole suite offline
and off the network, which issue #13 requires of the default suite: the only
path in this project that sends anything off the host is the timestamp
request, and a test that installed from an index would quietly make that
sentence false.

The distribution names other than `blende` itself are fixture names. They are
chosen so that no real install of anything can decide the result.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parent.parent
SOURCE = REPOSITORY / "src"

sys.path.insert(0, str(SOURCE))

from blende.environment import Requirement, Unplaceable, parse_requirement  # noqa: E402

# Absent from the metadata rather than empty in it: `Requires-Python:` with
# nothing after it and no such header at all are different defects, and only
# the second one is what a build that dropped the pin looks like.
NO_FLOOR = object()


def write_distribution(root, name, version, *, requires_python=">=3.11", requires=()):
    """Write the `.dist-info` an installer would have written.

    The directory carries the escaped name, dashes replaced by underscores,
    because that is what an installer writes and what `importlib.metadata`
    matches on. Writing the literal name here produced a directory that the
    lookup does not find, which would have made every absent-dependency case
    below pass for the wrong reason.
    """
    info = Path(root) / f"{name.replace('-', '_')}-{version}.dist-info"
    info.mkdir()
    lines = ["Metadata-Version: 2.1", f"Name: {name}", f"Version: {version}"]
    if requires_python is not NO_FLOOR:
        lines.append(f"Requires-Python: {requires_python}")
    lines.extend(f"Requires-Dist: {requirement}" for requirement in requires)
    (info / "METADATA").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return info


class ReportTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.TemporaryDirectory()
        self.addCleanup(self.root.cleanup)

    def report(self, *, on_path=True):
        environment = dict(os.environ)
        entries = [self.root.name] if on_path else []
        entries.append(str(SOURCE))
        environment["PYTHONPATH"] = os.pathsep.join(entries)
        return subprocess.run(
            [sys.executable, "-m", "blende"],
            capture_output=True,
            text=True,
            env=environment,
            cwd=str(REPOSITORY),
            check=False,
        )

    def test_it_names_the_interpreter_the_floor_and_every_resolved_dependency(self):
        write_distribution(
            self.root.name, "blende", "0.0.0", requires=["stand-in-array-library"]
        )
        write_distribution(self.root.name, "stand-in-array-library", "9.1.2")

        result = self.report()

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn(
            sys.implementation.name.replace("cpython", "CPython"), result.stdout
        )
        self.assertIn(
            ".".join(str(part) for part in sys.version_info[:3]), result.stdout
        )
        self.assertIn("declared interpreter floor: >=3.11", result.stdout)
        self.assertIn("required stand-in-array-library: 9.1.2", result.stdout)

    def test_an_optional_dependency_that_is_absent_is_named_and_the_run_passes(self):
        write_distribution(
            self.root.name,
            "blende",
            "0.0.0",
            requires=['stand-in-plotting-library; extra == "plots"'],
        )

        result = self.report()

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn(
            "optional [plots] stand-in-plotting-library: not installed", result.stdout
        )

    def test_a_required_dependency_that_is_absent_is_named_and_the_run_fails(self):
        write_distribution(
            self.root.name, "blende", "0.0.0", requires=["stand-in-array-library"]
        )

        result = self.report()

        self.assertNotEqual(0, result.returncode)
        self.assertIn("required stand-in-array-library: not installed", result.stdout)

    def test_metadata_declaring_no_interpreter_floor_is_refused(self):
        write_distribution(self.root.name, "blende", "0.0.0", requires_python=NO_FLOOR)

        result = self.report()

        self.assertNotEqual(0, result.returncode)
        self.assertIn("declares no interpreter floor", result.stderr)

    def test_a_requirement_carrying_a_marker_that_is_not_an_extra_is_refused(self):
        write_distribution(
            self.root.name,
            "blende",
            "0.0.0",
            requires=['stand-in-array-library; python_version < "3.12"'],
        )

        result = self.report()

        self.assertNotEqual(0, result.returncode)
        self.assertIn("cannot place", result.stderr)

    def test_a_checkout_with_nothing_installed_is_refused_rather_than_read_off_the_project_file(
        self,
    ):
        result = self.report(on_path=False)

        self.assertNotEqual(0, result.returncode)
        self.assertIn("is not installed", result.stderr)
        # The refusal has to stay a refusal. The project file is right there in
        # the working directory, and reporting numpy off it would produce a
        # report that looks exactly like a good one.
        self.assertNotIn("resolved dependency set", result.stdout)


class ParseRequirementTest(unittest.TestCase):
    def test_a_bare_name(self):
        self.assertEqual(
            Requirement("numpy", None, "numpy"), parse_requirement("numpy")
        )

    def test_a_version_specifier_is_not_part_of_the_name(self):
        self.assertEqual("numpy", parse_requirement("numpy>=2.4").name)
        self.assertEqual("numpy", parse_requirement("numpy (>=2.4)").name)
        self.assertEqual("numpy", parse_requirement("numpy [extra-of-its-own]").name)

    def test_an_extras_marker_places_the_requirement_under_its_extra(self):
        parsed = parse_requirement('matplotlib>=3.6; extra == "plots"')
        self.assertEqual("matplotlib", parsed.name)
        self.assertEqual("plots", parsed.extra)

    def test_a_marker_that_is_not_an_extra_is_refused(self):
        with self.assertRaises(Unplaceable):
            parse_requirement('tomli; python_version < "3.11"')

    def test_a_marker_carrying_more_than_an_extra_is_refused(self):
        with self.assertRaises(Unplaceable):
            parse_requirement(
                'matplotlib; extra == "plots" and python_version < "3.12"'
            )

    def test_a_line_with_no_readable_name_is_refused(self):
        with self.assertRaises(Unplaceable):
            parse_requirement(">=2.4")


if __name__ == "__main__":
    unittest.main()
