"""What the tracked project file declares.

This reads this repository's own `pyproject.toml`, so it proves the state of
the tree on the day it runs rather than proving a guard. That is deliberate and
it is the point: issue #1 decides that the floor is pinned and that numpy is
the only required runtime dependency, and a decision nothing reads back is a
sentence. A plotting library added to `dependencies` in a hurry, or a floor
deleted while somebody was making an install work, both redden here.

The reader is `tomllib`, in the standard library from 3.11, which is the floor
the file itself declares. No dependency is added to check a file whose subject
is that the package has one dependency.
"""

from __future__ import annotations

import tomllib
import unittest
from pathlib import Path

PROJECT_FILE = Path(__file__).resolve().parent.parent / "pyproject.toml"


class ProjectMetadataTest(unittest.TestCase):
    def setUp(self):
        with PROJECT_FILE.open("rb") as handle:
            self.pyproject = tomllib.load(handle)
        self.project = self.pyproject["project"]

    def test_the_oldest_supported_interpreter_is_pinned(self):
        floor = self.project.get("requires-python", "")
        self.assertTrue(
            floor.strip(),
            "requires-python is what says which interpreters this claims to "
            "install on. Absent, the claim is every interpreter that will ever "
            "exist.",
        )

    def test_numpy_is_the_only_required_runtime_dependency(self):
        self.assertEqual(
            ["numpy"],
            self.project.get("dependencies"),
            "Anything else here is installed by everybody, including the batch "
            "job on a compute node and the environment whose analysis this "
            "package exists to be imported into.",
        )

    def test_no_plotting_library_is_required(self):
        # Named rather than pattern-matched. The failure this catches is a
        # backend moved out of an extra and into the required set, and the
        # backends are a short list somebody reads.
        required = " ".join(self.project.get("dependencies", [])).lower()
        for backend in (
            "matplotlib",
            "plotly",
            "bokeh",
            "seaborn",
            "altair",
            "pyqtgraph",
        ):
            self.assertNotIn(
                backend,
                required,
                f"{backend} is a plotting library and belongs behind an extra.",
            )


if __name__ == "__main__":
    unittest.main()
