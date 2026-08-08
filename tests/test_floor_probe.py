"""A module using a standard library call newer than the floor, to prove the
check red.

Issue #25 asks for a commit using a construct newer than the floor to prove the
`oldest supported build` check red on the runner rather than only described as
able to catch one. `itertools.batched` arrived in 3.12 and the declared floor is
3.11, so this module imports and runs on a current interpreter and fails on the
one the metadata promises. That is the whole shape of the failure the check
exists for: nobody decides to break a floor, somebody writes what their own
interpreter offers.

The commit after this one removes it and the same job goes green. Both runs are
linked from the pull request body.
"""

from __future__ import annotations

import unittest
from itertools import batched


class FloorProbeTest(unittest.TestCase):
    def test_a_call_that_does_not_exist_on_the_floor(self):
        self.assertEqual([(1, 2), (3, 4)], list(batched([1, 2, 3, 4], 2)))


if __name__ == "__main__":
    unittest.main()
