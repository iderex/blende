"""`python -m blende` prints the environment report and nothing else.

There is no console script. A command line is issue #84 and it is not this;
the module entry point exists so that the report can be run from an install
without one.
"""

from __future__ import annotations

import sys

from blende.environment import main

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
