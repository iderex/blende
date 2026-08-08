"""Deterministic blinding for precision measurement.

Nothing is exported yet. The package exists at this commit so that the
decision in issue #1 is a fact about an installable distribution rather than a
sentence in a document: the floor it claims, the single required dependency,
and an environment report that says what an install of it resolved to.

Importing this package imports the standard library and nothing else, and that
holds for the environment report as well. numpy is required because the data
path is arrays, and the modules that use it are the ones that have not landed.
"""

__all__: list[str] = []
