"""This repository's text-level invariants, one rule per invariant.

Issue #28 asks for a check that enforces the rules other issues owe it, as
patterns over tracked text rather than as a language parser, so the answer is
deterministic and the run stays cheap. Each rule below names the issue that
asked for it and the failure it prevents.

Two modes, and the second is the reason the first is worth anything.

    python tools/greppable_invariants.py
        Reads the tracked tree and refuses a match. Zero findings is the
        expected result and is what every commit on the default branch has to
        produce.

    python tools/greppable_invariants.py --prove
        Reads `tests/invariant-regressions/`, where every rule has a sample
        written to trip it. Each sample names the rule it is for on a line of
        its own. The mode refuses a rule no sample trips, a sample naming a
        rule that does not exist, and a sample that has stopped tripping the
        rule it names. A rule that has never been shown to bite is a pattern in
        a file, and this is what stops one shipping.

The means is Python from the standard library, run under the interpreter the
package metadata already declares. Two of the rules ask whether a module is in
the standard library, and the interpreter answers that from
`sys.stdlib_module_names` rather than from a list somebody pastes into this
tree and then has to maintain against a version of the language. The two guards
already here are shell, and shell was the right means for them because their
whole subject is what git does to bytes; it is the wrong means for a rule whose
subject is a set the interpreter holds.

Rules are patterns and they are honest about it. Where a rule cannot see the
whole of the invariant it names, the part it cannot see is written in the rule
rather than left for somebody to find out. Three invariants issue #28 lists are
not rules here at all, and the issue is where each one is recorded with the
reason.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tomllib
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent

# Where the samples live. They are written to be refused, so the tree scan has
# to skip them or the check is red by construction, and `--prove` reads them by
# naming this directory rather than by walking into it from anywhere else.
#
# They are not under `tests/fixtures/`. That directory is declared binary in
# `.gitattributes` and every file in it carries a recorded digest, which is the
# contract for bytes whose exactness is the point. A sample here is read as
# text, and is edited whenever the rule it proves is revisited.
SAMPLES = "tests/invariant-regressions"

# The line a sample uses to say which rule it is for. Written as a comment so
# the sample is still a readable file of whatever kind the rule reads, and `#`
# starts a comment in both of the kinds here.
DECLARES = re.compile(r"^#\s*invariant:\s*(?P<id>[a-z0-9-]+)\s*$")


@dataclass(frozen=True)
class Rule:
    """One invariant, the paths it reads, and what it cannot see."""

    id: str
    # The issue that asked for this rule, so a reader can go and argue with the
    # decision rather than with the pattern.
    issue: str
    # What a match means, printed on a finding.
    refusal: str
    # Which tracked paths the rule reads. A rule that reads a directory this
    # tree does not have yet is deliberate: the invariant is declared before
    # the layer it constrains exists, which is the whole shape of milestone 01.
    scope: tuple[str, ...]
    # The residual. What the pattern does not reach, in the rule rather than in
    # a document beside it.
    blind_to: str
    # Which file suffixes the rule reads inside its scope. Almost every rule
    # here is about this package's own source, and the default says so. A rule
    # whose subject is the workflow files has to say otherwise, because a walk
    # that assumed Python would skip every file such a rule exists to read and
    # would report a clean tree for a rule that never looked at anything.
    suffixes: tuple[str, ...] = (".py",)
    patterns: tuple[re.Pattern[str], ...] = ()


# A plain double-quoted string on one line, which is what an output template
# looks like in source. The lookarounds hold the rules that read templates to
# templates: a quote that touches another quote belongs to a docstring, and a
# docstring is prose. That distinction is the reason these rules can refuse a
# word in what the package prints while the same word stays available to the
# sentence explaining what the package does not do.
PLAIN_STRING = re.compile(r'(?<!")"(?!")(?P<text>[^"\n]*)"(?!")')

RULES: tuple[Rule, ...] = (
    Rule(
        id="contract-imports-stdlib-only",
        issue="#20",
        refusal=("the contract layer imports something outside the standard library"),
        scope=("src/blende/contract/",),
        blind_to=(
            "an import performed at run time through importlib, and a module "
            "reached by a name this pattern reads as standard library because "
            "a file in the tree shadows one. The lint gate's A005 covers the "
            "second."
        ),
    ),
    Rule(
        id="core-imports-required-only",
        issue="#20",
        refusal=(
            "the core layer imports at module level something that is neither "
            "the standard library, nor a required dependency, nor this package"
        ),
        scope=("src/blende/core/",),
        blind_to=(
            "an import inside a function, which is the form this rule exists "
            "to leave available: a compute node with no plotting stack has to "
            "be able to import the package and blind a value, and an import "
            "that happens when the adapter is called does not stop it."
        ),
    ),
    Rule(
        id="no-vocabulary-of-protection",
        issue="#15",
        refusal=(
            "an output template or a public name says protect, secure or "
            "encrypt, and blinding is none of those things"
        ),
        scope=("src/",),
        blind_to=(
            "a docstring, on purpose. The documents have to be able to say "
            "what this package does not do, and a rule that refused the word "
            "everywhere would refuse the disclaimer along with the claim. Also "
            "a template built by joining two strings, where the word arrives "
            "from a name rather than from a literal."
        ),
        patterns=(
            re.compile(r"^\s*(?:def|class)\s+\w*(?:protect|secure|encrypt)", re.I),
        ),
    ),
    Rule(
        id="no-blinding-string-literal",
        issue="#4",
        refusal=(
            "a blinding string, a key or a nonce is written as a literal in a "
            "tracked file, and a secret in the tree is a secret everybody with "
            "the tree holds"
        ),
        scope=("src/", "tests/"),
        blind_to=(
            "a long literal passed positionally into a call, where nothing on "
            "the line says what the value is. Matched by the shape of a name "
            "bound to a literal rather than by the entropy of the literal, "
            "because the workflow files pin actions by a forty character "
            "digest and an entropy rule fires on every one of them."
        ),
        patterns=(
            re.compile(
                r"\b\w*(?:key|secret|blinding|nonce|passphrase)\w*\s*=\s*"
                r"""(?P<quote>['"])(?:(?!(?P=quote)).){12,}(?P=quote)""",
                re.I,
            ),
        ),
    ),
    Rule(
        id="no-language-string-hash",
        issue="#17",
        refusal=(
            "the interpreter's own hash is called in the package, and it is "
            "randomised per process, so anything derived through it differs "
            "between two runs of the same analysis"
        ),
        scope=("src/",),
        blind_to=(
            "a value that reaches the interpreter's hash without the call "
            "being written, which is every use of a set or a dict. Ordering "
            "derived from one of those is the same defect and this rule does "
            "not see it; the determinism check in issue #30 runs two processes "
            "and does."
        ),
        patterns=(re.compile(r"(?<![\w.])hash\s*\("),),
    ),
    Rule(
        id="committed-carries-its-qualifier",
        issue="#6",
        refusal=(
            "an output template says committed without saying witnessed or "
            "local beside it, and a commitment nobody outside saw is a local "
            "record"
        ),
        scope=("src/",),
        blind_to=(
            "a template assembled from two strings, where the word and its "
            "qualifier are written on different lines. The rule reads one line "
            "at a time and says so."
        ),
    ),
    Rule(
        id="refusal-is-raised-not-dropped",
        issue="#18",
        refusal=(
            "a refusal is built as a statement and never raised, so the run "
            "walks on past a violation it had already found"
        ),
        scope=("src/",),
        blind_to=(
            "nothing this pattern could reach, and one thing it could not: a "
            "refusal returned by a helper whose name says none of this. The "
            "lint gate's F841 covers the spelling that binds the value to a "
            "name."
        ),
        patterns=(re.compile(r"^\s*(?:\w+\.)?(?:Refusal|refuse\w*)\s*\("),),
    ),
    Rule(
        id="action-pin-carries-its-version",
        issue="#91",
        refusal=(
            "an action is pinned to a commit with no version beside it, and "
            "the comment is the only thing in the file that says which "
            "release a forty character hash is"
        ),
        scope=(".github/",),
        suffixes=(".yml", ".yaml"),
        blind_to=(
            "a comment that disagrees with its hash, which is the other way "
            "this goes wrong and needs the forge to resolve a hash to a tag "
            "before anything can say so; a stale comment and an accurate one "
            "are the same bytes here. It also does not refuse the missing "
            "hash, which is the neighbouring half of the same clause and is "
            "zizmor's unpinned-uses audit. A version is read as a comment "
            "carrying a digit, so a comment naming a release with no number "
            "in it passes."
        ),
        patterns=(re.compile(r"uses:\s*\S+@[0-9a-fA-F]{40}(?!\s*#.*[0-9])"),),
    ),
)


def tracked_files() -> list[str]:
    """Every path git tracks, in git's own opinion rather than a walk's."""
    listing = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=REPOSITORY_ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return [path for path in listing.split("\0") if path]


def required_distributions() -> set[str]:
    """The names the package declares as required, read rather than written."""
    with (REPOSITORY_ROOT / "pyproject.toml").open("rb") as handle:
        declared = tomllib.load(handle)["project"].get("dependencies", [])
    return {
        re.split(r"[^A-Za-z0-9_.-]", name.strip())[0].replace("-", "_").lower()
        for name in declared
    }


def imported_roots(line: str) -> str | None:
    """The top level module a source line imports, if it imports one."""
    plain = re.match(r"^(?P<indent>\s*)import\s+(?P<name>[.\w]+)", line)
    if plain:
        return plain.group("name").split(".")[0]
    frm = re.match(r"^(?P<indent>\s*)from\s+(?P<name>[.\w]+)\s+import\s", line)
    if frm:
        name = frm.group("name")
        # A relative import stays inside the layer, which is the thing the
        # rule is for rather than against.
        if name.startswith("."):
            return None
        return name.split(".")[0]
    return None


def import_findings(rule: Rule, line: str, allowed: set[str]) -> str | None:
    """The two import rules, which ask a question a pattern alone cannot."""
    root = imported_roots(line)
    if root is None:
        return None
    if rule.id == "core-imports-required-only" and line[:1].isspace():
        # A module-level import is the one this rule refuses. An import inside
        # a function is what keeps an optional dependency optional.
        return None
    if root in allowed:
        return None
    return f"imports `{root}`"


def qualifier_findings(line: str) -> str | None:
    """`committed` in an output template, without its qualifier beside it."""
    for template in PLAIN_STRING.finditer(line):
        text = template.group("text")
        if not re.search(r"\bcommitted\b", text, re.I):
            continue
        if re.search(r"\b(?:witnessed|local)\b", text, re.I):
            continue
        return "says committed with neither witnessed nor local beside it"
    return None


def protection_findings(line: str) -> str | None:
    """protect, secure or encrypt inside something the package prints."""
    for template in PLAIN_STRING.finditer(line):
        if re.search(r"\b(?:protect|secure|encrypt)", template.group("text"), re.I):
            return "an output template uses the vocabulary of protection"
    return None


@dataclass
class Finding:
    rule: Rule
    path: str
    line_number: int
    detail: str
    line: str


@dataclass
class Scan:
    findings: list[Finding] = field(default_factory=list)
    rules_that_fired: set[str] = field(default_factory=set)


def in_scope(rule: Rule, path: str) -> bool:
    return any(path.startswith(prefix) for prefix in rule.scope)


def read_lines(path: str) -> Iterator[tuple[int, str]]:
    text = (REPOSITORY_ROOT / path).read_text(encoding="utf-8", errors="replace")
    return enumerate(text.splitlines(), start=1)


def apply_rule(rule: Rule, path: str, allowed: set[str], scan: Scan) -> None:
    for number, line in read_lines(path):
        detail: str | None = None
        if rule.id in {"contract-imports-stdlib-only", "core-imports-required-only"}:
            detail = import_findings(rule, line, allowed)
        elif rule.id == "committed-carries-its-qualifier":
            detail = qualifier_findings(line)
        elif rule.id == "no-vocabulary-of-protection":
            detail = protection_findings(line) or next(
                (
                    "a public name uses the vocabulary of protection"
                    for pattern in rule.patterns
                    if pattern.search(line)
                ),
                None,
            )
        else:
            for pattern in rule.patterns:
                if pattern.search(line):
                    detail = "matches the rule's pattern"
                    break
        if detail is None:
            continue
        scan.rules_that_fired.add(rule.id)
        scan.findings.append(Finding(rule, path, number, detail, line.strip()))


def allowed_imports(rule: Rule) -> set[str]:
    stdlib = set(sys.stdlib_module_names)
    if rule.id == "contract-imports-stdlib-only":
        # The contract layer is what an outside implementation reads as a
        # specification, so it imports nothing this repository ships either.
        return stdlib | {"__future__"}
    return stdlib | {"__future__", "blende"} | required_distributions()


def scan(paths: Iterable[str], *, scoped: bool) -> Scan:
    result = Scan()
    listing = list(paths)
    # Fail closed. An empty list means the walk broke, and a broken walk that
    # reports a clean tree is the failure this check exists to prevent.
    if not listing:
        sys.exit(
            "No path was listed for scanning. Refusing to report a clean "
            "result from a walk that returned nothing."
        )
    for rule in RULES:
        allowed = allowed_imports(rule)
        for path in listing:
            if not path.endswith(rule.suffixes):
                continue
            if scoped and not in_scope(rule, path):
                continue
            apply_rule(rule, path, allowed, result)
    return result


def report(findings: list[Finding]) -> None:
    for finding in findings:
        print(
            f"::error file={finding.path},line={finding.line_number}::"
            f"[{finding.rule.id}] {finding.rule.refusal} ({finding.detail}). "
            f"The invariant is issue {finding.rule.issue}."
        )
        print(f"  {finding.path}:{finding.line_number}: {finding.line}")
        print(f"  this rule does not see: {finding.rule.blind_to}")


def check_the_tree() -> int:
    paths = [path for path in tracked_files() if not path.startswith(SAMPLES + "/")]
    result = scan(paths, scoped=True)
    if result.findings:
        report(result.findings)
        print(f"{len(result.findings)} finding(s) against {len(RULES)} rule(s).")
        return 1
    # The run says what it examined and what each rule cannot see, so a clean
    # result cannot be read as a tree with none of these defects in it. Every
    # one of these rules is a pattern, and a pattern that found nothing and a
    # pattern that cannot look are the same output otherwise.
    print(f"{len(RULES)} rule(s), no finding on the tracked tree:")
    for rule in RULES:
        print(f"  {rule.id} ({rule.issue}), reading {', '.join(rule.scope)}")
        print(f"    does not see: {rule.blind_to}")
    return 0


def declared_rule(path: str) -> str | None:
    for _, line in read_lines(path):
        match = DECLARES.match(line)
        if match:
            return match.group("id")
    return None


def prove_every_rule_bites() -> int:
    # Every tracked file here, whatever its suffix. Collecting by the suffixes
    # the rules read looks tighter and fails open: deleting a rule deletes the
    # only suffix its sample was collected under, so the sample disappears from
    # this mode instead of being reported as one that outlived its rule, and
    # deleting a rule is the thing this mode exists to notice. A file here that
    # declares no rule is refused below rather than skipped.
    samples = [path for path in tracked_files() if path.startswith(SAMPLES + "/")]
    if not samples:
        sys.exit(
            f"No sample was found under {SAMPLES}. Refusing to report that "
            "every rule bites when none was read."
        )

    by_id = {rule.id: rule for rule in RULES}
    proved: set[str] = set()
    failures: list[str] = []

    for path in sorted(samples):
        named = declared_rule(path)
        if named is None:
            failures.append(
                f"{path} names no rule. Add a line reading "
                "`# invariant: <rule-id>` so the sample says what it proves."
            )
            continue
        rule = by_id.get(named)
        if rule is None:
            failures.append(
                f"{path} names the rule `{named}`, which no rule in this file "
                "declares. Either the rule was renamed or the sample outlived "
                "it."
            )
            continue
        result = scan([path], scoped=False)
        fired = {finding.rule.id for finding in result.findings}
        if named not in fired:
            failures.append(
                f"{path} is written to trip `{named}` and does not. A rule "
                "that has never been shown to bite is a pattern in a file."
            )
            continue
        proved.add(named)
        line = next(f for f in result.findings if f.rule.id == named)
        print(f"  {named}: {path}:{line.line_number}: {line.line}")

    unproved = sorted({rule.id for rule in RULES} - proved)
    if unproved:
        failures.append(
            "These rules are declared and no sample under "
            f"{SAMPLES} trips them: " + ", ".join(unproved) + "."
        )

    if failures:
        for failure in failures:
            print(f"::error::{failure}")
        return 1

    print(f"{len(proved)} rule(s), each tripped by the sample that names it.")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--prove",
        action="store_true",
        help="read the samples and refuse a rule none of them trips",
    )
    arguments = parser.parse_args(argv)
    if arguments.prove:
        return prove_every_rule_bites()
    return check_the_tree()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
