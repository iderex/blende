# Security policy

## What this project is, so that a report can be about it

blende is a Python library for blind analysis in precision measurement. It
derives a deterministic offset from a salted blinding key, fixes one canonical
byte encoding for everything that enters a digest, and holds the declaration
set a commitment to an analysis plan is taken over. What is landed today is
`src/blende/contract/` and `src/blende/environment.py`. The package exports
nothing yet, no artefact writer and no unblinding path exist, and
`python -m blende` prints an environment report and is the only entry point.

The contract layer opens no socket, reads no file and parses no input format.
It takes bytes and numbers from the caller and returns bytes and numbers.
`src/blende/environment.py` is the single exception, and it is the one surface
named below. numpy is the only declared runtime dependency, and that layer is
held to the standard library by a check in `tools/greppable_invariants.py`, so
the key derivation, the fingerprint and the digests are `hashlib` and `hmac`.

There is also no release. No tag, no GitHub release, and the name resolves to
nothing on PyPI:

    $ gh api repos/iderex/blende/releases --jq 'length'
    0
    $ gh api repos/iderex/blende/tags --jq 'length'
    0
    $ curl -s -o /dev/null -w '%{http_code}' https://pypi.org/pypi/blende/json
    404

Whatever you are holding, you got it from this repository.

## Where to report

Private vulnerability reporting is enabled on this repository, and I measured
that rather than assuming it:

    $ gh api repos/iderex/blende/private-vulnerability-reporting
    {"enabled":true}

So the channel is

    https://github.com/iderex/blende/security/advisories/new

and it answers today. Use it for anything that lets a blinding key or a derived
offset out. Anything in the second list below can go on the public issue
tracker instead, and I would rather have it there than not at all.

I promise no acknowledgement deadline. A deadline this project cannot keep is
worse than none, because it leaves you counting days and then guessing whether
the report arrived at all. Silence here means I have not read it yet, never
that I read it and decided against you.

## What counts as a vulnerability in this program

The thing this code exists against is an analyst who biases a result by seeing
it too early. The assets are the blinding key and everything that would let a
reader of a published artefact recover the offset from it. Reports that land on
those are the ones worth writing.

Key material reaching somewhere the operator did not put it. `BlindingKey` in
`src/blende/contract/key.py` keeps its material in `__slots__` behind a
property and overrides both `__repr__` and `__str__` to render a fingerprint
prefix, because a generated repr would put the blinding string into a
traceback, a debugger line and any log that formats an object. Any path that
defeats that is a vulnerability: an exception built from a key, a serialisation
that renders one, a copy or a pickle that does.

A refusal that hands back the data. `src/blende/contract/refusal.py` carries a
rule identifier, a subject and a sentence, and no formatted value, because the
ordinary habit of putting the offending number into the message hands the
analyst exactly the number they are not supposed to see. A refusal that names a
value, or that identifies an item by its index into a closed region, is a leak
even though nothing crashes.

A derivation that stops separating. The parameter name inside the digested
message is the whole of the domain separation between one parameter and the
next, `canonical.frame` puts a length in front of every field so two different
field lists cannot reach one byte string, and the fingerprint is keyed by the
published context with the key material as the message, in that order and for a
stated reason. A defect that collapses two parameters onto one offset, that
makes the framing non-injective, or that makes a published fingerprint cheaper
to invert than enumerating candidate keys, is a vulnerability here even though
no test goes red.

The workflow YAML. `.github/workflows/` is code that runs with a token. The
Scorecard job holds `security-events: write` and `id-token: write`, the zizmor
job holds `security-events: write`, and neither is meant to be reachable from
an untrusted pull request. A path by which a fork's pull request obtains a
write-scoped token, injects into a `run:` block, or poisons something a
write-scoped job consumes, belongs in the private channel.

The one parser. `src/blende/environment.py` reads `Requires-Dist` lines out of
installed distribution metadata, and that is the only input in the tree the
program did not produce itself. I rate it low, because whoever can write into
your site-packages has already won. But that module exists to refuse rather
than guess, so a crafted requirement line that makes it report a clean
environment over an incomplete install would be a real finding.

The suite's own guards. `tools/default_suite.py` installs audit-hook guards
that refuse a test binding a socket, reaching the network, resolving a name or
writing outside its temporary directory. A way past one of those from inside a
default-suite test is worth reporting, though it protects this project's own CI
rather than a user, so it needs no embargo.

## What is not a vulnerability here

Blinding is not confidentiality. Anyone holding the key can undo the transform,
and the person running the analysis is holding the data anyway. The offset
defends an analyst against their own expectations, not a dataset against an
intruder. "Somebody with the blinding key can recover the true value" is the
design working.

A short blinding string is enumerable, and the code says so. The floor is
sixteen characters or sixteen bytes, and `contract/key.py` states that this is
a length floor and not a claim about entropy, that a published fingerprint
inherits the key's entropy and adds none, and that `generate()` exists because
a drawn key beats a typed one. Repeating that is not a report; a change that
quietly removed the disclosure is worth an issue.

A key derived from the data is not refused. A function that received a key and
a dataset cannot tell whether the first came from the second, and the module
discloses that in place of a check it cannot write.

The interval mapping reads eight leading bytes of the digest, so two digests
agreeing in those eight bytes give one number. That is a stated consequence of
choosing a width every language reads natively, written down where the constant
is, rather than something the constant hides.

Files written in order to be refused. `tests/harness-regressions/` and
`tests/invariant-regressions/` contain a file that binds a socket, one that
connects to an address, one that removes a tree outside the temporary
directory, one carrying a blinding string literal, and more. Each exists to
prove a guard bites, and the run excludes them. A scanner that finds them has
found the fixtures.

SHA-256 reported as a weak hash. The primitive is named once per module, as a
string handed to `hmac.new` in `key.py` and `derivation.py` and to
`hashlib.new` in `declaration.py`, and some tools flag that on sight. An
argument about the primitive itself is welcome as an issue rather than as an
advisory.

An untriaged Scorecard number. That workflow says of itself that nothing in its
output has been triaged and no acceptance is recorded, so a low check is a
to-do list here and not a finding.

A dependency older than the newest release, with no advisory against the locked
version. `tools/dependency_policy.py` is the gate for that, and it prints what
it did not cover.

A package named blende on a package index. I have published none. If you find
one it is not mine, and telling me is a kindness rather than a report about
this repository.

A timing report on the digest comparison in `contract/declaration.py`. It
compares the digest of the declaration set a run holds against the value
recorded when the plan was fixed, and both of those belong in a published plan.
Neither operand is secret, and there is no secret comparison in this tree to
make constant time.

## If you are writing one

Name the file and the function, and say what the attacker ends up holding.
Everything here is either bytes or a refusal, so a few lines of input and the
output you got beats a scanner export. For the derivation, send the key
material, the declaration and the value you observed;
`tests/fixtures/vectors/derivation.txt` is the shape I will answer in.
