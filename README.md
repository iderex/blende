# blende

Blinding is standard in precision measurement and is rebuilt from scratch on every experiment: LAURA++ adds an offset determined from a blinding string, Muon g-2 runs random frequency offsets, CMS blinded 110 to 140 GeV for the Higgs search. STAR in 2018 had to investigate and implement new blinding procedures from zero for the first species-blind data production in collider physics, with two decades of data-management experience behind it. The package solves the pattern once: deterministic offsets from a salted key, blinded axes, open and closed regions, an audit log before unblinding, and a cryptographic commitment to the analysis plan. The commitment is the piece that cannot be retrofitted and the piece a house-built solution always omits, because it is the only one that constrains its author.

Planning happens on the issue tracker first. Every decision that shapes
the architecture is written down there with its reasons before the code
that depends on it exists.

See [NOTICE.md](NOTICE.md) for the intended-use notice.
