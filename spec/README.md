# spec/

The current revision of draft-mih-sokolov-scitt-payload-binding is the one named
by `DRAFT` in `Makefile`; it is the only revision the build and CI act on.

## Posted revisions -02 to -05 (restored for diffing)

The `.xml` and `.txt` files for -02, -03, -04 and -05 are the bytes the IETF
archives as posted, downloaded unmodified from
`https://www.ietf.org/archive/id/draft-mih-sokolov-scitt-payload-binding-0N.{xml,txt}`
on 2026-10-04. They were missing from `main` (each revision's source was renamed
forward when the next one opened), so posted revisions could not be diffed from
the repository. Do not edit or rebuild them.

The `.md` files are the kramdown-rfc sources for those revisions, taken from the
repository history. Each one, built with the -04 revision of
draft-ietf-scitt-receipts-ccf-profile in the reference cache (the revision
current when -02 to -05 were posted), produces a `.txt` byte-identical to the
archived one.

| Rev | `.md` from commit | sha256 `.xml` | sha256 `.txt` |
|-----|-------------------|---------------|---------------|
| -02 | bb9a64b | `c965f24123f41843467a6ee7b919a7ee2065ce957721e8872959b8f5ecd7731e` | `47ab675797d7edfe905c13b8482735239d9c5ceb318accbc33e4a5a51e5ec875` |
| -03 | dc991c2 | `3359e910053c01a7f3f6e8a8cc472db569a24a83c1478774a1514203e666a9a0` | `d303e6e4ec4c4bf3b9c483bcabbd720309f952a5e77d912968bef39c1f245d13` |
| -04 | c4b3e29 | `fa1a79f1443736ebc642740a1aa70fde1c7e5d124f3bb51ccf189b4c874e6ac1` | `de06a6eade0306c46b2c1d0f1987a1a7d2d544909a1299e9af9053959cedb376` |
| -05 | ed5ec5d | `9392f96f5122e82de378012c4c55db9dfdafa51c61c014eb6203a194ef9c80ac` | `938073e7ce4f4289ca6d45bebac0b319f2a701804eac5c32203124e65f2fb4fa` |

## Revision -06 is not posted on its own (decision, 2026-10-04)

The working revision -06 differs from the posted -05 only in the
Acknowledgments, a new "Changes from -05" section, and one updated
informative reference; it makes no normative change. Every Datatracker
submission needs fresh agreement from every author, so -06 will not be
submitted by itself. Its changes go out with the next revision that carries
normative text. Until then, -05 is the operative normative revision.
