# spec/

The current revision of draft-mih-sokolov-scitt-payload-binding is the one named
by `DRAFT` in `Makefile`; it is the only revision the build and CI act on.

## Posted revisions -02 to -06 (restored for diffing)

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
| -06 | 861fcb5 | `d710265973593e99e15601145478791da8b9bce9852b75f02d8f4938e86fc29d` | `1cb34a5b6551d25bbd1ffd8444d919881cd46ac539e20e84c9fd3899e27acb21` |

## Revision -06 posted 2026-10-25 (document date 2026-10-26)

Revision -06 was posted from commit 861fcb5 (Datatracker submission
170909) after Steven's written go-ahead of 25 October 2026 and Anton's
release build; the hashes in the table above were computed on the files in
that commit and match the posted `.txt` and `.xml` byte for byte. The -06
files are frozen under the freeze rule in `../RELEASING.md`; the next edit to
the specification opens -07.

Background: on 2026-10-04 the authors had decided not to post -06 on its own
while it differed from -05 only in the Acknowledgments, a "Changes from -05"
section and one informative reference. -06 then gained normative text, the
three causes of the Unresolved state (#92), the member mapping of a pre-image
assembled from selected source fields (#5), and the Failed state for an
obtained artifact that the selected context's construction does not accept,
and was posted once every author agreed to its final text.
