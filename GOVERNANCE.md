# Governance

This repository carries **`draft-mih-sokolov-scitt-payload-binding`** — *Canonicalization
Declaration for SCITT Signed Statements* — together with its registry material, conformance
vectors and reference code. The document is an **individual IETF Internet-Draft**. It is not a
Working Group document and it is not an RFC.

This file states how the project is run. It is modeled on the governance practice used across the
sibling repositories, adapted to the fact that this document has **two authors**.

## Why this document exists now

An interoperability mechanism is only worth as much as the discipline behind it. A project with two
authors needs a stated answer to an ordinary question — *what happens when one of us is not
available?* — because the alternative is an unwritten rule that is quietly worked around when it
becomes inconvenient. A rule that cannot be met does not produce review. It produces exceptions.

The arrangement below is **symmetric**. It is not written about either author in particular, and it
does not depend on which of them is busy. Availability varies for both, in both directions, and the
project should behave the same way whichever of them is unreachable.

## Roles

- **Contributors** — anyone who opens an issue or pull request. Contributions are made under the
  Developer Certificate of Origin (DCO sign-off); there is no CLA.
- **Maintainers** — review and merge changes, cut releases, and steward the repository.
  Co-maintainers from other organizations are explicitly welcome and earn merge rights through
  sustained, high-quality contribution.
- **Authors** — the named authors of the Internet-Draft. Authorship is an IETF matter, held under
  BCP 78 and BCP 79, and is not conferred or removed by this document.

The current maintainers and authors are listed in [`MAINTAINERS.md`](./MAINTAINERS.md).

## How changes are made

Changes happen by pull request and public discussion, with **lazy consensus** among maintainers.

### Non-normative changes land without waiting

Editorial corrections, examples, conformance vectors, tooling, CI, registry housekeeping, and any
change that carries no RFC 2119 keyword: open the PR and land it. **No maintainer needs to wait for
the other.** This is a standing pre-authorization and it runs in both directions.

### Normative changes get an issue first, and a 14-day window

A normative change is any change to what a conforming implementation MUST, SHOULD or MAY do —
including the canonicalization algorithm registrations, the derived identifier, the envelope
conventions, and the statement-to-receipt binding.

1. Open an issue describing the problem, the proposed change, and the section affected.
2. Allow **14 days** for comment.
3. If no maintainer objects within the window, the change may land.

The window is a minimum, not a target. It exists so a maintainer who is heads-down for two weeks can
still object in time, without being obliged to review on anyone else's schedule. An objection raised
inside the window is resolved before the change lands; silence is consent.

### Changes are not reverted unilaterally

There is no standing revert right. Once a change has landed under this process it is part of the
document's history, and a maintainer who disagrees with it opens a pull request correcting it, under
the same rules. Undoing work quietly is how a two-author project acquires a disputed history that
neither author can reconstruct later.

## Internet-Draft revisions and Datatracker submissions

**Every submission to the IETF Datatracker requires the agreement of every author, without
exception.** This includes editorial revisions, acknowledgments-only revisions, and rebuilds that
change no normative text. The standing pre-authorization above governs the repository; it does not
govern publication.

A normative change that landed under the 14-day window without an explicit statement from an author
is not thereby agreed for submission. Before a revision is submitted, each normative change made
since the previous revision carries an explicit yes from each author, named by commit. Lazy
consensus governs the repository; it does not accumulate into a submission.

A revision is a statement made in both authors' names to a standards body. It is the one thing in
this project that cannot be undone by a later pull request, and it is therefore the one thing that
always waits.

### What agreement attaches to

Agreement attaches to **bytes**, not to a branch or a revision number:

- a **pinned commit** or the **built `.xml`/`.txt` artifact** as it will be submitted; or
- the exact version **uploaded to the Datatracker**.

**An agreement never carries to another commit.** If the document is amended, rebuilt or
force-pushed after agreement is given, the author seeking to submit states the new identifier and
asks again. This is not a formality: a concurrence given on text that then changed is a
concurrence to something nobody agreed to.

## Availability

Either author may be unavailable for extended periods. When that happens:

- non-normative work continues without them;
- normative proposals run their 14-day window and land if unopposed;
- **submissions wait.**

A submission may wait a long time. That is the intended behaviour, not a failure of the process.

## Becoming a maintainer

Open issues and pull requests, review others' changes, and take part in discussion. After a track
record of quality contributions, the existing maintainers may invite you to become a maintainer.
Maintainership is not tied to employer; contributors from any organization are welcome, and a second
implementing organization is worth more to this document than any amount of internal review.

Becoming a **maintainer** of this repository is separate from becoming an **author** of the
Internet-Draft. The second follows IETF practice and the existing authors' agreement, not this file.

## What this document does not change

This file governs the repository. It does not and cannot alter the rights and obligations of
Internet-Draft authorship, which are held under **BCP 78** and **BCP 79**, nor the standing of the
document itself — which, on Working Group adoption, passes to the working group rather than to this
project.

## Code of Conduct

All participants are expected to follow the project
[Code of Conduct](./CODE_OF_CONDUCT.md).

## Licensing

The specification is contributed under the **IETF Trust's terms (BCP 78/79)**, with code components
under the **Revised BSD License**. Reference code and tooling in this repository are licensed as
stated in [`LICENSE`](./LICENSE).
