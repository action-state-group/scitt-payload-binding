# Maintainers

Two lists, deliberately kept separate. **Maintainership** of this repository is granted and held
under [`GOVERNANCE.md`](./GOVERNANCE.md). **Authorship** of the Internet-Draft is an IETF matter,
held under BCP 78 and BCP 79, and is neither conferred nor removed by this file.

## Repository maintainers

| Name | Affiliation | GitHub |
| --- | --- | --- |
| Steven Mih | Action State Group, Inc. | [@StevenMih](https://github.com/StevenMih) |
| Anton Sokolov | Tyche Institute | [@tyche-dev](https://github.com/tyche-dev) |

Maintainers review and merge changes, cut revisions, and steward the repository.
**Co-maintainers from other organizations are welcome** — see
[Becoming a maintainer](./GOVERNANCE.md#becoming-a-maintainer). A second implementing organization
is worth more to this document than any amount of internal review.

## Internet-Draft authors

`draft-mih-sokolov-scitt-payload-binding` — *Canonicalization Declaration for SCITT Signed
Statements*

| Name | Affiliation | Contact |
| --- | --- | --- |
| Steven Mih | Action State Group, Inc. | spec@actionstate.ai |
| Anton Sokolov | Tyche Institute | anton.sokolov@tyche.institute |

## What needs whose agreement

A short form of [`GOVERNANCE.md`](./GOVERNANCE.md). The rules are symmetric: they apply to every
maintainer equally and do not depend on which one is unavailable.

| Change | What is required |
| --- | --- |
| Editorial, examples, vectors, tooling, CI, registry housekeeping | **Land it.** No maintainer waits for another. |
| Normative change — anything altering what a conforming implementation MUST, SHOULD or MAY do | **Issue first, 14-day comment window.** Lands if unopposed. Silence is consent. |
| **Submission to the IETF Datatracker** | **Every author agrees. No exceptions** — including editorial and acknowledgments-only revisions. |

Agreement to a submission attaches to **bytes**: a pinned commit, the built `.xml`/`.txt` as it will
be submitted, or the exact version uploaded to the Datatracker. **An agreement never carries to
another commit** — if the document is amended, rebuilt or force-pushed afterwards, the maintainer
seeking to submit states the new identifier and asks again.

Nothing landed under this process is reverted unilaterally. A maintainer who disagrees opens a pull
request correcting it, under the same rules.

## Security and conduct

Security reports: see [`SECURITY.md`](./SECURITY.md).
Conduct concerns: see [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md).
