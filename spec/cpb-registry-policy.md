# CPB Registry Operational Policy

> **STATUS: RATIFICATION TEXT.** This document is the policy Steven Mih and
> Anton Sokolov agreed on 2026-10-05, carried in one ratification pull
> request. It takes effect when that pull request merges with both §5
> sign-offs given at its exact head SHA. A sign-off given at one commit does
> not carry to another: if the pull request changes after an approval, the
> approval must be given again at the new head.
>
> Canonical Payload Binding (CPB) is a public, neutral, cross-organization
> specification co-authored by Steven Mih (Action State Group) and Anton
> Sokolov (TalTech / Tyche Institute). It is never branded to, or hosted
> under, any single registrant's product or domain. Agent Action Capsule is
> one registrant among peers, not the registry's owner.

## Purpose and scope

The operative normative revision is
[`draft-mih-sokolov-scitt-payload-binding-05`](draft-mih-sokolov-scitt-payload-binding-05.md),
the posted revision. (-06 adds no normative text and does not change
anything below.) Under -05 (§14), CPB requests **one** new IANA registry, the
Canonicalization Algorithm Registry, plus one `cpb-refs` registration in the
existing COSE Header Parameters registry. **CPB creates no artifact-type
registry and does not depend on one.** Artifact-type and digest-context
declarations are owned and selected by the profiles that define them (-05
§8.1, Cross-Profile Comparability).

This document is the operating policy for what this repository keeps ahead
of RFC publication:

- the working record of canonicalization-algorithm tokens that -05 lists as
  the requested initial IANA contents; and
- legacy and provisional artifact-type records, kept as history and as
  profile-owned data only (REGISTRY.md's Artifact Type section and
  `spec/cpb-provisional-registry.md`). Listing a type here does not register
  it.

It covers four things REGISTRY.md does not:

1. The entry lifecycle, stated publicly (§1).
2. Immutability at promotion, cited rather than restated (§2).
3. The Designated Expert panel: members, the two-organization rule, and
   recusals (§3).
4. The IANA-forwarding clause (§4).

## §1 — Entry lifecycle: provisional → live → withdrawn

Two statuses apply to a registered entry: **live** and **withdrawn**. There is
no third status. Live and withdrawn have covered every case seen so far, and a
third state would mean a third branch in every verifier and in the site
generator.

| Stage | REGISTRY.md equivalent | -05 IANA status |
|---|---|---|
| **provisional** (pre-registration) | Rung 3, status `provisional`, tracked in `spec/cpb-provisional-registry.md` or `registry/entries/*.yaml`. Never live; a lookup treats it as non-live. | none (not an IANA entry) |
| **live** | Rung 1 or Rung 2 in the REGISTRY.md tables: `owner-confirmed`, `third-party-documented` or `standards-referenced` (legacy `Registered` maps to `owner-confirmed`). | `Active` |
| **withdrawn** | `withdrawn` in the Entry Status Vocabulary. | `Withdrawn` |

- **Withdrawn is terminal and binds the name for good.** The token is never
  reassigned, and its last definition stays as the historical record (-05
  §14.1). This is how `jcs-n` and `cde-n` are recorded.
- **Removal is not a status.** An owner may remove an entry or filing at any
  time (REGISTRY.md, Owner-requested removal). A removed name is **not
  bound**: it is recorded under REGISTRY.md's `## Removed` section with a
  date and a note, and it can be filed again later. An owner who wants the
  name reusable asks for removal, not withdrawal. (`mesh-inference-exchange`
  was removed this way in the ratification pull request.)
- **`Reserved`** is a name hold, not a lifecycle stage. This matches both -05
  and REGISTRY.md's legacy mapping.

This adds nothing to REGISTRY.md's Entry Status Vocabulary. No status is
created, so no follow-up change to that table is needed.

## §2 — Immutability at promotion (existing rule, cited)

No new policy. -05 §14 states it for the IANA registry ("An active entry's
algorithm semantics are immutable. If a behavior change is needed, a new
entry MUST be registered; an existing name MUST NOT be reinterpreted"), and
REGISTRY.md states the same rule for its own records, with its two narrow
exceptions: a factual bibliographic correction, and a lifecycle status
transition. It is cited here so this document describes an entry's whole
life. The normative text stays in those two places.

## §3 — Designated Expert panel: two or more organizations

**Rule.** The standing panel of Designated Experts that reviews proposals in
this repository MUST include experts from at least two distinct
organizations. A single entry's reviewer assignment is a separate matter: one
expert may review an entry alone. The rule governs the panel that
assignments are drawn from, so that no single registrant's organization makes
up the whole panel.

**Scope under -05.** -05 has one IANA registry, the Canonicalization
Algorithm Registry, under Specification Required with a Designated Expert for
each registration. In this repository the panel reviews:

- proposed canonicalization-algorithm tokens and status changes, before they
  are written into the requested initial IANA contents; and
- the legacy and provisional artifact-type records described above. A panel
  decision on one of those records is a decision about this repository's
  history file, not an artifact-type registration. -05 has no artifact-type
  registry for it to be.

After IANA establishes the registry, the IESG appoints its Designated
Experts. The panel below is the editors' panel. It is not an IANA
appointment, and the editors do not claim the power to make one.

**Panel.** Ratified with this document:

| Expert | Organization | Record |
|---|---|---|
| Steven Mih | Action State Group | CPB author. Approved `machine-mandate`; Anton Sokolov owns it and recused. |
| Anton Sokolov | TalTech / Tyche Institute | CPB author. Expert reviewer on `mesh-inference-exchange` and `cll-checkpoint` / `mmr-checkpoint` (both filings have since left this repository; see REGISTRY.md § Removed). Sole reviewer on `vto`. |
| Manu Sheel Gupta | libp2p | Additional designated expert, appointed by this ratification. He has accepted. |

Manu Sheel Gupta's organization is neither author's organization, so the
two-organization rule holds even if both authors recuse. The rule **binds
from ratification**. No entry admitted after this document takes effect is
reviewed under a single-organization panel.

**Recusals.** An expert does not review an entry that they own or that their
own team filed. Named recusals at ratification:

- **Manu Sheel Gupta recuses on `vto`**, his own team's filing. **Anton
  Sokolov reviews `vto` alone.**
- **Anton Sokolov recuses on `machine-mandate`**, which he owns. Steven Mih
  gave that approval.

A recusal is recorded in the entry's filing (`de_reviewer` in
`registry/entries/*.yaml`, or the entry's prose), so that a reader can see
from the record who reviewed an entry and who did not.

**Authors as experts.** The two CPB authors stay on the panel. Authors often
serve as Designated Experts, and the per-entry recusal rule above covers the
conflict. No third-party replacement is required. An entry owned by an
author also carries REGISTRY.md's `Disclosure` field.

## §4 — The IANA-forwarding clause

**This states what a registrant can rely on before building against a CPB
identifier, and where that assurance stops.**

Under -05 §14, IANA is the registry maintainer. No source repository or
other body is an alternative registry authority. Before RFC publication, the
names in -05 are draft-local, and its table is only the *requested* initial
registry contents. This repository is a working record, not an interim
registry of record (REGISTRY.md, CPB-03 status note).

> **Clause.** The editors undertake two things, and only these two, because
> only these two are theirs to give. First, the IANA Considerations section
> of the defining document will **request** that every canonicalization
> algorithm token in its initial contents, `Active`, `Reserved` or
> `Withdrawn`, be established **under the same identifier string, with the
> same registered semantics and status**, together with its public
> vector-backed conformance history. Second, the editors will not themselves
> rename, reassign or silently re-adjudicate a token in the course of
> preparing that request.
>
> **Artifact-type names are outside this clause.** CPB creates no
> artifact-type registry. An artifact type's name and digest contexts are
> owned by its profile, and forwarding them to IANA, if they go anywhere, is
> that profile's own IANA Considerations section's job. (The
> `cll-checkpoint` relocation to the Checkpointed Local Log draft is the
> worked example.) Records kept in this repository's history files are not
> forwarded by CPB.
>
> **What the editors cannot undertake.** The contents of an IANA registry at
> establishment are settled by IANA and by the responsible working group, not
> by the authors of an individual Internet-Draft. Under a Specification
> Required policy a Designated Expert may decline an entry. A working group
> may rewrite an IANA Considerations section, including by dropping a
> registry from the document's scope, which has already happened once in this
> document's history (the artifact-type registry, dropped at -03). An
> implementer building on a pre-IANA CPB token therefore carries a real,
> bounded risk. The editors will not move the name, and will ask that nobody
> else does, but they cannot promise on behalf of a body that has not agreed.
> That is the honest shape of the guarantee, and it is stated here rather
> than discovered later.

**Why this is weaker than RFC 7120, and why that matters.**
[RFC 7120](https://www.rfc-editor.org/rfc/rfc7120), "Early IANA Allocation of
Standards Track Code Points", lets implementers build against an IANA code
point before the defining document reaches RFC status, on the understanding
that early-allocated values are not reassigned except in exceptional
circumstances (RFC 7120 §3). The clause above looks like a counterpart to
that, but it is not one: **RFC 7120 works because IANA operates it**, under a
documented procedure with IESG approval. CPB has no such standing. What is
offered above is an undertaking by two editors, not a procedure run by a
registry authority, and an implementer should weigh it that way. RFC 7120 is
cited here as the thing CPB's undertaking is *weaker than*, so that nobody
reads the resemblance as equivalence.

**What this clause does not do.** It does not freeze a token's *content*:
immutability (§2) already governs that, separately. It does not promise that
a provisional record will ever become a live entry. It covers only the
**identifier string** and recorded semantics of a canonicalization-algorithm
token that is in the requested initial contents. That is narrower than a
promotion guarantee, and it is all that "safe to build on before RFC" needs.

## §5 — Ratification

This document is policy once both sign-offs below are recorded with date and
form. Accepted forms are PR approval, on-record email, or an explicit written
statement quoted here, the same evidentiary bar as REGISTRY.md's Gate C for
owner acknowledgment. Both parties use **PR approval at the exact head SHA**
of the ratification pull request.

| Party | Sign-off | Date | Form |
|---|---|---|---|
| Steven Mih (Action State Group) | Approved at `<head SHA>` | 2026-10-`<dd>` | PR approval at the exact head SHA. As author, he opens the ratification PR at that SHA, and the commit carries his `Signed-off-by`. |
| Anton Sokolov (TalTech / Tyche Institute) | Approved at `<head SHA>` | 2026-10-`<dd>` | PR approval at the exact head SHA (GitHub review). His agreement in substance is also on record by email, 2026-10-05. |

**Filling the slots.** Two slots stay open until the approvals exist.
`<head SHA>` is the full 40-hex commit id that Anton Sokolov's approving
review is attached to, and the same value goes in both rows. `<dd>` is the
day of each party's act (Steven Mih opening the PR at that SHA; Anton
Sokolov approving at it). The slots are filled in a housekeeping commit
**after merge**. Editing this table inside the ratification PR would move its
head and void the approval it records. Until that commit lands, the approving
review on the ratification pull request is the record.

**Decided at ratification** (formerly open items):

1. §1: no `deprecated` status. Live and withdrawn only; removal is not a
   status and binds no name.
2. §3: Manu Sheel Gupta (libp2p) appointed. Recusals written in: Manu Sheel
   Gupta on `vto`, Anton Sokolov on `machine-mandate`. The authors stay on
   the panel.
3. §3: the panel record is corrected. Steven Mih, not Anton Sokolov,
   approved `machine-mandate`.
4. §3 and §4 are aligned to posted -05, which keeps no artifact-type
   registry.

REGISTRY.md's Entry Status Vocabulary needs no change for item 1. The panel
rule and the recusals live here.
