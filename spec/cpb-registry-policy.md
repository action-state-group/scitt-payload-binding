# CPB Registry Operational Policy — DRAFT

> **STATUS: DRAFT — HELD pending ratification.** This document is drafted for
> Steven Mih and Anton Sokolov to review and sign off (§5). It is **not**
> merged policy until both sign-offs are recorded here. Nothing in this
> document takes effect, supersedes, or is authoritative over REGISTRY.md
> until ratified — where this draft and REGISTRY.md's current text differ,
> REGISTRY.md's ratified text governs until this draft is either adopted (and
> REGISTRY.md updated to match) or withdrawn. A CPB editor MUST NOT merge this
> file's contents into REGISTRY.md, cite it as settled policy, or act as if
> any open item below (marked **TBD**) has been decided.
>
> Canonical Payload Binding (CPB) is a public, neutral, cross-organization
> registry co-authored by Steven Mih (Action State Group) and Anton Sokolov
> (TalTech / Tyche Institute). It is never branded to, or hosted under, any
> single registrant's product or domain — Agent Action Capsule is one
> registrant among peers, not the registry's owner.

## Purpose

REGISTRY.md already states most of CPB's registration policy in full — the
Registration Ladder, the Entry Status Vocabulary, the Designated Expert
Admission Checklist, and the Third-Party Registration Rules are normative
today and this document does not restate or duplicate them. This document
covers the parts of the operational policy that are **not yet written down
anywhere**, drafted here so they can be reviewed and ratified as a unit
rather than trickled into REGISTRY.md one PR at a time:

1. A named entry-lifecycle framing (§1) for public-facing use.
2. The existing immutability-at-promotion rule, cited rather than restated
   (§2) — no new policy here, included so this document is a complete
   picture of "what happens to an entry over its life."
3. A designated-expert-panel requirement of reviewers from **at least two
   organizations** (§3) — new policy, not currently required by REGISTRY.md's
   Admission Checklist.
4. The **IANA-forwarding clause** (§4) — new policy, the guarantee that makes
   building against a provisional or promoted CPB identifier safe today, ahead
   of RFC publication.

## §1 — Entry lifecycle: provisional → promoted → deprecated

This is a **public-facing simplification**, not a replacement for
REGISTRY.md's more granular Registration Ladder and Entry Status Vocabulary.
The mapping between the two is exact and is stated here so the two documents
cannot silently drift apart:

| This policy's lifecycle stage | REGISTRY.md equivalent |
|---|---|
| **provisional** | Rung 3 — tracked in `spec/cpb-provisional-registry.md` (or, going forward, `registry/entries/*.yaml` with `rung: provisional`), status `provisional`. |
| **promoted** | Rung 1 or Rung 2 admitted to the live REGISTRY.md tables — status `owner-confirmed`, `third-party-documented`, or `standards-referenced`. |
| **deprecated** | **TBD — new status, not yet in REGISTRY.md's Entry Status Vocabulary.** See below. |

**`deprecated` is a genuinely new status and is the one item in this section
requiring a real ratification decision, not just a restatement.**
REGISTRY.md already has two adjacent-but-distinct mechanisms that a
`deprecated` status must be reconciled against, not silently duplicate:

- **`withdrawn`** (Entry Status Vocabulary) — "the token stays bound but will
  never (again) be carried forward to a live registration." This applies
  today to canonicalization algorithms (`jcs-n`, `cde-n`). It is a terminal
  state for the *token*, with its definitional text retained unedited as a
  historical record.
- **Owner-requested removal** ([Removal and Correction](../REGISTRY.md#removal-and-correction))
  — an owner may request removal "at any time, for any reason... unconditional."
  A removed entry moves to a `## Removed` section with a date and brief note.

**TBD (Steven + Anton ratify):** is `deprecated` —

- (a) a generalization of `withdrawn` to cover Artifact Type Registry entries
  (which currently have no `withdrawn` equivalent — only owner-requested
  removal), naming the same terminal-but-retained treatment; or
- (b) a distinct third state sitting between "live" and "withdrawn/removed" —
  e.g. an entry whose construction still resolves and verifies, but whose
  owner or the DE panel no longer recommends new adoption (a soft signal,
  not a fail-closed one) — which `withdrawn`'s current fail-closed semantics
  ("a verifier meeting it MUST fail closed") does not fit; or
- (c) not needed at all — the existing `withdrawn` + owner-requested-removal
  pair already covers every real case seen to date, and `deprecated` should
  be dropped from the public-facing lifecycle framing rather than invented
  as a third mechanism.

This draft does not pick one. Whichever is ratified, the resolution must be
written back into REGISTRY.md's Entry Status Vocabulary table (not left as a
policy-doc-only concept) before this lifecycle framing can be called complete.

## §2 — Immutability at promotion (existing rule, cited)

No new policy. REGISTRY.md's policy header states this already: **"Entries
are immutable in behavior — if a behavior change is needed (a different
canonicalization algorithm, field set, or exclusion set), a new entry MUST be
registered; an entry's registered behavior MUST NOT be modified
retroactively."** The two narrower exceptions (a factual bibliographic
correction, or a lifecycle status transition) are also already stated there
and are unchanged by this document. Included here only so this policy
document is a self-contained description of an entry's full life; the
normative text remains REGISTRY.md's.

## §3 — Designated Expert panel: reviewers from ≥2 organizations

**New policy.** REGISTRY.md's Designated Expert Admission Checklist requires
DE review as a merge precondition per entry, but does not currently require
that the DE panel, taken as a whole, span more than one organization. This
matters specifically because CPB is a cross-organization neutral registry:
a panel drawn entirely from one registrant's own organization is exactly the
appearance-of-capture problem a neutral registry exists to avoid, independent
of whether any individual reviewer acted in good faith.

**Proposed rule:** the standing Designated Expert panel for CPB's two
registries MUST include reviewers from at least two distinct organizations.
A specific entry's DE assignment (REGISTRY.md's existing per-entry mechanism)
is unaffected by this — what changes is that the *panel available to be
assigned from* must not be single-organization.

**Current panel, and the one open item (do not decide — Steven's call):**

| Expert | Organization | Status |
|---|---|---|
| Anton Sokolov | TalTech / Tyche Institute | Active — named DE reviewer on every entry seen to date (`machine-mandate`, `mesh-inference-exchange`, `cll-checkpoint`/`mmr-checkpoint`) |
| **TBD — third designated expert** | — | **Not decided. Manu Sheel Gupta (libp2p / VTO) has been proposed. Steven Mih makes the final appointment — this draft does not.** |

This table intentionally does not name a second confirmed expert beyond
Anton. Steven and Anton should treat naming the panel to ≥2-organizations-and-
beyond as part of ratifying this section, not something this draft resolves
by proposing a name itself.

## §4 — The IANA-forwarding clause

**New policy — this is what makes `provisional` safe to build against today.**

CPB's registries are, for now, interim: REGISTRY.md's policy header already
states the change controller is "Action State Group, Inc. (interim) → IETF
on publication," and that the registry home moves with the document through
adoption to IANA at RFC publication. What is not yet stated anywhere is the
guarantee an implementer actually needs before committing code to a
provisional or promoted CPB identifier ahead of that transfer:

> **Clause.** An identifier registered in either CPB registry — a
> canonicalization-algorithm token or an artifact-type name — that is live
> (`owner-confirmed`, `third-party-documented`, or `standards-referenced`) or
> `provisional` at the time CPB's IANA Considerations section establishes the
> corresponding IANA registries (at RFC publication) is carried forward to
> that IANA registry **under the same identifier string, with the same
> registered semantics**. The identifier does not change, is not
> re-adjudicated from scratch, and does not lose its accumulated
> vector-backed conformance history solely because of the transfer. A
> `provisional` entry is not "promoted" by the transfer itself — it remains
> exactly as provisional under IANA stewardship as it was under this interim
> registry, subject to the same promotion gates — but its *name* is
> guaranteed stable across the move.

**Analog: RFC 7120 early allocation.** This clause is CPB's registry-level
counterpart to [RFC 7120](https://www.rfc-editor.org/rfc/rfc7120)'s
"Early IANA Allocation of Standards Track Code Points" — the mechanism that
lets implementers build against an IANA code point *before* the defining
document reaches RFC status, on the understanding that early-allocated
values are not reassigned out from under them absent exceptional
circumstance (RFC 7120 §3). CPB's situation is the mirror image: the
registries exist and are actively used *before* IANA hosts them at all, so
the guarantee an implementer needs runs the other direction — not "this
early value won't be revoked before publication," but "this pre-IANA value
won't be renamed or reassigned *at* publication." Citing RFC 7120 as the
analog rather than inventing new vocabulary is deliberate: implementers
already reason about early-allocation stability guarantees, and this clause
asks them to trust the same shape of promise, pointed at the opposite end of
the same transition.

**What this clause does not do.** It does not freeze an entry's *content* —
immutability-at-promotion (§2) already governs that, separately, for
promoted entries. It does not guarantee a `provisional` entry will ever be
promoted — only that if and when either registry is transferred to IANA,
whatever an entry's status was immediately before transfer, its **identifier
string** survives the move unchanged. This is narrower than a promotion
guarantee and is exactly the guarantee "safe to build on while provisional"
requires — nothing more.

## §5 — Ratification

This document is not policy until both sign-offs below are recorded, with
date and form (PR approval, on-record email, or an explicit written
statement quoted here) — the same evidentiary bar REGISTRY.md's own Gate C
uses for owner acknowledgment.

| Party | Sign-off | Date | Form |
|---|---|---|---|
| Steven Mih (Action State Group) | **PENDING** | — | — |
| Anton Sokolov (TalTech / Tyche Institute) | **PENDING** | — | — |

**Open items that ratification must resolve, not this draft (see inline TBDs above):**

1. §1 — what `deprecated` actually means, reconciled with `withdrawn` and
   owner-requested removal (three options given, none chosen).
2. §3 — the third Designated Expert appointment (Manu Sheel Gupta proposed;
   Steven's decision).

On ratification, a follow-up PR folds the resolved text into REGISTRY.md
proper (the Entry Status Vocabulary table for §1's resolution, and the
Designated Expert Admission Checklist for §3's panel requirement) so this
document's content does not live only here indefinitely — this file is a
staging document for ratification, not a second permanent home for policy
text that belongs in REGISTRY.md.
