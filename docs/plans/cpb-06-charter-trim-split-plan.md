# `-06` charter-trim split plan — 2026-09-15

**Status.** Phase 1 deliverable for `[cpb-06-charter-trim]`. **Phase 0 is not
clear**: Henk Birkholz has not replied (last note 2026-09-14 17:21 UTC), and
Anton Sokolov has not consented to the scope below at any SHA. **Nothing in
this document has been drafted into the spec.** No `-06` `.md`/`.txt`/`.xml`
exists on this branch. This is the table Steven sends to Anton (and, if he
agrees, to Henk) before any editing starts.

**Supersedes `[cpb-06-acknowledgments]`.** That item's branch
(`cpb-06-acknowledgments`, commit `76132c6`, stacked on `origin/main` at
`8ad37a5` / PR #88) is an acknowledgments-only `-06`, unposted. **Fold, don't
post it**: its diff (adding Imran Siddique as a contributor, widening the
opening sentence from "IETF 126 hackathon" to "hackathon ... or through
public review afterward") is small and self-contained, and should land inside
whatever `-06` this plan produces rather than burn a revision on a change
that reads as "nothing moved" to the exact reviewer who said the document is
too wide. Its content is captured in the KEEP row for Acknowledgments below.
Its own PR should stay open, unmerged, until this task's gate decision is
made — if the scope trim is rejected, that PR is still the fallback.

## Measurements this plan is built from

Re-verified against `spec/draft-mih-sokolov-scitt-payload-binding-05.txt`
(`origin/main` `6ba7c77`, 2688 lines, **47 form-feeds**, matching the task
brief). Page numbers below are the TOC's own page numbers; line numbers are
`grep -n` section-header hits in the `.txt`. §8 measures 1029–1422 = **393
lines** (task said "395," consistent within form-feed rounding) across
pp.19–26.

## Section-by-section table

| § | Title | Current pp. | Current lines | Disposition | Est. post-trim |
|---|---|---|---|---|---|
| 1 | Introduction (+1.1 Out of Scope) | 4–5 | 128 | **REWRITE** — lead supply-chain, agents one sentence | ~65–90 lines |
| 2 | Changes from -04 | 6 | 38 | **UNSTATED** — becomes Changes-from-05; not in task's KEEP/MOVE list | flag, ~40 est. |
| 3 | Conventions and Definitions | 7–8 | 127 | **KEEP** | 127 |
| 4 (stem) | Canon. Algorithm Registrations (stem) | 9 | 75 | **KEEP** (stem text applies to 4.1/4.4) | 75 |
| 4.1 | Algorithm jcs | 10 | 48 | **KEEP** | 48 |
| 4.2 | Algorithm jcs-n (Withdrawn) | 11–12 | 110 | **COMPRESS** to one line + pointer to `docs/audits/jcsn-withdrawal-audit-2026-08-18.md` | ~5 |
| 4.3 | Algorithm cde-n (Withdrawn) | 13 | 27 | **COMPRESS** to one line + pointer (same audit doc pattern) | ~5 |
| 4.4 | Algorithm as-transmitted | 14 | 62 | **KEEP** | 62 |
| 5 + 5.1 | Derived Identifier + Representation | 15–16 | 77 | **KEEP** | 77 |
| 6 + 6.1/6.2 | Envelope Conventions | 16–17 | 94 | **KEEP** | 94 |
| 7 + 7.1 | Statement-to-Receipt Binding + Leaf Construction | 18 | 55 | **KEEP** | 55 |
| **8 + 8.1–8.5** | **Typed Digest References (Information Model)** | **19–26** | **393** | **MOVE OUT — all of it.** See "§8 destination" below | 0 (in this doc) |
| 9 | Profile Independence | 26 | 13 | **MOVE OUT** | 0 |
| 10 | Discovery Mirror | 26 | 28 | **MOVE OUT** | 0 |
| 11 | Extensibility and Cross-Cutting Facilities | 27 | 10 | **MOVE OUT** | 0 |
| 12 (stem) | Security Considerations (stem) | 27 | 1 | **KEEP** (stem) | 1 |
| 12.1 | Preimages Are Bytes, Not Renderings | 27 | 11 | **KEEP** (explicit in brief) | 11 |
| 12.2 | Low-Entropy Fields | 27 | 25 | **KEEP** (explicit in brief) | 25 |
| 12.3 | Float Values and Digest Reproducibility | 28 | 21 | **KEEP** (explicit in brief) | 21 |
| 12.4 | Immutable Coordinates | 28 | 33 | **UNSTATED** — not named in KEEP or MOVE | flag |
| 12.5 | Tamper Evidence and Runtime Honesty | 29 | 9 | **UNSTATED** | flag |
| 12.6 | Long-Term Verifiability Considerations | 29 | 18 | **UNSTATED** | flag |
| 13 | Privacy Considerations | 29 | 46 | **KEEP** | 46 |
| 14 + 14.1/14.2 | IANA Considerations (registry) | 30–33 | 201 | **KEEP** — "the registry is the point" | 201 |
| 15 | Related Work | 34 | 76 | **MOVE OUT** | 0 |
| 16 (Refs) | References | 35–36 | 211 | **KEEP** | 211 |
| App. A | Synthetic Registration Walkthrough | 39 | 80 | **MOVE OUT** | 0 |
| App. B | Synthetic Two-Slot Composition | 40–41 | 77 | **MOVE OUT** | 0 |
| App. C | Field-Verified Instances | 42–46 | 249 | **MOVE OUT** | 0 |
| App. D | Profile-Owned Payload Carriage Example | 46 | 95 | **UNSTATED** — not named; content is §8-adjacent (payload carriage) | flag, likely MOVE with §8 |
| — | Acknowledgments | 47 | 66 | **KEEP, folds `[cpb-06-acknowledgments]`** — see cross-reference collision below | ~45–66 |
| — | Authors' Addresses | 48 | 41 | **KEEP** (boilerplate) | 41 |

Four items are **not covered by the task's proposed KEEP/MOVE list** and are
left `flag`ged rather than decided here, per "nothing decided" in the DONE
criteria:

- **§2 Changes from -04** — every prior `-0N` has carried one; presumably
  becomes "Changes from -05" and stays, but the brief doesn't say so.
- **§12.4–12.6** (Immutable Coordinates, Tamper Evidence, Long-Term
  Verifiability) — the brief names only 12.1–12.3 ("preimages-are-bytes,
  low-entropy fields, floats") as the canonicalization-bearing subset of
  Security Considerations. 12.4–12.6 read as bearing on receipt/witness
  behavior, not canonicalization, so they're plausible MOVE candidates, but
  that's a guess, not a decision.
- **Appendix D** (Profile-Owned Payload Carriage Example) — not named in
  either list. It is worked examples of §8.4 Payload Carriage, so the natural
  reading is it travels with §8's move, but naming it explicitly avoids
  losing 95 lines by omission.

## Cross-reference collision: Acknowledgments cites the material being moved

The current Acknowledgments section (line 2581–2646, kept per the brief and
the fold-in target for `[cpb-06-acknowledgments]`) is not self-contained —
two bullets cite Appendix C by cross-reference:

- Anton Sokolov's bullet: *"the A2A boundary-seal instance in {{appendix-c}}."*
- The Iman Schrock / two-computation bullet: *"The vector set cited in
  {{appendix-c2}} contains those two computations."*

If Appendix C moves out of the document (per the KEEP table above), these two
bullets break unless rewritten to point at wherever §8/Appendix C ends up
living — which is exactly the open question below. **This is a second
instance of the same dependency**, not a new one: it means the Acknowledgments
fold and the §8-destination decision cannot be sequenced independently: the
Acknowledgments text can't be finalized until §8's destination is chosen.

## A supporting observation for Jon's meta-content-type concern

`-05` §1.1 Out of Scope already disclaims, in its own words: *"Artifact types
and their digest contexts — which named categories of structured content
exist, what fields and exclusion sets each declares... CPB defines no
artifact-type registry."* §8 then spends 8 pages defining exactly a
mechanism for declaring artifact types and resolving their digest contexts.
The document already says, in its own scope statement, that this is not its
job. That internal tension is independent evidence for Jon's read and belongs
in the trimmed Introduction's rationale for the cut, not just the review
citation.

## The test the trim must pass

Per the brief: without §8, CPB must say only *"these bytes were canonicalized
this way"* and never *"this digest points at a thing of type X."* Checking
the KEEP list against that test: §4 (algorithm registry — names a
construction, not an artifact type), §5 (derived identifier), §6 (envelope
carriage of a digest, not of a typed reference), §7 (receipt binding) all
describe *how a digest was produced and carried*, never *what kind of thing
it identifies*. The KEEP list, taken as specified, passes the test. **The
open items above (§2, §12.4–12.6, Appendix D) do not currently threaten this**
— none of them introduce a type field — but Appendix D should be confirmed
moved before final draft, since worked examples are exactly where a
"payload-of-payloads" framing could re-enter informally.

## Page estimate — honest number, not fit to target

Body-content line sum for the sections marked KEEP/REWRITE/COMPRESS above
(§1 rewritten at the midpoint of its estimated range, §2/§12.4–12.6/App. D
excluded pending the flags above, Acknowledgments at its current 66-line
length before any edit for the cross-reference collision):

```
  75 (§1, rewritten estimate)  +  38 (§2, unresolved, counted as-is)
+ 127 (§3) +  75 (§4 stem) +  48 (§4.1) +  10 (§4.2/4.3 compressed)
+  62 (§4.4) +  77 (§5) +  94 (§6) +  55 (§7)
+  58 (§12 stem+12.1-12.3) +  46 (§13) + 201 (§14) + 211 (Refs)
+  66 (Acknowledgments) + 41 (Authors' Addresses)
= 1284 lines
```

At the document's own observed density (395 lines / 7 pages = **56.4
lines/page**, from §8's measured span): **1284 / 56.4 ≈ 23 pages of body
content**, plus front matter (title page, Abstract, Status of This Memo,
Table of Contents — currently pp.1–3, and largely fixed overhead independent
of body length, though the TOC itself shrinks a lot with 20 fewer headings)
at an estimated **2.5–3 pages**.

**Honest total: ≈ 25–26 pages, not 15–18.**

This is over target even with §1 aggressively rewritten and §4.2/4.3
compressed to a pointer. The three largest surviving costs are §14 IANA
(201 lines, ~3.6pp — kept whole because "the registry is the point"), the
Reference list (211 lines, ~3.7pp), and §3 Conventions (127 lines, ~2.3pp).
Hitting 15–18pp from here needs either accepting a higher number than Jon's
literal ask, or additional compression choices beyond what the brief
specifies (e.g., trimming the reference list, or tabulating rather than
prosifying §3) — **those are scope calls for Anton, not something decided in
this plan.**

## Where does §8 go? — NEEDS STEVEN + ANTON

Restating the brief's framing: AAC and the composition draft both depend on
typed digest references, and §8.1 Cross-Profile Comparability is what the
`urn:action-state:aac-aep-scitt:digest-binding` vector demonstrates and what
AAC-04 cites. This CPB trim cannot silently orphan that dependency.

- **(a) New short I-D.** Cleanest boundary — a document whose whole charter
  is "typed digest references," which is a better answer to "is this
  adjacent to SCITT" than folding it into either CPB or AAC. Cost: a second
  I-D to shepherd, a second adoption call, and a new home for the
  Cross-Profile Comparability vector's normative reference.
- **(b) Fold into AAC.** Keeps the machinery next to its only real consumer
  today. Cost: AAC becomes the document that defines a general-purpose
  citation-binding mechanism, which cuts against AAC's own scope discipline
  and reintroduces "leans on Agent Action Capsule" one layer down — anyone
  wanting typed digest references without AAC now has to import an
  agent-shaped document to get them.
- **(c) Non-I-D application note.** Cheapest, fastest, no new adoption call.
  Cost: it stops being a normative reference anything can cite by RFC
  number — AAC-04 and the composition draft would need to either restate the
  mechanism themselves or accept a non-normative pointer, which weakens
  exactly the interoperability property Jon called "in and useful."

**This is the same question as `[cpb-aac-entry-nonlive-repair]` Q1 and
`[capsule-registry-governance-repair]` Defect 1** — where profile-owned
material lives once CPB stops carrying it. The brief is explicit: answer it
once, and all three tasks must agree on the same answer. Not decided here.

## Note for Steven to send Anton

> Jon Geater's SCITT-list review (2026-09-14) calls CPB "adjacent" to
> charter as written: the canonicalization-declaration core is useful, but
> §8's typed-digest-reference machinery and the Agent Action Capsule / Agent
> Passport framing read as scope creep from a WG reviewer's seat. The fix
> under discussion is a `-06` that keeps the canonicalization declaration
> (registry, derived identifier, envelope/receipt binding, the
> canonicalization-relevant half of Security Considerations, Privacy, IANA)
> and moves out Typed Digest References (§8, 8 pages), Profile Independence,
> Discovery Mirror, Extensibility, Related Work, and the three evidence
> appendices — roughly 30 of 47 pages. Measured honestly, even that cut lands
> the document at ~25 pages, not the ~16 Jon suggested, because the kept
> registry and reference sections alone run ~14 pages. The open question with
> real cost is where the moved §8 material lives afterward, since AAC-04 and
> the composition draft both cite it today (three options on the table: a new
> short I-D, fold into AAC, or a non-normative application note) — that answer
> has to be the same across CPB, AAC, and capsule-registry, and it's the part
> that needs your sign-off before anyone touches the `.md`. Nothing has been
> drafted; this is the split plan for your review at commit `ef06aca`
> (branch `cpb-06-charter-trim`, held for EM push).

## Fold/supersede statement

`[cpb-06-acknowledgments]` (branch `cpb-06-acknowledgments`, `76132c6`) is
**folded, not superseded** — its diff is small, uncontroversial, and already
reviewed-shaped (widens the "hackathon-only" framing, adds Imran Siddique).
It should be cherry-picked or hand-applied into whichever `-06` eventually
gets drafted once Phase 0 clears, rather than merged on its own. Its PR
should stay open and untouched (not posted, not closed) until the scope
decision lands, per the brief's "if the scope decision below goes the other
way, that item's PR is still there and nothing is lost."
