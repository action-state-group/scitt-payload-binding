---
title: "Canonical Payload Binding: A Signed Statement Construction Profile"
abbrev: "Canonical Payload Binding"
docname: draft-mih-sokolov-scitt-payload-binding-02
category: std
submissiontype: IETF
ipr: trust200902
area: "Security"
workgroup: "SCITT"
keyword:
 - SCITT
 - canonicalization
 - payload binding
 - derived identifier
 - typed digest reference
stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 - ins: S. Mih
   name: Steven Mih
   organization: Action State Group, Inc.
   email: spec@actionstate.ai
 - ins: A. Sokolov
   name: Anton Sokolov
   organization: Tyche Institute
   email: anton.sokolov@tyche.institute

normative:
  RFC2119:
  RFC8174:
  RFC8126:
  RFC8259:
  RFC8785:
  RFC9052:
  RFC9943:

informative:
  RFC9901:
  RFC9942:
  RFC9995:
  RFC4998:
  I-D.ietf-scitt-receipts-ccf-profile:
  I-D.mih-scitt-agent-action-capsule:
    title: "An Agent Action Capsule Profile for SCITT"
    seriesinfo:
      Internet-Draft: draft-mih-scitt-agent-action-capsule-02
    author:
      - ins: S. Mih
        name: Steven Mih
        organization: Action State Group, Inc.
  I-D.hillier-scitt-arp:
    title: "Attestation Reconciliation Protocol"
    seriesinfo:
      Internet-Draft: draft-hillier-scitt-arp-01
    author:
      - ins: J. Hillier
        name: Joel Hillier
  I-D.mih-sato-agent-accountability-composition:
    title: "Agent Accountability: Composition and Conformance"
    seriesinfo:
      Internet-Draft: draft-mih-sato-agent-accountability-composition-00
    author:
      - ins: S. Mih
        name: Steven Mih
        organization: Action State Group, Inc.
      - ins: T. Sato
        name: Tom Sato
  I-D.sokolov-rats-aep-composition:
    title: "Composing Application-Layer Action Evidence with Remote Attestation Procedures"
    seriesinfo:
      Internet-Draft: draft-sokolov-rats-aep-composition-03
    author:
      - ins: A. Sokolov
        name: Anton Sokolov
        organization: Tyche Institute
  I-D.birkholz-verifiable-agent-conversations:
    title: "Verifiable Agent Conversations"
    seriesinfo:
      Internet-Draft: draft-birkholz-verifiable-agent-conversations-00
    author:
      - ins: H. Birkholz
        name: Henk Birkholz
        organization: Fraunhofer Institute for Secure Information Technology
  I-D.rampalli-pedigree:
    title: "PEDIGREE: Provenance and Delegation Records for Digital Artifacts"
    seriesinfo:
      Internet-Draft: draft-rampalli-pedigree-00
    author:
      - ins: K. Rampalli
        name: Karthik Rampalli
        organization: Glyphzero, Inc.
  I-D.lee-orprg-permit-receipts:
    title: "Permit Receipts for Permit-Before-Commit Authorization of AI-Agent and Workload External Effects"
    seriesinfo:
      Internet-Draft: draft-lee-orprg-permit-receipts-00
    author:
      - ins: Y. Lee
        name: Yong Bok Lee
        organization: Meridian Verity Group

--- abstract

Independently written systems that anchor records to a SCITT Transparency
Service repeatedly re-derive the same construction: a canonical form of
structured content, a content-addressed identifier derived from that form, a
receipt placed in the unprotected header of the Signed Statement, and a typed
reference mechanism that lets one record cite another by digest across profile
boundaries. This document defines that construction as a reusable profile —
the Canonical Payload Binding — so that each payload class declares its
canonicalization algorithm and exclusion set once, obtains an interoperable
derived identifier, and inherits statement-to-receipt binding and typed
digest reference semantics without restating the mechanics in every profile.
It complements the COSE Hash Envelope mechanism defined in RFC 9995: where
that mechanism signals that a Signed Statement's payload is a digest
standing in for content held elsewhere, this document defines how that
digest is computed from structured content so that independently written
implementations converge on the same bytes. An IANA registry governs the canonicalization
algorithms; entries are immutable. This document defines no payload content
formats and registers no artifact types; the artifact types that a typed
reference may cite, and their meaning, are declared by the payload profiles
that use this construction as their binding layer.

--- note_Note_to_Readers

This document is an individual submission. The intended venue is the SCITT
Working Group (scitt@ietf.org). Named attributions and acknowledgments in this document were individually
confirmed in writing by the named parties.
The short name "Canonical Payload Binding" and the document title are
expected to be settled by the adopting working group.

The source of this document and the companion interop record are maintained
at: https://github.com/action-state-group/scitt-payload-binding

--- middle

# Introduction {#intro}

Systems that anchor structured content to a SCITT Transparency Service
{{RFC9943}} face a common sub-problem: how does a producer turn a JSON or
CBOR object into a content-addressed Signed Statement whose identifier
survives serialization, and how does a verifier check that the identifier
in hand matches the bytes in hand? Each answer involves the same four
moves — canonicalize, derive an identifier, bind a receipt, cite externals
by digest — but they have been restated independently in every profile that
needed them, with small variations that defeat interoperability.

This document extracts those four moves into a single reusable profile
called the Canonical Payload Binding (CPB). CPB is the missing piece the COSE
Hash Envelope mechanism {{RFC9995}} deliberately leaves open: RFC 9995 defines
how a Signed Statement signals that its payload field carries a hash rather
than the content itself, but it does not say how that hash is computed from
structured content so that two independently written implementations arrive
at the same bytes. CPB fills that gap and stops there — it defines the
canonicalization algorithm, the derived identifier it produces, the binding
of that identifier to a Signed Statement and its Receipt, and a typed
reference mechanism for citing other digests, and it defines nothing about
what the hashed content means. CPB is derived from
{{I-D.mih-scitt-agent-action-capsule}} (§Conventions, §envelope, §registration,
§identity), which first stated the construction in a SCITT context, and
generalized at the IETF 126 hackathon in Vienna, where seven parties
participated in the public interop program. The public record reports four
codebases demonstrating byte agreement in specific shared, declared contexts.
Other frozen artifacts retained separately declared digest contexts. ORPRG
retained its CP-JSON-2 context and was represented in the interop design through a typed reference rather
than through an assertion of cross-profile digest equality. Digests remain
governed by their original contexts; CPB does not relabel an ORPRG CP-JSON-2
commitment as a CPB canonicalization algorithm's output. The provenance is
stated here once and not repeated in subsequent sections.

For generic citation-binding verification, a CPB verifier can process a
typed reference to any artifact type whose digest context it can resolve.
Whether a particular citation slot permits that artifact type is determined
by the consuming profile. Artifact-specific appraisal, authorization
semantics, and application integration remain separate.

Supporting a new artifact type requires no change to this document's
citation-binding algorithm. Declaring the type, its digest context, and its
meaning is a matter for the payload profile that defines it; it may also
require consuming-profile integration and artifact-specific appraisal.

## Out of Scope {#outofscope}

This document does not define:

* Payload semantics — what fields a payload contains, what their values mean,
  or what verdicts or decisions are carried. Those belong to payload profiles
  that use CPB as their binding layer.

* Artifact types and their digest contexts — which named categories of
  structured content exist, what fields and exclusion sets each declares,
  and which purpose labels its digest contexts use. Artifact types are
  registered in the shared Artifact Type Registry, governed separately from
  this document; CPB defines only the algorithms and the typed-reference
  container they use. (See {{I-D.mih-scitt-agent-action-capsule}} for an
  example payload profile that registers artifact types there.)

* Application meaning — the real-world interpretation of any record
  anchored via this construction.

* Transparency Service registration policy — which records a Transparency
  Service will or must accept. Registration policy is a Transparency Service
  concern, not a statement profile concern.

* Transports — how registration requests or retrieval queries travel between
  producers, Transparency Services, or verifiers.

# Changes from -01 {#changes-01}

The most consequential correction since -01 is registry-level: the registry
was re-derived from what the field actually built, not from what -01
originally specified. `jcs-n`, live and Registered in -01, is withdrawn;
`jcs` — the construction every independent implementation actually
converged on — is registered in its place. The rest of this revision
consolidates registry, canonicalization, and conformance-checker work
landed since -01 was posted, and rescopes the document to its charter.

**Charter rescope.** This document no longer normatively defines the
Artifact Type Registry or any artifact-type-specific payload-shape rule.
What changes is governance ownership, not location: `REGISTRY.md` does not
move, and stays in this repository as the shared home for both registries
this document's ecosystem uses. The Canonicalization Algorithm Registry
({{iana-alg}}) remains CPB-normative. The Artifact Type Registry — its
registration template, the purpose-label vocabulary, and both live entries
(`agent-action-capsule`, `machine-mandate`) — is governed separately, by
its own Designated Expert checklist and registration rungs already stated
in `REGISTRY.md`, and this document references that registry rather than
defining it. It is a single shared registry, not a per-profile one:
{{I-D.mih-scitt-agent-action-capsule}} registers artifact types there
alongside any other payload profile that wants to, TRACE, EMILIA, PEDIGREE,
HaltSeal, and GAR among them, each citing a CPB algorithm for its
canonicalization; no one profile owns the registry. The worked walkthrough
of Artifact-Type-Registry governance (Specification Required / Designated
Expert / third-party registration) that -01 carried as an appendix is
removed from this document, not moved — it belongs beside the registry it
documents, in `REGISTRY.md`, where it already lives. This document now
anchors {{RFC9995}} and keeps only the canonicalization algorithm(s), the
derived identifier, Signed-Statement and Receipt binding, and the typed
digest-reference container; the Abstract's former claim that this document
governs "the artifact types" is corrected.

**Registry.**

* A machine-readable `registry.json` is now generated by CI from
  `REGISTRY.md`; releases pin a snapshot. A lookup against an identifier
  absent from the pinned snapshot but potentially valid in a later snapshot
  now returns a distinct verdict, `id-unknown-to-snapshot`, rather than
  being indistinguishable from a genuinely unknown identifier.
* `REGISTRY.md` gained an onboarding ladder and a controlled entry-status
  vocabulary (`owner-confirmed`, `third-party-documented`, `provisional`,
  `standards-referenced`), a three-rung registration path (owner-authored /
  third-party-documented / provisional) with a template, lifecycle, and
  removal/correction path, and Designated Expert review stated explicitly
  as a precondition of merging an entry rather than a status a merged entry
  can still assert. This infrastructure is shared by every registry this
  file hosts, including the shared Artifact Type Registry, which
  {{I-D.mih-scitt-agent-action-capsule}} registers into alongside every
  other payload profile that does — no single profile owns it.
* The registry generator and validator now source legal status values from
  `REGISTRY.md` itself instead of a hardcoded list, and reject a malformed
  table row (mismatched cell/header count) closed instead of silently
  mis-assigning columns; a small number of rows that predate the controlled
  vocabulary are named explicitly as the only ones permitted a legacy
  status spelling.
* A `Reserved` placeholder token no longer reads as `Verified`: registry
  lookups previously returned a "verified" verdict on entry presence alone;
  a distinct `VERDICT_RESERVED` verdict now applies to any entry present
  but not in `Registered` status.
* The required-fields table, the "immutable" language, and the
  upgrade-acknowledgment gate were corrected: the required-fields table is
  scoped to new entries; "immutable" is stated consistently as "immutable
  in behavior"; and the acknowledgment gate now requires the same
  consuming-profile acknowledgment for an upgrade to `owner-confirmed` that
  it already required for initial admission, closing a path where an owner
  could file without an acknowledgment and self-acknowledge afterward.

**Canonicalization algorithms.** `jcs` — plain RFC 8785 JCS, no
normalization pass — is registered ({{algo-jcs}}), with a named consuming
profile and a discriminating vector against `jcs-n`: one payload carrying a
null member and an empty array (`jcs` preserves both, `jcs-n` stripped
them) plus a float member (`jcs` admits it, `jcs-n` rejected it), failing
loudly in both directions. `jcs-n` is withdrawn ({{algo-jcs-n}}) — the same
terminal-marking disposition `cde-n` already carried in -01 — following an
implementer census (the reference implementation was the only implementer
of the normalization step it added), a byte audit showing 191 of 203
evaluated records were byte-identical under plain `jcs` without that step,
the 12 divergent records being proof-of-concept artefacts retained by
vintage, and the admission bar this revision applies to every entry: a
named consuming profile. Separately,
a cross-language conformance harness (`vectors/CANONICALIZATION_DECLARATION.md`)
versions `jcs-n`'s construction precisely enough for an independent
implementation to conform against without reading the reference library;
it stands as part of the permanent historical record for the now-withdrawn
algorithm. The lowercase-`\u` string-escaping rule and the corresponding
control-character sort order — properties of RFC 8785 JCS itself, and
therefore shared by `jcs` and the withdrawn `jcs-n` alike — are now stated
in prose and cross-linked from `REGISTRY.md`. The shared JCS serialization
helper also now rejects non-finite numeric values (`Infinity`, `-Infinity`,
`NaN`) before serialization, consistent with RFC 8785 Section 3.2.2.3
admitting finite values only.

**Digest determinism and typed references.** Two paragraphs now state
explicitly what -01 only implied: each algorithm entry and each artifact
type's digest-context declaration names exactly one hash algorithm, so
`digest_alg` is fully determined by `type` (together with `purpose` where
needed) for any registered reference, and a verifier encountering a
`digest_alg` inconsistent with the resolved context MUST treat it as a
failure and MUST NOT attempt to reconcile it ({{comparability}}). A
MUST-FAIL/PASS vector pair pins that an assembled pre-image — one built
from selected source fields rather than the payload minus an exclusion
set — is under-determined by algorithm and field set alone; producer-chosen
member naming and nesting are part of the bytes. Two conformance-checker
categories exercise this: recomputing both pinned pre-images and asserting
they diverge for exactly the demonstrated reason, and applying a declared
`member_mapping` to assert it reproduces the vector's own input. Contributed
by Rul1an as an external submission, reproduced independently against the
reference canonicalizer.

**Conformance checker.** A grammar/wire-layer conformance checker
(`cpb-check`) validates a record against its declared profile grammar — a
presence-and-number-form walk and duplicate-key rejection — built around a
duplicate-preserving raw-bytes lexer, since a standard JSON parser silently
drops duplicate keys before any rule can see them; digest recomputation and
`canonicalization_id` resolution remain out of scope pending a later gate.
Vector-harness fixes landed alongside it: the lexer now rejects trailing
bytes after a JSON document ends and NFC-normalizes before duplicate-key
detection, and an inverted must-fail assertion and a `-0`/duplicate-key gap
that could previously let the harness certify a vector as passing for the
wrong reason are both closed.

# Conventions and Definitions {#conventions}

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
{{RFC2119}} {{RFC8174}} when, and only when, they appear in all capitals,
as shown here.

Payload Class:
: A named category of structured content that has declared a canonicalization
  algorithm (from the registry in {{iana-alg}}) and an exclusion set of
  fields that are omitted from the canonical form before the derived
  identifier is computed. A payload class is declared by the payload profile
  that defines it; this document does not maintain a registry of payload
  classes or artifact types.

Derived Identifier:
: The content-address of a payload: the output of CANONICAL-DIGEST applied
  to the canonical form of the payload with the exclusion set removed.
  Verifiers MUST recompute the derived identifier from the payload bytes;
  a carried derived-identifier value is advisory only and a mismatch is a
  defect.

Digest Context:
: The complete set of parameters that determine how a digest was computed:
  the field set selected, the exclusion set applied, the canonicalization
  algorithm applied, any domain separation, the encoding of the pre-image,
  and the representation of the output. Two digest values are comparable
  only when their full digest contexts are established as compatible. A
  payload class or artifact type MAY declare more than one digest context
  over the same payload, each serving a distinct purpose declared by the
  payload profile that defines the class or type; the contexts are
  independent and MUST NOT be conflated.

CANONICAL-DIGEST:
: A function parameterized by a canonicalization algorithm A: for any such
  algorithm A and payload v, CANONICAL-DIGEST(A, v) = ENCODE_A(H_A(A(v))),
  where H_A is the digest function and ENCODE_A the output encoding
  declared by A's entry in the Canonicalization Algorithm Registry
  ({{iana-alg}}). Every entry registered by this document declares SHA-256
  and 64-character lowercase hexadecimal; an entry registered by a later
  document MAY declare another digest function or encoding, and a verifier
  MUST read both from the entry rather than assuming them. A(v) is the
  octet string produced by the algorithm applied to v; the specific
  pre-image construction — field selection, normalization, and encoding —
  is part of A's definition and is registered per {{iana-alg}}.

Signed Statement:
: A COSE_Sign1 object {{RFC9052}} that carries a payload, a protected
  header, and an optional unprotected header; defined in {{RFC9943}}.

Receipt:
: A COSE structure produced by a Transparency Service that provides
  verifiable evidence that a Signed Statement was registered; defined in
  {{RFC9943}} and format-governed by the Verifiable Data Structure of the
  service.

Transparent Statement:
: A Signed Statement to whose unprotected header one or more Receipts have
  been attached.

Verifier:
: Any party that validates a record from its bytes, without trusting the
  producer.

# Payload Canonicalization Algorithms {#algorithms}

A canonicalization algorithm specifies how to produce a canonical octet string
from a structured value. The canonical octet string is the pre-image to
CANONICAL-DIGEST. A payload class declares exactly one canonicalization
algorithm; verifiers MUST NOT guess the algorithm from the payload shape.

The algorithms defined in this document and registered in the Canonicalization
Algorithm Registry ({{iana-alg}}) are:

| Name | Summary | Reference |
|---|---|---|
| jcs | Plain RFC 8785 JCS, no normalization pass; SHA-256; lowercase hex output | {{algo-jcs}} |
| jcs-n | Withdrawn -- JCS + absent-field normalization; never carried to IANA | {{algo-jcs-n}} (withdrawn) |
| cde-n | Withdrawn -- token reserved, never assigned a definition | {{algo-cde-n}} (withdrawn) |
| as-transmitted | No canonicalization; digest over a byte sequence fixed by a cited named production in the container format; SHA-256; 64-character lowercase hex | {{algo-as-transmitted}} |

Entries in the Canonicalization Algorithm Registry are immutable: new
behavior requires a new entry, never a retroactive edit to an existing one.
A reserved entry binds its token only; its summary is provisional until the
entry is defined, at which point the full entry becomes immutable. A reserved
entry may instead be withdrawn ({{algo-cde-n}}, {{algo-jcs-n}}), which is
terminal: the token stays bound, no definition is ever assigned (or, for an
entry that was already defined, no further definition ever attaches to it),
and the name is not reassigned. The hash function is part of each algorithm's
definition; migration to a different hash (for example, a future
post-quantum function) is performed by registering a new algorithm entry,
never by reinterpreting an existing one.

## Algorithm jcs {#algo-jcs}

Algorithm `jcs` is the JSON Canonicalization Scheme {{RFC8785}} applied
directly to the payload, with no normalization pass: no member is removed
because its value is JSON null, an empty array, or an empty object.

Pre-image construction:

1. Apply JCS {{RFC8785}} to the octets supplied to the algorithm, to
   produce the canonical UTF-8 octet string. Exclusion-set removal is not
   part of this algorithm: the derived identifier construction
   ({{derived-id}}) removes the payload class's declared exclusion set
   before invoking the algorithm.

2. Compute SHA-256 over those octets.

3. Encode the digest as lowercase hexadecimal. The output is a 64-character
   ASCII string.

The CANONICAL-DIGEST of a payload P using `jcs` is therefore:

~~~
CANONICAL-DIGEST(jcs, P) =
    lowercase_hex(SHA-256(JCS(P)))
~~~

The exclusion set is matched against the top-level member names of P only;
a member of the same name nested inside a member's value is not removed.

`jcs` places no additional restriction on JSON numbers beyond RFC 8785 itself:
a JSON floating-point number is permitted and is serialized per the
canonical ECMAScript-based number-to-string procedure RFC 8785 {{RFC8785}}
Section 3.2.2.3 defines for IEEE 754 double-precision values. Two conforming
implementations that parse the same numeric literal into the same
double-precision value therefore produce byte-identical output; see
{{floats}}. A payload profile MAY still declare its own stricter constraint
(for example, requiring monetary fields to be exact decimal strings) — such a
constraint is a payload-profile decision, not a requirement of this
algorithm.

## Algorithm jcs-n (Withdrawn) {#algo-jcs-n}

Algorithm `jcs-n` is withdrawn (2026-08-18) -- terminal marking, never
deletion: the token stays bound, the definition it once carried is not
reassigned, and it is never carried forward to IANA. That is a terminal
marking that `cde-n` ({{algo-cde-n}}) also carries, though on different
facts: `cde-n` never acquired a definition, while `jcs-n` did and its
records remain verifiable by vintage. `jcs-n` applied JCS {{RFC8785}} to an
absent-field-normalized JSON object -- the normalization step removed,
bottom-up and recursively, every member whose value was JSON null, an empty
array, or an empty object, before JCS serialization. The full original
construction is the permanent record in
draft-mih-sokolov-scitt-payload-binding-00, Section 3.1, and is not restated
here.

The withdrawal followed from an implementer census (the reference
implementation was the only implementer of the normalization step), a byte
audit showing 191 of 203 evaluated records were byte-identical under plain
`jcs` without it, the 12 divergent records being proof-of-concept artefacts
retained by vintage, and the admission bar this document now applies to
every entry: a named
consuming profile. `jcs` ({{algo-jcs}}) is the entry that replaces it going
forward; a payload class or typed digest reference that named `jcs-n` used
the withdrawn construction described above, and a party citing that
historical construction going forward registers a new entry rather than
resuming use of this token.

Withdrawal forecloses new declarations of `jcs-n`; it does not
retroactively invalidate records already sealed under it. A payload class
or typed digest reference that names `jcs-n` MUST NOT be newly declared. A
verifier encountering `jcs-n` in a record committed on or after 2026-08-18
MUST fail closed — MUST NOT report the payload class or typed digest
reference as verified. A verifier encountering `jcs-n` in a record
committed before 2026-08-18 MAY verify it against the withdrawn
construction as that construction is permanently recorded in
draft-mih-sokolov-scitt-payload-binding-00, Section 3.1; such a record is a
historical record, not a live conformance case, and a verifier that
declines to implement the withdrawn construction MUST report the reference
as unverified rather than as failed. A historical identifier MUST NOT be
relabelled to another algorithm token or recomputed under another
algorithm.

## Algorithm cde-n (Withdrawn) {#algo-cde-n}

Algorithm `cde-n` is withdrawn. It is a recorded terminal state, not a
deletion: the token was reserved for a deterministic CBOR canonicalization
profile, but it was never assigned a definition, and it will not be. The
entry remains in the Canonicalization Algorithm Registry ({{iana-alg}}) as
withdrawn -- the reserved entry bound the token, so the token stays bound,
never assigned, never reassigned. A future deterministic CBOR
canonicalization profile, if one is specified, is registered under a new
token rather than by assigning a definition to `cde-n`.

A payload class or typed digest reference that names `cde-n` cannot be
verified: the token names no defined algorithm and never will, so a
verifier encountering it MUST fail closed — MUST NOT report the payload
class or typed digest reference as verified.

## Algorithm as-transmitted {#algo-as-transmitted}

Algorithm `as-transmitted` applies no canonicalization. The digest pre-image
is the exact octet sequence already fixed by the container format or
cryptographic envelope carrying the payload -- for example, the signing input
over which a signature was computed. The signature (or other format-defined
byte-fixing) is what makes those bytes authoritative; re-canonicalizing them
would be redundant at best and would break the very binding that makes the
bytes authoritative at worst.

Because there is no canonicalization step, `as-transmitted` has no field set
and no exclusion set. An artifact type entry that declares `as-transmitted`
as its canonicalization algorithm MUST instead state a byte-boundary
selector in place of a field set: a normative reference plus the name that
referenced specification gives to the exact byte sequence in question. Two
examples of a valid selector:

* `RFC 7515 §5.1, JWS Signing Input` -- the octets a JWS signature is
  computed over.
* `RFC 9052 §4.4, ToBeSigned` -- the octets a COSE_Sign1 signature is
  computed over.

A selector that is not a cited named production is prose, not a selector,
and this registry exists to eliminate exactly that kind of ambiguity: an
artifact type MUST NOT register `as-transmitted` on the strength of an
uncited description such as "the payload bytes." If the container
specification carrying the artifact does not itself name the exact byte
sequence as a discrete production, the artifact type MUST NOT use
`as-transmitted` -- it registers a canonicalization algorithm instead, one
that defines the pre-image construction from first principles.

The CANONICAL-DIGEST of a byte sequence B identified by the declared
byte-boundary selector is:

~~~
CANONICAL-DIGEST(as-transmitted, B) = lowercase_hex(SHA-256(B))
~~~

Digest: SHA-256, 64-character lowercase hex, matching `jcs`. These are
stated explicitly here as part of this entry, not inherited silently from
the generic CANONICAL-DIGEST definition ({{conventions}}).

# The Derived Identifier {#derived-id}

The derived identifier of a record is computed as:

~~~
id = CANONICAL-DIGEST(A, payload minus exclusion_set)
~~~

where A is the canonicalization algorithm declared by the payload class and
the exclusion set is the set of fields declared by the payload class as
self-referential or chain-linkage fields. The derived identifier is a
64-character lowercase hex string for every algorithm this document
registers; for an algorithm registered elsewhere, its representation is the
one that algorithm's registry entry declares.

The exclusion set MUST be declared by the payload class in its specification.
Fields excluded are those that either contain the derived identifier itself
(they cannot be inside the pre-image they help compute) or that reference
other records in a chain (to keep the content-address stable regardless of
what later chains to this record). The exclusion set is normative for the
payload class; a verifier MUST apply the same exclusion set as the producer.

A producer MAY carry the derived identifier as a field in the payload.
A verifier MUST recompute the identifier from the payload bytes and the
declared exclusion set. If the recomputed value does not match the carried
value, the verifier MUST treat this as a defect in the record.

When selective disclosure is in use, the derived identifier MUST be computed over the
SD-encoded form of the payload, not the plaintext payload. A payload profile MUST
declare non-eligible for selective disclosure any field that the profile's own verifier
requires in order to evaluate the binding.

## Representation {#representation}

Representation is normative and MUST be declared by the payload class.
The following representations are distinct and are not implicitly
interchangeable:

* bare 64-character lowercase hexadecimal text;
* prefixed textual representation; and
* raw 32-byte octet sequence.

A payload class MUST specify which representation it uses for each field
containing or referencing a derived identifier. A verifier MUST NOT
silently coerce among representations.

A deterministic conversion MAY be applied only where this specification or
the applicable payload profile expressly defines both the conversion and
the resulting comparison representation. Such a conversion is an explicit
protocol operation and does not make the original representations
byte-identical.

# Envelope Conventions {#envelope}

A Signed Statement carrying a CPB-bound payload MUST be a COSE_Sign1
{{RFC9052}} structure. The protected header MUST carry:

* `alg`: the signing algorithm.
* `kid` or `x5chain`: the signing key identifier or certificate chain.
* `content_type`: the media type of the payload, as `application/CLASS+json`
  or `application/CLASS+cbor` according to the serialization the payload
  class declares, where CLASS is the payload class name as declared by the
  payload class's own defining specification.

A field belongs in the protected header only if a SCITT-generic party — a
Transparency Service registration policy or a profile-unaware verifier —
must act on it without understanding the payload class. Everything
semantically specific to the payload class stays in the payload.

Protected-header claims are a closed set per payload class: extensions
are payload-only. A Transparency Service that does not understand a
protected-header extension MUST be able to register the Signed Statement
and verify the envelope without it.

The closed-claim principle does not prevent payload-class-specific
protected-header fields from existing; it requires that such fields be
defined by the payload class specification, not added ad-hoc by producers.

# Statement-to-Receipt Binding {#receipt-binding}

A producer makes a record transparent by registering its Signed Statement
with a SCITT Transparency Service per {{RFC9943}} and attaching the returned
Receipt to the unprotected header, forming a Transparent Statement.

This profile is VDS-agnostic at the statement layer. Receipt format and
proof verification are governed by the Verifiable Data Structure (VDS) of
the Transparency Service; this profile imposes no VDS requirement.

A verifier MUST NOT report receipt-backed status without having verified
a Receipt from a Transparency Service under a key the verifier trusts.

A verifier determining which VDS to apply when verifying a Receipt MUST
read the VDS identifier from the protected header of the Receipt. The
verifier MUST NOT infer the VDS from the COSE structure of the receipt
alone. Unknown VDS identifiers MUST be rejected.

## Leaf Construction {#leaf-rule}

This profile imposes no leaf construction on a Verifiable Data Structure.
Where a Transparency Service's VDS keys its log on the derived identifier,
the derived identifier is a 32-byte value and its hexadecimal form is a
representation of that value ({{representation}}); a VDS or profile that
keys on it therefore states which of the two it uses, and producer and
verifier MUST use the same one. The following is the failure this
requirement exists to prevent.

That is, for a derived identifier whose string value is a 64-character
hex string D, the log leaf input MUST be the raw 32-byte value:

~~~
leaf_input = bytes.fromhex(D)    -- correct: 32 raw bytes
~~~

The following is incorrect and MUST NOT be used:

~~~
leaf_input = D.encode("utf-8")  -- WRONG: 64 ASCII bytes
~~~

A verifier constructing the leaf for proof verification MUST apply the same
rule. Failure to distinguish the byte sequence from its hex encoding produces
a silently wrong leaf hash that fails inclusion verification against any
correct log.

# Typed Digest References {#typed-refs}

A typed digest reference is the mechanism by which one record cites an
external artifact — another record, an authorization document, a
configuration object, or any other verifiable item — by its content-address
without embedding it.

A typed digest reference is a JSON object with the following fields:

| Field | Type | Req | Meaning |
|---|---|---|---|
| type | string | REQUIRED | The artifact type identifier. This document defines the reference container and its verification algorithm; it does not itself register artifact types or resolve `type` values to digest contexts. That resolution is provided by the shared Artifact Type Registry, into which the payload profile that declares the cited artifact type registers it (see {{I-D.mih-scitt-agent-action-capsule}} for an example). |
| purpose | string | CONDITIONAL | The purpose label selecting which of the artifact type's digest contexts this reference targets, drawn from the vocabulary the type's entry in the shared Artifact Type Registry defines. REQUIRED whenever the resolved artifact type declares more than one digest context. MAY be omitted only when the resolved artifact type declares exactly one digest context, in which case that single context applies; a verifier MUST NOT infer a default when more than one context is declared. |
| digest_alg | string | REQUIRED | The hash algorithm of the digest value (e.g., "SHA-256"). The canonicalization context of the cited artifact is resolved from the digest context selected by `type` and `purpose`, not from this field. |
| digest | string | REQUIRED | The digest of the cited artifact, in the representation declared by the selected digest context. |

Additional fields MAY be present and MUST be ignored by verifiers that do
not understand them.

## Cross-Profile Comparability {#comparability}

Within typed-reference verification, the digest carried by the reference
and the digest recomputed over the referenced artifact are comparable only
when both are interpreted under the same established referenced-artifact
digest context and comparison representation.

If the verifier cannot resolve a digest context for the value of `type`,
it MUST NOT report the typed reference as verified; the reference is
present but not verified. Two situations produce that outcome and a
verifier MUST distinguish them in what it reports, because they call for
different responses:

* The type is absent from every registry the verifier consults. No payload
  profile has declared a digest context under that name, and the citation
  becomes verifiable only once one does.
* The type is declared somewhere, but absent from the particular registry
  snapshot the verifier holds, which may predate an entry that does exist.
  The remedy is to obtain a current snapshot, not to seek a new
  registration.

A verifier that reports these as one condition sends an implementer to fix
the wrong thing. A verifier that cannot tell them apart -- because it holds
no snapshot version -- MUST report the weaker of the two, that its snapshot
may be stale.

The consuming profile determines the disposition, and a profile MUST state
what it does with a present-but-not-verified reference. A citation carrying
an unresolvable `type` is not an error in the citing record. It is also not
evidence: {{immutable-coordinates}} requires that citations pin content by
CANONICAL-DIGEST precisely so that an unverified reference cannot be relied
on, so a profile MUST NOT treat "not an error" as permission to proceed as
though the reference had verified.

To verify the reference, the verifier MUST use the `type` field, together
with the `purpose` field when the resolved artifact type declares more than
one digest context, to resolve exactly one of the referenced artifact's
declared digest contexts. If `type` resolves to more than one digest
context and `purpose` is absent, ambiguous (matching no purpose label the
resolved artifact type declares), or names a purpose label the resolved
artifact type does not declare, the reference is unresolvable: the verifier
MUST NOT guess a
context and MUST NOT report the typed reference as verified. It MUST confirm
that `digest_alg` identifies a hash algorithm consistent with the resolved
context.

`digest_alg` is REQUIRED even though every algorithm registered in
{{iana-alg}} today names the same hash, SHA-256: it is the field that lets
a future Canonicalization Algorithm Registry entry using a different hash
land as a new token without a breaking change to this wire format, rather
than being decorative because only one value is legal now.

The hash algorithm is not chosen per-reference: each entry in the
Canonicalization Algorithm Registry names its hash function as an immutable
part of its definition ({{algorithms}}), and each artifact type's own
digest-context declaration names exactly one such algorithm. `digest_alg` is
therefore fully
determined by `type` (together with `purpose` where needed): a conforming
reference can only carry the hash algorithm the resolved digest context
mandates. It is a redundant consistency declaration by design — hash-in-algorithm
is what makes Canonicalization Algorithm Registry entries immutable and enables
long-term algorithm migration by registering a new entry rather than
reinterpreting an existing one.

It MUST then recompute the referenced artifact's digest under that context and
compare the recomputed value with the value carried in the `digest` field.

**Comparison is byte-for-byte.** A verifier compares `digest_alg` against the
name the resolved digest context mandates as an exact octet sequence: no case
folding, no alias table, no whitespace trimming. `sha-256` does not match
`SHA-256`. The two IANA registries an implementer is likely to reach for
disagree on spelling for the same function, so a case-insensitive or
alias-tolerant comparison silently accepts a reference that names a different
registry's token — and once one implementation tolerates it, the field stops
being a consistency declaration and becomes decoration. The registered name is
the one the Canonicalization Algorithm Registry entry states.

A `digest_alg` value that does not name the hash algorithm mandated by the
resolved digest context is a defect in the reference. The verifier MUST treat
this as a failure and MUST NOT attempt to reconcile the inconsistency — for
example, by silently proceeding with the algorithm the registry mandates and
ignoring the mislabeled field. More generally, if the context established from
the `type` and `digest_alg` fields cannot be reconciled with the context used
to recompute the referenced artifact, or if a required deterministic conversion
to a common comparison representation is not expressly defined, the verifier
MUST NOT report the typed reference as verified. The failure verdict is mandatory
at the verifier layer; the consuming profile determines the resulting error
disposition, but not the verdict itself.

The citing record's own derived-identifier context need NOT be compatible
with the referenced artifact's digest context; those contexts govern
different computations.

The two values actually being compared must share an established comparison
context. Bare hexadecimal equality alone is not a join.

## Verification Scope {#verification-scope}

Successful verification of a typed digest reference establishes content
binding to the referenced artifact under the declared digest context. CPB
verification alone MUST NOT be interpreted as establishing issuer authority,
artifact validity, scope, freshness, revocation status, policy compliance,
semantic acceptance, or application authorization. Any appraisal required
by the referenced artifact type or consuming application profile remains a
separate verification step. Missing, indeterminate, or failed required
appraisal MUST NOT be treated as authorization success.

The interchangeability property of typed digest references -- that any
artifact type whose digest context can be resolved may fill a citation slot
-- applies to citation-binding interoperability only and does not extend to
any appraisal or authorization semantics defined by the artifact type or
consuming profile.

# Profile Independence {#profile-independence}

A payload profile MUST NOT impose requirements on the internal structure or field
values of another payload profile. Relationships between artifacts of different types
are expressed solely through typed references ({{typed-refs}}) that resolve against
each artifact type's own digest-context declaration.

This constraint keeps verification of a multi-artifact chain decomposable: a verifier
evaluates each binding under each profile's own semantics independently and never needs
to evaluate a pair of profiles jointly. Implementations therefore need not implement,
or be aware of, profiles they neither produce nor consume, and a new profile may declare
its own artifact types without revalidating existing profiles or implementations.

# Discovery Mirror {#discovery}

This section is informative.

A producer MAY place an unprotected COSE header parameter that mirrors the
derived identifier of the record. This parameter is advisory only: it
allows log tooling, registration policies, and cross-grain citation to
locate a record's content-address without parsing the payload, but it
carries no binding guarantee.

A verifier MUST recompute the derived identifier from the payload. A
mismatch between the advisory mirror value and the recomputed value is a
defect in the record and MUST be reported.

The discovery mirror parameter is aligned with the trace-metadata convention
in draft-birkholz-verifiable-agent-conversations §7.4
{{I-D.birkholz-verifiable-agent-conversations}}, which defines a similar
unprotected-header mechanism for conversation-grain records. A record using
CPB at the action grain and a conversation container using that convention
can share one discovery layer.

# Extensibility and Cross-Cutting Facilities {#cross-cutting}

This section is informative.

Several concerns are common to all payload profiles and, if defined independently per
profile, would undermine decomposable verification or fragment the interoperability
surface: selective disclosure, countersignature and multi-party attestation, record
relations (supersedes, confirms, corrects), erasure tombstones, producer timestamps
and validity periods, batch aggregation, and profile versioning.

This specification does not define these facilities in this document. Each will be
addressed in a companion document that payload profiles MUST reference rather than
developing an incompatible per-profile variant. Defining any of these facilities
per-profile would violate the constraint established in {{profile-independence}}.

# Security Considerations {#security}

## Preimages Are Bytes, Not Renderings

The pre-image of a CANONICAL-DIGEST is the octet string produced by the
canonicalization algorithm — not a rendered form, not a console output, and
not a string with added whitespace, trailing newlines, or encoding
differences. A producer that serializes then re-reads the payload before
computing the digest MUST ensure the byte sequence entering SHA-256 is
identical to what the canonicalization algorithm produces, not what a
deserializer happens to emit. Diagnosing divergence requires comparing the
exact octets, not visual representations.

## Low-Entropy Fields

A digest hides its pre-image only to the degree the pre-image space is large
and unguessable. When a committed value is drawn from a small enumeration, a
short identifier, or a bounded numeric range, an adversary can reconstruct it
by enumerating candidates and matching digests. A payload class SHOULD commit
low-entropy fields under a per-issuer salt or via a selective-disclosure
mechanism (see the SD-JWT commitment pattern in {{RFC9901}}) rather than
digesting the bare value. Bare digests of low-entropy fields are not
confidential.

## Float Values and Digest Reproducibility {#floats}

Different JSON implementations can serialize the same numeric quantity
({{RFC8259}} number values that are not integers) as
`1.0`, `1e0`, or `1.00`; a canonicalization algorithm's number-serialization
rule determines whether that variation survives into the digest pre-image.
Algorithm `jcs` ({{algo-jcs}}) inherits RFC 8785's canonical
ECMAScript-based number-to-string procedure ({{RFC8785}} Section 3.2.2.3),
which fixes one serialization per IEEE 754 double-precision value; two
conforming implementations that parse the same numeric literal into the same
double-precision value therefore produce byte-identical output under `jcs`.
That guarantee is bounded by parsing, not by canonicalization: a JSON parser
that rounds a numeric literal to a different double-precision value than
another parser produces a different pre-image under any algorithm, `jcs`
included. A payload profile for which this residual risk is unacceptable —
for example, one carrying monetary or quantity values — MAY declare its own
stricter constraint, such as requiring exact decimal strings instead of
JSON numbers, in the fields it selects for digesting; such a constraint is a
payload-profile decision, not a requirement this document imposes on every
payload class.

## Immutable Coordinates {#immutable-coordinates}

A mutable reference — a branch name, a tag that can be moved, a content
URL that is not a content-addressed URL — is not evidence. The moment a
record is amended at its referent, any citation to the mutable reference
silently refers to the new content. All citations to external artifacts MUST
use typed digest references ({{typed-refs}}) that pin the content by its
CANONICAL-DIGEST. Names, labels, and human-readable identifiers MAY appear
alongside a typed reference for display purposes but carry no evidentiary
weight.

When an artifact type cited in an immutable coordinate has no resolvable
digest-context declaration at verification time, the citation is present
but not verified; the consuming profile determines the disposition
({{comparability}}). This is not a defect in the citing record: the
citation becomes verifiable once a conforming declaration exists.

## Tamper Evidence and Runtime Honesty

The envelope signature and the registration Receipt provide tamper evidence
for the record's bytes and bound its timing. They do not prove the recording
runtime was honest at the moment of recording. A producer that seals a false
record produces a structurally valid record of a fiction. A Transparency
Service's append-only property bounds the timing of such a record and makes
its omission or substitution detectable; it does not make its content true.

## Long-Term Verifiability Considerations {#ltv}

Artifacts bound under this specification may need to remain verifiable over periods
considerably longer than the lifetime of any particular digest or signature algorithm.
Because a binding is expressed in terms of a registered algorithm identifier rather
than a fixed algorithm, artifacts bound under different algorithms are each well-formed
and independently verifiable.

Preserving verifiability across an algorithm transition requires that evidence be
re-established under a stronger algorithm *before* the original is considered weak;
this cannot be done retroactively. Deployments with long retention requirements SHOULD
adopt an evidence-renewal scheme. {{RFC4998}} specifies one such scheme and
distinguishes timestamp renewal, which operates on archived evidence alone, from
hash-tree renewal, which requires access to the original data objects. This
specification does not mandate a particular scheme.

# Privacy Considerations {#privacy}

A record bound under this profile carries digests of content rather than
the content itself. The derived identifier and any typed digest references
commit to the content without disclosing it; the record is therefore
payload-blind to any verifier that does not independently possess the
referenced artifacts.

Payload privacy is the responsibility of the payload class. A payload class
that includes fields identifying persons, sessions, or request content
SHOULD document the privacy properties of those fields, including whether
they can be inferred from their digests given knowledge of the value space.
Low-entropy fields are not confidential even when digested ({{security}}).

An anchored record cannot be retracted: a Transparency Service's log is
append-only and a registered record persists. Payload classes SHOULD
specify which fields, if any, must not be present in a record that is
intended to be anchored.

# IANA Considerations {#iana}

This document requests the creation of one new IANA registry, the
Canonicalization Algorithm Registry ({{iana-alg}}), under a "Canonical
Payload Binding" heading. The registry uses the Specification Required
policy ({{RFC8126}}, Section 4.6); a Designated Expert is required for each
registration. This document does not define an Artifact Type registry:
artifact types are registered in the shared Artifact Type Registry in
`REGISTRY.md`, governed separately from this document under its own
Designated Expert checklist and registration rungs; this document
references that registry (see {{outofscope}}) but does not define it. This
revision's Canonicalization Algorithm Registry entries reflect a deliberate
correction over -01's: the registry was re-derived from what the field
actually built, rather than restated from what -01 originally specified
({{changes-01}}).

Registry entries are immutable. A registered entry defines a specific
algorithm. If a behavior change is needed, a new entry MUST be registered;
existing entries MUST NOT be modified retroactively. Maintainer is IANA per
standard process; no other governance body is defined.

Until this registry comes into existence at RFC publication, the table
below serves as the provisional living registry, maintained in this
document's source repository. If the document is adopted, the provisional
registry moves with the document to a repository of the working group's
choosing.

## Canonicalization Algorithm Registry {#iana-alg}

This registry records the canonicalization algorithms that may be used to
compute CANONICAL-DIGEST values.

Each entry pins its canonicalization steps, its hash function, and its
output representation together as a single immutable triple, so that
changing any one of the three requires registering a new token rather than
reinterpreting an existing one — otherwise a token such as `jcs` would
silently come to mean more than its name states.

Registration template:

* Name: A short ASCII identifier suitable for use in protocol fields.
* Description: A normative prose description sufficient to implement the
  algorithm deterministically.
* Reference: The document that specifies the algorithm.

Initial contents:

| Name | Description | Reference |
|---|---|---|
| jcs | RFC 8785 JCS over the octets supplied to the algorithm, no normalization pass; SHA-256; 64-character lowercase hex | This document |
| jcs-n | Withdrawn (2026-08-18) -- never carried to IANA. The token was reserved and defined a JCS-plus-absent-field-normalization construction, but that construction is not carried forward; the permanent record of the construction is draft-mih-sokolov-scitt-payload-binding-00, Section 3.1 | This document (withdrawn) |
| cde-n | Withdrawn (2026-08-18) -- never carried to IANA. The token was reserved and stays bound; it was never assigned a definition and never will be | This document (withdrawn) |
| as-transmitted | No canonicalization: the pre-image is the exact octet sequence identified by a cited named production in the container format (e.g., a signature's signing input); an artifact type using this algorithm states a byte-boundary selector in place of a field set; SHA-256; 64-character lowercase hex | This document |

A payload class or typed digest reference naming `cde-n` MUST NOT be
treated as verifiable under any vintage: the token was bound by a reserved
entry but never assigned a definition, so no construction exists to verify
against, and a verifier encountering it MUST fail closed. A payload class
or typed digest reference naming `jcs-n` MUST NOT be newly declared;
records committed under it before 2026-08-18 are governed by the vintage
rule in {{algo-jcs-n}}. Both withdrawals are recorded terminal states, not
deletions: the tokens stay bound and are never assigned or reassigned. See
{{algo-cde-n}} and {{algo-jcs-n}}.

An artifact type MUST NOT declare `as-transmitted` without a byte-boundary
selector that cites a named production in the container specification
({{algo-as-transmitted}}). Without that selector, an `as-transmitted`
declaration states nothing: there is no field set, no exclusion set, and no
canonicalization to fall back on for the pre-image construction.

# Related Work {#related}

COSE Hash Envelope ({{RFC9995}}) is the hash-side sibling: it defines how
to carry a content-addressed reference to an opaque payload in a COSE
structure. CPB is the statement-side complement: it defines how the payload
content is canonicalized and identified so that the content-address is
reproducible across implementations.

The CCF Receipt Profile ({{I-D.ietf-scitt-receipts-ccf-profile}}) and COSE Receipts ({{RFC9942}}) are the receipt-side
twins: they define the Verifiable Data Structure formats that may appear in
the unprotected headers of Transparent Statements whose binding layer is
defined here.

In-toto and DSSE represent an industry two-layer precedent: a
content-addressed artifact layer combined with an attestation layer over
the artifact's identifier. CPB formalizes the same pattern for the SCITT
statement context.

{{I-D.hillier-scitt-arp}} independently derives a similar canonical claim
construction in its §2. Its Canonical Claim defines its own key-sort, NFC,
number-rendering, and undefined-stripping rules, plus a Claim Hash join
key. The construction is near-`jcs` but not byte-compatible. The
independent re-derivation is evidence that this layer is consistently
re-invented when it is not standardized; CPB exists to stop the
re-invention. Implementations must not assume byte compatibility; ARP's
Canonical Claim carries an explicit construction identifier by which a
consumer can determine compatibility.

{{I-D.birkholz-verifiable-agent-conversations}} defines trace-metadata
conventions at the conversation grain (§7.4). The discovery mirror in
{{discovery}} is designed to be compatible with that convention so that
action-grain records and conversation-grain containers share one discovery
layer. The alignment is informative; CPB does not normatively depend on
that document.

{{I-D.sokolov-rats-aep-composition}} addresses the complementary problem in
the RATS domain: composing application-layer action evidence with remote
attestation. {{I-D.mih-sato-agent-accountability-composition}} defines
composition and conformance rules for multi-agent accountability chains.
Together these documents demonstrate that the canonicalize-and-derive-identifier
construction is a recurring primitive across independent use cases — one shared
binding layer serving SCITT-anchored agent records, RATS attestation
composition, and multi-agent accountability chains.

--- back

# Synthetic Registration Walkthrough {#appendix-a}

This appendix illustrates the mechanics of {{derived-id}}, {{envelope}}, and
{{receipt-binding}} using a non-domain-specific payload class. No domain
vocabulary from any specific profile is used.

**Payload class:** `temperature-record`. Fields: `station_id` (string),
`timestamp` (string), `celsius` (exact decimal string), `record_id` (string).
Exclusion set: `{record_id}`. Algorithm: `jcs`. Representation: bare 64-char
lowercase hex.

**Step 1 — Construct the payload:**

~~~json
{
  "station_id": "WS-42",
  "timestamp": "2026-07-24T00:00:00Z",
  "celsius": "21.3",
  "record_id": null
}
~~~

**Step 2 — Apply the exclusion set:**

Remove `record_id` (it is in the exclusion set). The resulting object is:

~~~json
{
  "station_id": "WS-42",
  "timestamp": "2026-07-24T00:00:00Z",
  "celsius": "21.3"
}
~~~

**Step 3 — Compute the derived identifier:**

Apply JCS {{RFC8785}} to produce the canonical octet string. Compute
SHA-256 and encode as lowercase hex. The result is the `record_id` value
to be placed back into the payload for transport.

**Step 4 — Construct the Signed Statement:**

Wrap the complete payload (including the now-populated `record_id`) in a
COSE_Sign1 with:

* `content_type`: `application/temperature-record+json`
* `alg` and `kid`: producer's signing algorithm and key identifier

**Step 5 — Register and receive a Receipt:**

Submit the Signed Statement to a SCITT Transparency Service. Attach the
returned Receipt to the unprotected header. The Transparent Statement is
now suitable for distribution to verifiers.

**Step 6 — Verify:**

A verifier extracts the payload, strips `record_id`, applies JCS,
recomputes SHA-256, and compares to the carried `record_id`. The verifier
then verifies the envelope signature and, if present, the Receipt under
a trusted service key. All three checks must pass for the record to be
considered fully verified.

# Synthetic Two-Slot Composition {#appendix-b}

This appendix illustrates {{typed-refs}} using two cooperating payload
classes. No domain vocabulary is used.

**Scenario:** a `decision-record` payload class cites an `authorization-doc`
using a typed digest reference.

**Authorization doc** (payload class `authorization-doc`; algorithm `jcs`):

~~~json
{
  "doc_id": "...",
  "subject": "WS-42",
  "scope": "temperature-write",
  "issued_at": "2026-07-24T00:00:00Z"
}
~~~

Its derived identifier is computed with `doc_id` in the exclusion set.
Suppose the result is `"ab12cd34..."`.

**Decision record** (payload class `decision-record`; algorithm `jcs`):

~~~json
{
  "record_id": null,
  "action": "write",
  "authorization": {
    "type": "authorization-doc",
    "digest_alg": "SHA-256",
    "digest": "ab12cd34..."
  }
}
~~~

The typed reference `authorization` cites the authorization doc by its
artifact type and derived identifier. A verifier can confirm the doc was
cited by resolving the `authorization-doc` artifact type's digest context
from its governing specification, recomputing `"ab12cd34..."` from the
doc's bytes, and matching.

**Composability:** the verifier needs only the `authorization-doc` digest
context — it does not need to understand the `decision-record` format to
verify the citation binding. For generic citation-binding verification, a CPB verifier can process a
typed reference to any artifact type whose digest context it can resolve.
Whether a particular citation slot permits that artifact type is determined
by the consuming profile. Artifact-specific appraisal, authorization
semantics, and application integration remain separate.

# Field-Verified Instances {#appendix-c}

The instances in this appendix were chosen to illustrate the mechanisms of
{{algorithms}}, {{receipt-binding}}, and {{typed-refs}}. They are not a
ranking. Two parties appear in every instance: the implementing system and
the verification counterparty. The common counterparty in each case is the
AAC reference implementation, which is present as a verifier, not as the
subject. This is a historical record and is not edited retroactively: the
instances below report what ran at the time, under algorithm `jcs-n`, which
is withdrawn as of this revision ({{algo-jcs-n}}). The byte-agreement result
each instance reports is a property of applying RFC 8785 JCS consistently,
which `jcs` ({{algo-jcs}}) also provides going forward.

**Owner consent status:** Anton Sokolov (Tyche Institute) — confirmed
2026-07-24. Tom Sato (GAR/SOOS) — confirmed 2026-07-25. Tymofii
Pidlisnyi (Agent Passport System) — confirmed 2026-07-24 (on-issue).

## Deep Mechanism Instances {#appendix-c1}

### Glyphzero Byte-Agreement — Algorithm Determinism

Public record: Glyphzero PEDIGREE delegation record, IETF 126 hackathon.

**What ran:** Two independently written RFC 8785 JCS implementations —
Glyphzero's (Rampalli), used to produce its PEDIGREE delegation records
{{I-D.rampalli-pedigree}}, and the AAC reference implementation — computed
a digest over the same delegation record and both produced
`subject_digest` `0b4da06b...` without any coordination on byte ordering
beyond RFC 8785 itself. The record carried no null, empty-array or
empty-object member, so the absent-field normalization pass `jcs-n` added
to JCS did not apply to it; the agreement is an agreement about RFC 8785
JCS, which is the part `jcs` ({{algo-jcs}}) carries forward.

**Mechanism illustrated:** {{algo-jcs}}. RFC 8785 JCS is reproducible
across separately written implementations. The agreement was not
premeditated; it emerged from two systems applying the same algorithm
independently. This instance does not evidence an independent
implementation of the withdrawn normalization pass, and the implementer
census ({{algo-jcs-n}}) records that there was none.

**Consent:** Karthik Rampalli (Glyphzero) confirmed 2026-07-25 (email, with corrections).

### GAR Session Block — Leaf Construction Rule

Public record: GAR Session Block anchor, IETF 126 hackathon; gar-core.ts
commit fe18f24; CT leaf 166.

**What ran:** A GAR Session Block record was registered in a SCITT
Transparency Service (RFC9162_SHA256 VDS). The log leaf was constructed as
SHA-256 of the raw bytes of the derived identifier — `bytes.fromhex(id)`,
not `id.encode("utf-8")`. The inclusion proof verified correctly against the
anchored Merkle root only when the leaf used the raw bytes.

**Mechanism illustrated:** {{leaf-rule}}. The leaf-bytes-not-hex rule was
discovered during live anchoring when a leaf constructed from the hex string
failed to verify; switching to raw bytes produced the correct root.

**Consent:** Tom Sato (GAR/SOOS) — confirmed 2026-07-25.

### A2A Boundary Seal — Derived Identifier as Protocol Gate

Public record: capsule-emit issue #29, verified offline at
https://github.com/action-state-group/capsule-emit/issues/29.

**What ran:** An A2A-protocol boundary producer submitted a record to a SCITT
Transparency Service and used the derived identifier as a protocol-layer
gate (`capsule.digest` / `capsule.resolve`). The receipt was verified
offline using a conforming SCITT verifier (`scitt-cose verify_receipt`
→ `ok=True`), and the Merkle inclusion proof (`verify_inclusion`) folded to
the anchored root. A DENY negative case was also demonstrated: a fabricated
derived identifier not present in the log returned 404 on the resolve step
and DENY on the gate.

**Classification (exact):** single-machine loopback rehearsal, independently
reproduced. The read-only resolve path (`/anchor/inclusion-proof-ct`) is live
at `anchor.agentactioncapsule.org`; a networked cross-machine close is
pending counterparty schedule.

**Mechanism illustrated:** {{derived-id}} and {{receipt-binding}} applied at
a protocol boundary: the derived identifier is stable across network hops and
usable as a verifiable join key without payload disclosure.

**Consent:** Anton Sokolov (Tyche Institute) — confirmed 2026-07-24.

## Field Table — IETF 126 Participants {#appendix-c2}

The following table lists all parties that ran verifiable instances at the
IETF 126 hackathon. Rows appear in alphabetical order by party name; the
order carries no ranking.

| Party | Record type | What ran | Public record |
|---|---|---|---|
| Agent Passport System (Pidlisnyi) | Decision record | Content-derived action reference; NFC + code-point sort + JCS; bidirectional cross-runs 6/6 + 24/24 | draft-pidlisnyi-aps + hackathon coordinates |
| EP (Schrock) | Named-human approval | Three independent codebases produced `8cf0c36e...`; three-computation single-digest | EMILIA/EP hackathon record |
| GAR (Sato) | Kernel session block | Sealed as record; CT leaf = SHA-256(raw bytes of id); leaf 166 verified | gar-core.ts commit fe18f24 |
| Glyphzero (Rampalli) | Delegation record | Two independent JCS implementations; `subject_digest` `0b4da06b...` | Glyphzero PEDIGREE hackathon record |
| Microsoft (Chamayou) | Two-TS statement | One payload, two receipt profiles (ccf.v1 + RFC9162_SHA256) in conjunction | scitt-ccf-ledger PR #424 |
| Sokolov (Tyche) | Boundary-seal | A2A gate; derived-id as resolve key; DENY negative; offline Receipt verify | capsule-emit issue #29 |

## Agreed and Scheduled {#appendix-c3}

The following cross-verifications are agreed and scheduled but have not
produced field-verified instances at time of writing:

* VTO/libp2p (M.S. Gupta) — content-addressed telemetry objects citing
  action records across grains.
* VSO/VeritasChain (Kamimura) — verifiable service objects under `jcs`.

Field-verified instances are expected to be added in future revisions as
cross-verifications complete.

The PermitReceipt × MachineMandate composition is excluded from this appendix.
It is recorded in the AAC interop registry (INTEROP.md).


# Acknowledgments {#acknowledgments}
{:numbered="false"}

The following individuals contributed findings from the IETF 126 hackathon in
Vienna that directly shaped the rules in this document. All attributions
cite public artifacts.

**Contributors** \[all named attributions and contributor acknowledgments
individually confirmed: Anton Sokolov (confirmed 2026-07-24), Iman Schrock
(confirmed 2026-07-24), Tom Sato (confirmed 2026-07-25), Yong Bok Lee (Scott
Lee) (contributor attribution confirmed 2026-07-27), Tymofii Pidlisnyi (Agent Passport System,
confirmed 2026-07-24, on-issue), Karthik Rampalli (Glyphzero, confirmed
2026-07-25, email, with corrections)\]:

* Anton Sokolov (Tyche Institute) — assurance-boundary discipline; the A2A
  boundary-seal instance in {{appendix-c}}.

* Yong Bok Lee (Scott Lee), Meridian Verity Group — ORPRG-derived
  cross-profile digest-context discipline: equal-looking digest text alone
  is not a valid join; a typed reference is verified by recomputing the
  referenced artifact under its established digest context and comparing
  that result with the digest carried in the reference, not with the citing
  record's own derived identifier. Also contributed the
  representation-boundary distinction among raw digest bytes, bare lowercase
  hexadecimal text, and prefixed text, and the verification-scope boundary
  separating typed-reference content binding from artifact-specific
  appraisal and authorization. See {{I-D.lee-orprg-permit-receipts}}.

* Tymofii Pidlisnyi (Agent Passport System) — the content-derived action reference pattern
  (NFC + code-point sort + JCS) demonstrating that `jcs-n` generalizes
  across canonicalization styles; bidirectional cross-runs with confirmed
  byte-agreement.

* Tom Sato (GAR/SOOS) — the leaf-bytes-not-hex finding documented in
  {{leaf-rule}}: the log leaf hashes the raw bytes of the derived
  identifier, not the hex-string encoding.

* Karthik Rampalli (Glyphzero) — independent JCS implementation
  byte-agreement on `subject_digest` `0b4da06b...`, demonstrating that
  RFC 8785 JCS is reproducible across separately written implementations.

* Iman Schrock (EMILIA/EP) — confirmed 2026-07-24 — the three-computation single-digest instance
  (`8cf0c36e...`) demonstrating byte-agreement across three independent
  codebases.

**Acknowledged** \[Amaury Chamayou confirmed 2026-07-24 (email)\]:

* Amaury Chamayou (Microsoft) — two-TS single-statement demonstration;
  the vds-from-protected-header finding subsequently mirrored in
  microsoft/scitt-ccf-ledger #424.
