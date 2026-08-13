---
title: "Canonical Payload Binding: A Signed Statement Construction Profile"
abbrev: "Canonical Payload Binding"
docname: draft-mih-sokolov-scitt-payload-binding-01
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
IANA registries govern both the canonicalization algorithms and the artifact
types that may appear in typed references; entries are immutable.

--- note_Note_to_Readers

This document is an individual submission. The intended venue is the SCITT
Working Group (scitt@ietf.org). Named attributions and acknowledgments in this document were individually
confirmed in writing by the named parties.
The short name "Canonical Payload Binding" and the document title are
expected to be settled by the adopting working group.

The source of this document and the companion interop record are maintained
at: https://github.com/action-state-group/agent-action-capsule

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
called the Canonical Payload Binding (CPB). It is derived from
{{I-D.mih-scitt-agent-action-capsule}} (§Conventions, §envelope, §registration,
§identity), which first stated the construction in a SCITT context, and
generalized at the IETF 126 hackathon in Vienna, where seven parties
participated in the public interop program. The public record reports four
codebases demonstrating byte agreement in specific shared, declared contexts.
Other frozen artifacts retained separately declared digest contexts. ORPRG
retained its CP-JSON-2 context and was represented in the interop design through a typed reference rather
than through an assertion of cross-profile digest equality. Digests remain
governed by their original contexts; CPB does not relabel an ORPRG CP-JSON-2
commitment as jcs-n. The provenance is stated here once and not repeated in
subsequent sections.

For generic citation-binding verification, a CPB verifier can process a
typed reference to any registered artifact type. Whether a particular
citation slot permits that artifact type is determined by the consuming
profile. Artifact-specific appraisal, authorization semantics, and
application integration remain separate.

Supporting a newly registered artifact type does not require a new generic
citation-binding algorithm. It may still require consuming-profile
integration and artifact-specific appraisal.

## Out of Scope {#outofscope}

This document does not define:

* Payload semantics — what fields a payload contains, what their values mean,
  or what verdicts or decisions are carried. Those belong to payload profiles
  that use CPB as their binding layer.

* Application meaning — the real-world interpretation of any record
  anchored via this construction.

* Transparency Service registration policy — which records a Transparency
  Service will or must accept. Registration policy is a Transparency Service
  concern, not a statement profile concern.

* Transports — how registration requests or retrieval queries travel between
  producers, Transparency Services, or verifiers.

# Conventions and Definitions {#conventions}

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
{{RFC2119}} {{RFC8174}} when, and only when, they appear in all capitals,
as shown here.

Payload Class:
: A named category of structured content that has declared: a
  canonicalization algorithm (from the registry in {{iana-alg}}), an
  exclusion set of fields that are omitted from the canonical form before
  the derived identifier is computed, and an entry in the Artifact Type
  registry ({{iana-art}}).

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
  over the same payload, each serving a distinct purpose ({{iana-art}}); the
  contexts are independent and MUST NOT be conflated.

CANONICAL-DIGEST:
: A function parameterized by a canonicalization algorithm A: given a value
  v, CANONICAL-DIGEST(A, v) = HEX(SHA-256(A(v))), where HEX denotes
  lowercase hexadecimal encoding and A(v) is the octet string produced by
  the algorithm applied to v. The specific pre-image construction — field
  selection, normalization, and encoding — is part of A's definition and
  is registered per {{iana-alg}}.

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
| jcs-n | JCS + absent-field normalization; SHA-256; lowercase hex output | {{algo-jcs-n}} |
| cde-n | Deterministic CBOR canonicalization profile; SHA-256 | {{algo-cde-n}} (pending) |
| as-transmitted | No canonicalization; digest over a byte sequence fixed by a cited named production in the container format; SHA-256; 64-character lowercase hex | {{algo-as-transmitted}} |

Entries in the Canonicalization Algorithm Registry are immutable: new
behavior requires a new entry, never a retroactive edit to an existing one.
A reserved entry binds its token only; its summary is provisional until the
entry is defined, at which point the full entry becomes immutable.
The hash function is part of each algorithm's definition; migration to a
different hash (for example, a future post-quantum function) is performed by
registering a new algorithm entry, never by reinterpreting an existing one.

## Algorithm jcs-n {#algo-jcs-n}

Algorithm `jcs-n` is the JSON Canonicalization Scheme {{RFC8785}} applied to
an absent-field-normalized JSON object, followed by SHA-256.

Pre-image construction:

1. Normalize the input: remove, bottom-up and recursively, every member whose
   value is JSON null, an empty array (zero elements), or an empty object
   (zero members). Members explicitly set to a non-null value are not removed.
   Apply this normalization after the exclusion set is removed ({{derived-id}})
   and before JCS serialization. The semantic equivalence among JSON null, an
   empty array, an empty object, and the absence of a field is a payload-class
   (profile) decision; `jcs-n` defines only the byte construction after the
   profile's declared normalization has been applied.

2. Apply JCS {{RFC8785}} to produce the canonical UTF-8 octet string.

3. Compute SHA-256 over those octets.

4. Encode the digest as lowercase hexadecimal. The output is a 64-character
   ASCII string.

Additional constraint: monetary and quantity values anywhere in a payload
using `jcs-n` MUST be exact decimal strings, not JSON floating-point numbers
({{RFC8259}} number values that are not integers). A float in a digest-bearing
field cannot be reproduced deterministically across implementations.

The CANONICAL-DIGEST of a payload P using `jcs-n` is therefore:

~~~
CANONICAL-DIGEST(jcs-n, P) =
    lowercase_hex(SHA-256(JCS(normalize(P minus exclusion_set))))
~~~

The exclusion set is matched against the top-level member names of P only;
a member of the same name nested inside a member's value is not removed.

This algorithm is Suite 1 of this profile. The four codebases demonstrating
byte agreement at IETF 126 all used `jcs-n` in shared, declared contexts; all
are valid under `jcs-n` without modification. Independently written
implementations produced byte-identical `subject_digest` values for the same
input, with no coordination beyond the specification; see Appendix C.

## Algorithm cde-n (Reserved) {#algo-cde-n}

Algorithm `cde-n` is reserved for a deterministic CBOR canonicalization
profile. Its definition -- including the choice of deterministic encoding
profile, the float width, and the treatment of exceptional floating-point
values -- will be specified in a subsequent revision of this document. That
revision will state how the profile relates to the CDE and dCBOR profiles and
to the deterministic serialization work in the CBOR Working Group; `cde-n`
is not defined as any of them.

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

Digest: SHA-256, 64-character lowercase hex, matching `jcs-n`. These are
stated explicitly here as part of this entry, not inherited silently from
the generic CANONICAL-DIGEST definition ({{conventions}}).

# The Derived Identifier {#derived-id}

The derived identifier of a record is computed as:

~~~
id = CANONICAL-DIGEST(A, payload minus exclusion_set)
~~~

where A is the canonicalization algorithm declared by the payload class and
the exclusion set is the set of fields declared by the payload class as
self-referential or chain-linkage fields. The derived identifier is a 64-character
lowercase hex string when A is `jcs-n`.

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
  class declares, where CLASS is the payload class name registered in the
  Artifact Type Registry ({{iana-art}}).

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

When a Transparency Service keys its log on the derived identifier of a
record, the log leaf MUST be computed over the raw bytes of the derived
identifier, not over its hex-string encoding.

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
| type | string | REQUIRED | The artifact type, from the Artifact Type Registry ({{iana-art}}). |
| purpose | string | CONDITIONAL | The purpose label ({{iana-art}}) selecting which of the artifact type's digest contexts this reference targets. REQUIRED whenever the resolved artifact type registers more than one digest context. MAY be omitted only when the resolved artifact type registers exactly one digest context, in which case that single context applies; a verifier MUST NOT infer a default when more than one context is registered. |
| digest_alg | string | REQUIRED | The hash algorithm of the digest value (e.g., "SHA-256"). The canonicalization context of the cited artifact is resolved from the digest context selected by `type` and `purpose` ({{iana-art}}), not from this field. |
| digest | string | REQUIRED | The digest of the cited artifact, in the representation declared by the selected digest context. |

Additional fields MAY be present and MUST be ignored by verifiers that do
not understand them.

## Cross-Profile Comparability {#comparability}

Within typed-reference verification, the digest carried by the reference
and the digest recomputed over the referenced artifact are comparable only
when both are interpreted under the same established referenced-artifact
digest context and comparison representation.

To verify the reference, the verifier MUST use the `type` field, together
with the `purpose` field when the resolved artifact type registers more than
one digest context, to resolve exactly one of the referenced artifact's
registered digest contexts. If `type` resolves to more than one digest
context and `purpose` is absent, ambiguous (matching no registered purpose
label), or names a purpose label the resolved artifact type does not
register, the reference is unresolvable: the verifier MUST NOT guess a
context and MUST NOT report the typed reference as verified. It MUST confirm
that `digest_alg` identifies a hash algorithm consistent with the resolved
context.

`digest_alg` is REQUIRED even though every algorithm registered in
{{iana-alg}} today names the same hash, SHA-256: it is the field that lets
a future Canonicalization Algorithm Registry entry using a different hash
land as a new token without a breaking change to this wire format, rather
than being decorative because only one value is legal now.

It MUST then recompute the referenced artifact's digest under that context and
compare the recomputed value with the value carried in the `digest` field.

If the context established from the `type` and `digest_alg` fields cannot
be reconciled with the context used to recompute the referenced artifact,
or if a required deterministic conversion to a common comparison
representation is not expressly defined, the verifier MUST NOT report the
typed reference as verified. The consuming profile determines the resulting
error disposition.

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
registered artifact type may fill a citation slot -- applies to
citation-binding interoperability only and does not extend to any appraisal
or authorization semantics defined by the artifact type or consuming profile.

# Profile Independence {#profile-independence}

A payload profile MUST NOT impose requirements on the internal structure or field
values of another payload profile. Relationships between artifacts of different types
are expressed solely through typed references ({{typed-refs}}) and entries in the
artifact-type registry ({{iana-art}}).

This constraint keeps verification of a multi-artifact chain decomposable: a verifier
evaluates each binding under each profile's own semantics independently and never needs
to evaluate a pair of profiles jointly. Implementations therefore need not implement,
or be aware of, profiles they neither produce nor consume, and a new profile may be
registered without revalidating existing profiles or implementations.

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

## Float Values and Digest Reproducibility

JSON floating-point numbers ({{RFC8259}} number values that are not integers)
MUST NOT appear in any field from which a digest is computed. The same
numeric quantity can be serialized as `1.0`, `1e0`, or `1.00` in different
JSON implementations; JCS does not normalize these forms. A float in a
digest-bearing field silently produces implementation-dependent digests that
cannot be reproduced and therefore cannot be verified. Exact decimal strings
are the only portable encoding for monetary and quantity values.

## Immutable Coordinates

A mutable reference — a branch name, a tag that can be moved, a content
URL that is not a content-addressed URL — is not evidence. The moment a
record is amended at its referent, any citation to the mutable reference
silently refers to the new content. All citations to external artifacts MUST
use typed digest references ({{typed-refs}}) that pin the content by its
CANONICAL-DIGEST. Names, labels, and human-readable identifiers MAY appear
alongside a typed reference for display purposes but carry no evidentiary
weight.

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

This document requests the creation of two new IANA registries under a
"Canonical Payload Binding" heading. Both registries use the Specification
Required policy ({{RFC8126}}, Section 4.6); a Designated Expert is required
for each registration.

Registry entries are immutable. A registered entry defines a specific
algorithm or artifact type. If a behavior change is needed, a new entry
MUST be registered; existing entries MUST NOT be modified retroactively.
Maintainer is IANA per standard process; no other governance body is defined.

Until these registries come into existence at RFC publication, the tables
below serve as the provisional living registry, maintained in this
document's source repository. If the document is adopted, the provisional
registry moves with the document to a repository of the working group's
choosing.

## Canonicalization Algorithm Registry {#iana-alg}

This registry records the canonicalization algorithms that may be used to
compute CANONICAL-DIGEST values.

Each entry pins its canonicalization steps, its hash function, and its
output representation together as a single immutable triple, so that
changing any one of the three requires registering a new token rather than
reinterpreting an existing one — otherwise a token such as `jcs-n` would
silently come to mean more than its name states.

Registration template:

* Name: A short ASCII identifier suitable for use in protocol fields.
* Description: A normative prose description sufficient to implement the
  algorithm deterministically.
* Reference: The document that specifies the algorithm.

Initial contents:

| Name | Description | Reference |
|---|---|---|
| jcs-n | RFC 8785 JCS over a normalized JSON object (null, empty-array, and empty-object members removed bottom-up); SHA-256; lowercase hex | This document |
| cde-n | Deterministic CBOR canonicalization profile; SHA-256 | This document (reserved; subsequent revision) |
| as-transmitted | No canonicalization: the pre-image is the exact octet sequence identified by a cited named production in the container format (e.g., a signature's signing input); an artifact type entry using this algorithm states a byte-boundary selector in place of a field set; SHA-256; 64-character lowercase hex | This document |

An artifact type entry MUST NOT register `as-transmitted` without a
byte-boundary selector that cites a named production in the container
specification ({{algo-as-transmitted}}). Without that selector, an
`as-transmitted` entry states nothing: there is no field set, no exclusion
set, and no canonicalization to fall back on for the pre-image construction.

## Artifact Type Registry {#iana-art}

This registry records the artifact types that may appear in the `type`
field of a typed digest reference ({{typed-refs}}).

An artifact type declares one or more digest contexts. More than one is
needed whenever an artifact type has more than one digest that a verifier
might need to establish independently — for example, a digest that serves
as the artifact's own derived identifier, and a separate digest computed
over a declared subset of the same artifact to test equivalence with
another instance. Each digest context is independent: it states its own
canonicalization algorithm (which MAY differ per context, and MAY be an
identity algorithm such as `as-transmitted` when one is registered in the
Canonicalization Algorithm Registry) and its own field set, exclusion set,
domain separation, pre-image encoding, profile version, and representation,
as that algorithm requires. A single-context artifact type is the
degenerate case of this template, not a different template.

Registration template:

* Name: A short ASCII identifier. For a CPB-bound profile, this Name is
  the registered profile label that a citing composition profile treats
  as a protocol input; CPB takes no separate IANA action to register
  profile labels beyond registering this artifact type.
* Digest Contexts: One or more digest contexts. Each digest context states:
  * Purpose: a label drawn from the purpose-label vocabulary below,
    distinguishing this context from any other digest context the same
    artifact type registers.
  * Profile version: the version of the profile or specification that
    defines this digest context, or `N/A` if the artifact type's
    reference does not itself distinguish profile versions (for example,
    a type identifier that names a type but not a version).
  * Canonicalization algorithm: the algorithm name from {{iana-alg}} (MAY
    be `as-transmitted`). This token also pins the digest context's hash
    algorithm and output representation, recorded once in the cited
    Canonicalization Algorithm Registry entry ({{iana-alg}}) rather than
    restated per artifact type.
  * Field set: the field set selected for this context ({{derived-id}}).
    When the canonicalization algorithm is an identity algorithm with no
    field set (such as `as-transmitted`), this element is instead the
    byte-boundary selector that algorithm requires.
  * Exclusion set: the fields omitted from the field set before digesting.
    Not applicable to a context using an identity algorithm with no field
    set.
  * Domain separation: any domain-separation prefix or tag applied to the
    pre-image, or `none`.
  * Pre-image encoding: the encoding of the pre-image octets before
    digesting.
  * Representation: the representation of the output digest
    ({{representation}}).
* Reference: The document that defines the artifact type.

A digest context element that does not apply to a given context (for
example, exclusion set under `as-transmitted`) MUST be stated explicitly as
`none` or `N/A` rather than omitted. A registry entry is read in isolation
by a verifier that has not read this document's prose, and cannot assume a
default for an absent element.

**Purpose-label vocabulary.** Every digest context's purpose label is drawn
from a single vocabulary shared across this entire registry, so that a
companion specification introducing digest bindings at another layer (for
example, a statement-level multi-binding facility) has one namespace to
adopt rather than inventing a second, incompatible one. The initial
vocabulary, extensible by the same Specification-Required process as the
registries in this section:

| Label | Meaning |
|---|---|
| `identifier` | The digest context that computes the artifact's derived identifier ({{derived-id}}): the artifact's primary content-address. |
| `equivalence` | A digest context, distinct from `identifier`, computed over a declared field subset, used to determine whether two artifacts represent the same underlying content or action. |

This is CPB's first published definition of this namespace; neither this
document nor a companion may register a second purpose-label vocabulary
that overlaps this one in meaning.

A CPB purpose label is orthogonal to, not competing with, any role a
companion composition profile assigns a digest within a cross-document
join (for example, roles such as `subject`, `authority-reference`, or
`receipt-payload`). The purpose label describes a digest context's
function within its own artifact type; a join role describes which slot
in a multi-document binding that same digest fills. The two axes are
independent, and a single digest may carry one label from each at once —
for example, an artifact's `identifier` digest context ({{iana-art}}) may
simultaneously be the `subject` of a composition join. Neither vocabulary
constrains the other, and neither document needs to adopt the other's
terms.

A typed digest reference ({{typed-refs}}) selects which digest context of a
multi-context artifact type it targets via the reference's own `purpose`
field, using the purpose label from this vocabulary. Each digest context an
artifact type registers MUST carry a purpose label distinct from every other
digest context the same artifact type registers, so that `type` plus
`purpose` together resolve to exactly one digest context with no remaining
ambiguity. This mechanism is orthogonal to, and does not substitute for,
whatever role vocabulary a companion statement-level multi-binding facility
may separately define for its own join semantics.

Initial contents:

### `agent-action-capsule` {#art-agent-action-capsule}

Reference: {{I-D.mih-scitt-agent-action-capsule}}

Digest context (`identifier`):

* Profile version: N/A — draft-mih-scitt-agent-action-capsule does not
  currently register more than one profile version in this registry.
* Canonicalization algorithm: `jcs-n`
* Field set: all capsule fields
* Exclusion set: {capsule_id, chain}
* Domain separation: none
* Pre-image encoding: JCS UTF-8 octets, per `jcs-n` ({{algo-jcs-n}})
* Representation: 64-char lowercase hex

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
key. The construction is near-`jcs-n` but not byte-compatible. The
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
Exclusion set: `{record_id}`. Algorithm: `jcs-n`. Representation: bare 64-char
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

**Step 2 — Apply the exclusion set and normalize:**

Remove `record_id` (it is in the exclusion set). After absent-field
normalization (null members removed), the normalized object is:

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

A verifier extracts the payload, strips `record_id`, normalizes, applies JCS,
recomputes SHA-256, and compares to the carried `record_id`. The verifier
then verifies the envelope signature and, if present, the Receipt under
a trusted service key. All three checks must pass for the record to be
considered fully verified.

# Synthetic Two-Slot Composition {#appendix-b}

This appendix illustrates {{typed-refs}} using two cooperating payload
classes. No domain vocabulary is used.

**Scenario:** a `decision-record` payload class cites an `authorization-doc`
using a typed digest reference.

**Authorization doc** (payload class `authorization-doc`; algorithm `jcs-n`):

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

**Decision record** (payload class `decision-record`; algorithm `jcs-n`):

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
cited by resolving the `authorization-doc` artifact type from the registry
({{iana-art}}), recomputing `"ab12cd34..."` from the doc's bytes, and
matching.

**Composability:** the verifier needs only the registry entry for
`authorization-doc` — it does not need to understand the `decision-record`
format to verify the citation binding. For generic citation-binding verification, a CPB verifier can process a
typed reference to any registered artifact type. Whether a particular
citation slot permits that artifact type is determined by the consuming
profile. Artifact-specific appraisal, authorization semantics, and
application integration remain separate.

# Field-Verified Instances {#appendix-c}

The instances in this appendix were chosen to illustrate the mechanisms of
{{algorithms}}, {{receipt-binding}}, and {{typed-refs}}. They are not a
ranking. Two parties appear in every instance: the implementing system and
the verification counterparty. The common counterparty in each case is the
AAC reference implementation, which is present as a verifier, not as the
subject.

**Owner consent status:** Anton Sokolov (Tyche Institute) — confirmed
2026-07-24. Tom Sato (GAR/SOOS) — confirmed 2026-07-25. Tymofii
Pidlisnyi (Agent Passport System) — confirmed 2026-07-24 (on-issue).

## Deep Mechanism Instances {#appendix-c1}

### Glyphzero Byte-Agreement — Algorithm Determinism

Public record: Glyphzero PEDIGREE delegation record, IETF 126 hackathon.

**What ran:** Two independently written RFC 8785 JCS implementations —
Glyphzero's (Rampalli), used to produce its PEDIGREE delegation records
{{I-D.rampalli-pedigree}}, and the AAC reference implementation — each
computed `jcs-n` over the same delegation record. Both produced `subject_digest`
`0b4da06b...` without any coordination on byte ordering or normalization
beyond the algorithm definition.

**Mechanism illustrated:** {{algo-jcs-n}}. `jcs-n` is reproducible across
separately written implementations. The agreement was not premeditated; it
emerged from two systems applying the same algorithm independently.

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
* VSO/VeritasChain (Kamimura) — verifiable service objects under `jcs-n`.

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
  `jcs-n` is reproducible across separately written implementations.

* Iman Schrock (EMILIA/EP) — confirmed 2026-07-24 — the three-computation single-digest instance
  (`8cf0c36e...`) demonstrating byte-agreement across three independent
  codebases.

**Acknowledged** \[Amaury Chamayou confirmed 2026-07-24 (email)\]:

* Amaury Chamayou (Microsoft) — two-TS single-statement demonstration;
  the vds-from-protected-header finding subsequently mirrored in
  microsoft/scitt-ccf-ledger #424.
