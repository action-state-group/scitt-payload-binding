---
title: "Canonical Payload Binding: A Signed Statement Construction Profile"
abbrev: "Canonical Payload Binding"
docname: draft-mih-sokolov-scitt-payload-binding-03
date: 2026-09-05
category: std
submissiontype: IETF
ipr: trust200902
area: "Security"
workgroup: "Network Working Group"
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
   city: Tallinn
   country: Estonia
   email: anton.sokolov@tyche.institute

normative:
  RFC2119:
  RFC8174:
  RFC8126:
  RFC6838:
  RFC8259:
  RFC8610:
  RFC8785:
  RFC8949:
  RFC9052:
  RFC9942:
  RFC9943:
  RFC9995:

informative:
  RFC7515:
  RFC6920:
  RFC9162:
  RFC9901:
  RFC4998:
  I-D.ietf-scitt-receipts-ccf-profile:
  I-D.mih-scitt-agent-action-capsule:
    title: "An Agent Action Capsule Profile for SCITT"
    date: 2026-08-28
    seriesinfo:
      Internet-Draft: draft-mih-scitt-agent-action-capsule-04
    author:
      - ins: S. Mih
        name: Steven Mih
        organization: Action State Group, Inc.
  I-D.hillier-scitt-arp:
    title: "Attestation Reconciliation Protocol"
    date: 2026-08-13
    seriesinfo:
      Internet-Draft: draft-hillier-scitt-arp-03
    author:
      - ins: J. Hillier
        name: Joel Hillier
        organization: Certisyn, Inc.
  I-D.mih-sato-agent-accountability-composition:
    title: "Agent Accountability: Composition and Conformance"
    date: 2026-08-16
    seriesinfo:
      Internet-Draft: draft-mih-sato-agent-accountability-composition-01
    author:
      - ins: S. Mih
        name: Steven Mih
        organization: Action State Group, Inc.
      - ins: T. Sato
        name: Tom Sato
        organization: MyAuberge K.K.
      - ins: I. Schrock
        name: Iman Schrock
        organization: EMILIA Protocol, Inc.
      - ins: S. Bu
        name: Songbo Bu
        organization: Independent
      - ins: A. Sokolov
        name: Anton Sokolov
        organization: Tyche Institute
  I-D.sokolov-rats-aep-composition:
    title: "Composing Application-Layer Action Evidence with Remote Attestation Procedures"
    date: 2026-08-31
    seriesinfo:
      Internet-Draft: draft-sokolov-rats-aep-composition-06
    author:
      - ins: A. Sokolov
        name: Anton Sokolov
        organization: Tyche Institute
  I-D.birkholz-verifiable-agent-conversations:
    title: "Verifiable Agent Conversation Records"
    date: 2026-08-31
    seriesinfo:
      Internet-Draft: draft-birkholz-verifiable-agent-conversations-01
    author:
      - ins: H. Birkholz
        name: Henk Birkholz
        organization: Fraunhofer Institute for Secure Information Technology
      - ins: T. Heldt
        name: Tobias Heldt
      - ins: O. Steele
        name: Orie Steele
  I-D.le-scitt-derived-subjects:
    title: "SCITT Profile for Independently Derived Subjects"
    date: 2026-08-22
    seriesinfo:
      Internet-Draft: draft-le-scitt-derived-subjects-00
    author:
      - ins: T. Le
        name: Thanh Le
  I-D.le-comparing-derived-identifiers:
    title: "Principles for Comparing Independently Derived Identifiers"
    date: 2026-08-22
    seriesinfo:
      Internet-Draft: draft-le-comparing-derived-identifiers-00
    author:
      - ins: T. Le
        name: Thanh Le
  I-D.nobuo-scitt-protected-object-binding:
    title: "SCITT Statement Relationship and Protected Object Binding"
    date: 2026-07-07
    seriesinfo:
      Internet-Draft: draft-nobuo-scitt-protected-object-binding-00
    author:
      - ins: N. Aoki
        name: Nobuo Aoki
        organization: The Graduate University for Advanced Studies (SOKENDAI)
  I-D.rampalli-pedigree:
    title: "PEDIGREE: Provenance and Delegation Records for Digital Artifacts"
    date: 2026-04-25
    seriesinfo:
      Internet-Draft: draft-rampalli-pedigree-00
    author:
      - ins: K. Rampalli
        name: Karthik Rampalli
        organization: Glyphzero, Inc.
  I-D.lee-orprg-permit-receipts:
    title: "Permit Receipts for Permit-Before-Commit Authorization of AI-Agent and Workload External Effects"
    date: 2026-06-04
    seriesinfo:
      Internet-Draft: draft-lee-orprg-permit-receipts-00
    author:
      - ins: Y. Lee
        name: Yong Bok Lee
        organization: Meridian Verity Group

--- abstract

Independently written systems that anchor records to a SCITT Transparency
Service repeatedly need the same construction: a canonical form of structured
content, a content-addressed identifier derived from that form, binding to a
SCITT Signed Statement and Receipt, and references that cite external artifacts
by digest. This document defines that construction as the Canonical Payload
Binding (CPB). A payload profile declares its canonicalization algorithm and
exclusion set and thereby obtains a reproducible derived identifier. A CPB
Signed Statement carries either the complete statement content as specified by
RFC 9943 or a digest of content held elsewhere using the COSE Hash Envelope of
RFC 9995. CPB also defines an abstract typed digest reference information model
and one optional protected-header encoding, `cpb-refs`; a payload profile may
instead define its own reference serialization. An IANA registry governs CPB
canonicalization algorithms. CPB does not define payload content formats,
establish or require a universal artifact-type registry, or require either
typed-reference carrier.

--- note_Note_to_Readers

This document is an individual submission. The intended venue is the SCITT
Working Group (scitt@ietf.org). Named acknowledgments in this document were
individually confirmed in writing by the named parties.
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
called the Canonical Payload Binding (CPB). The COSE Hash Envelope
{{RFC9995}} identifies a hash function and carries the resulting digest; when
structured content needs a deterministic preimage, CPB supplies the
profile-selected canonicalization and derived-identifier construction. CPB
also supports the ordinary RFC 9943 case in which the complete statement
content, rather than its digest, is supplied to COSE. CPB defines the binding
mechanics and a typed-reference mechanism for citing other digests, but it
does not define what any payload or cited artifact means. CPB generalizes the
construction first stated by {{I-D.mih-scitt-agent-action-capsule}} and
exercised across independent implementations at the IETF 126 hackathon; the
companion interop record preserves the detailed provenance and digest-context
boundaries.

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
  and which purpose labels its digest contexts use. Those declarations are
  owned by payload or consuming profiles and identified by stable normative
  references. CPB defines no artifact-type registry.

* Application meaning — the real-world interpretation of any record
  anchored via this construction.

* Transparency Service registration policy — which records a Transparency
  Service will or must accept. Registration policy is a Transparency Service
  concern, not a statement profile concern.

* Transports — how registration requests or retrieval queries travel between
  producers, Transparency Services, or verifiers.

# Changes from -02 {#changes-02}

This revision separates the payload-neutral CPB mechanisms from payload
formats and makes their wire and verification behavior explicit:

* {{typed-refs}} is an abstract four-member information model. Payload
  profiles own any payload-level serialization. CPB defines one optional,
  closed CBOR encoding in the protected `cpb-refs` header.
* CPB creates no artifact-type registry. A consuming profile identifies by
  stable normative reference the artifact-type and digest-context
  declarations it accepts.
* Reference processing now distinguishes Malformed, Unresolved, Failed, and
  Verified outcomes and keeps them separate from validation of the enclosing
  COSE signature and issuer authentication.
* {{envelope}} separates RFC 9943 Full-Content Mode from RFC 9995 Hash
  Envelope Mode and retains every applicable RFC 9943 requirement in both.
* A Signed Statement uses at most one typed-reference carrier. The CDDL,
  duplicate and unknown-key behavior, `crit` handling, and resource limits
  for `cpb-refs` are now normative.

The -01-to-02 correction that withdrew `jcs-n` and registered `jcs` remains
unchanged.

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
: The content-address of a payload: the output of CANONICAL-DIGEST(A, v),
  where v is the payload value with its profile-declared exclusion set
  removed. Verifiers MUST recompute the derived identifier from the payload
  value; a carried derived-identifier value is advisory only and a mismatch
  is a defect.

Digest Context:
: The complete set of parameters that determine how a digest was computed:
  the field set selected, the exclusion set applied, the canonicalization
  algorithm applied, any domain separation, the encoding of the pre-image,
  and the representation of the output. Two digest values are comparable
  only when their full digest contexts are established as compatible. A
  payload class or artifact type MAY declare more than one digest context
  over the same payload, each serving a distinct purpose declared by the
  profile that defines the class or type. The declaration MUST also state the
  exact `digest_alg` token and comparison representation. The contexts are
  independent and MUST NOT be conflated.

RAW-DIGEST:
: A function parameterized by a canonicalization algorithm A: for any such
  algorithm A and payload v, RAW-DIGEST(A, v) = H_A(A(v)), where A(v) is the
  canonical octet string and H_A is the hash function declared by A's entry
  in the Canonicalization Algorithm Registry ({{iana-alg}}). RAW-DIGEST is
  an octet string; it has no textual encoding.

CANONICAL-DIGEST:
: A function parameterized by a canonicalization algorithm A: for any such
  algorithm A and payload v,
  CANONICAL-DIGEST(A, v) = ENCODE_A(RAW-DIGEST(A, v)), where ENCODE_A is
  the output encoding
  declared by A's entry in the Canonicalization Algorithm Registry
  ({{iana-alg}}). Every algorithm definition supplied by this document
  declares SHA-256 and 64-character lowercase hexadecimal; an entry
  registered by a later
  document MAY declare another digest function or encoding, and a verifier
  MUST read both from the entry rather than assuming them. A(v) is the
  octet string produced by the algorithm applied to v; the specific
  pre-image construction — field selection, normalization, and encoding —
  is part of A's definition and is registered per {{iana-alg}}.

Signed Statement:
: A COSE_Sign1 object {{RFC9052}} that carries a payload, a protected
  header, and an optional unprotected header; defined in {{RFC9943}}.

Signature-Valid:
: A state of a Signed Statement, independent of typed-reference processing.
  The COSE signature has been cryptographically validated under the selected
  verification key. This state alone does not establish that the key is
  authorized for the asserted issuer. Merely being encoded in a protected
  header does not establish this state.

Issuer-Authenticated:
: A state of a Signature-Valid Signed Statement for which the verifier's
  policy accepts the signing key as authorized for the asserted issuer.
  This state authenticates issuer claims but does not make a cited artifact
  or typed reference Verified.

Malformed:
: A typed-reference processing state. The reference or its `cpb-refs`
  container violates the applicable serialization, required-member,
  duplicate, closed-extension, or size rules. A verifier MUST NOT report any
  entry in a Malformed `cpb-refs` value as Verified.

Unresolved:
: A typed-reference processing state. The reference is well-formed, but the
  verifier cannot select exactly one authorized digest context or cannot
  obtain the cited artifact, or it lacks the implementation needed to execute
  an otherwise valid digest context. An Unresolved reference is
  not evidence of a content binding.

Failed:
: A typed-reference processing state. The reference is well-formed and exactly
  one authorized digest context is selected, but the declared algorithm or
  representation conflicts with that context, the selected token is
  permanently undefined or prohibited, or a recomputed digest differs from
  the supplied value.

Verified:
: A typed-reference processing state. The verifier selected exactly one
  authorized digest context, obtained the cited artifact, applied that
  context's canonicalization and hash rules, and obtained a digest equal to
  the supplied value in the context's declared representation.

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
| jcs-n | Withdrawn -- JCS + absent-field normalization; unavailable for new use | {{algo-jcs-n}} (withdrawn) |
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
reassigned, and it is never carried forward as an active IANA algorithm.
That is a terminal marking that `cde-n` ({{algo-cde-n}}) also carries, though on different
facts: `cde-n` never acquired a definition, while `jcs-n` did and its
records remain eligible for verification by vintage.

For historical evaluation, the complete `jcs-n` construction is as follows.
Let P be the JSON object supplied by the applicable payload or artifact-type
profile, and let E be that profile's set of top-level member names to exclude:

1. Before converting the input JSON text to a data model, reject a duplicate
   member name in any object, including a duplicate that would later be
   excluded. Equality is tested on decoded Unicode member-name strings after
   JSON escape processing, with no Unicode normalization. NFC-equivalent but
   distinct strings are not duplicate names, and `jcs-n` applies no Unicode
   normalization.

2. Reject a JSON number token unless it has the integer form
   `0|-?[1-9][0-9]*` and its value is in the inclusive range
   `[-(2^53-1), 2^53-1]`. In particular, a decimal point, exponent notation,
   leading zero, or `-0` is prohibited. A non-integer quantity, and an integer
   outside that range, has to be represented as an exact JSON string if the
   applicable profile permits it.

3. Remove from P each top-level member whose name is in E. A same-named member
   nested below the top level is retained.

4. Normalize the remaining value bottom-up and recursively. In each object,
   remove every member whose normalized value is JSON null, an empty array, or
   an empty object. Array elements are not object members and are not removed,
   but values inside an array are recursively normalized before their
   containing object is considered.

5. Apply JCS {{RFC8785}} to the normalized object to produce canonical UTF-8
   octets, compute SHA-256 over those octets, and encode the 32-octet digest as
   exactly 64 lowercase hexadecimal ASCII characters.

Thus, for historical `jcs-n` evaluation:

~~~
CANONICAL-DIGEST(jcs-n, P, E) =
    lowercase_hex(SHA-256(JCS(normalize(P minus E))))
~~~

These steps define digest evaluation only. Evaluating the construction and
obtaining matching bytes does not by itself establish an eligible vintage or
produce a Verified typed-reference outcome.

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
or typed digest reference that names `jcs-n` MUST NOT be newly declared. The
vintage cutoff is the start of 2026-08-18 UTC. Pre-cutoff vintage is
established only by profile-defined, cryptographically verifiable evidence
that binds the exact record, or its digest under the declared context, to a
time before that cutoff. A payload timestamp, source-control commit date,
file-system time, transport arrival time, or other unauthenticated date MUST
NOT be used as vintage evidence.

A verifier encountering `jcs-n` with evidence of a time at or after the
cutoff, or without sufficient evidence of a pre-cutoff vintage, MUST fail
closed and MUST NOT report the payload class or typed digest reference as
verified; a typed reference has the Failed outcome. Only after establishing
pre-cutoff vintage MAY a verifier apply the historical construction above.
If the construction is available, its ordinary digest comparison determines
whether the typed reference is Verified or Failed. A verifier that lacks an
implementation of the otherwise eligible historical construction reports the
typed reference as Unresolved. A historical identifier MUST NOT be relabelled
to another algorithm token or recomputed under another algorithm.

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
class or typed digest reference as verified. For a typed reference, the
outcome is Failed because the selected token has no algorithm definition.

## Algorithm as-transmitted {#algo-as-transmitted}

Algorithm `as-transmitted` applies no canonicalization. The digest pre-image
is the exact octet sequence already fixed by the container format or
cryptographic envelope carrying the payload -- for example, the signing input
over which a signature was computed. The signature (or other format-defined
byte-fixing) is what makes those bytes authoritative; re-canonicalizing them
would be redundant at best and would break the very binding that makes the
bytes authoritative at worst.

Because there is no canonicalization step, `as-transmitted` has no field set
and no exclusion set. A profile-owned artifact-type declaration that selects
`as-transmitted` for a digest context MUST instead state a byte-boundary
selector in place of a field set: a normative reference plus the name that
referenced specification gives to the exact byte sequence in question. Two
examples of a valid selector:

* {{RFC7515}}, Section 5.1, `JWS Signing Input` -- the octets a JWS signature is
  computed over.
* `RFC 9052 §4.4, ToBeSigned` -- the octets a COSE_Sign1 signature is
  computed over.

A selector that is not a cited named production is prose, not a selector.
This named-production rule eliminates that ambiguity: a digest-context
declaration MUST NOT select `as-transmitted` on the strength of an uncited
description such as "the payload bytes." If the container specification
carrying the artifact does not itself name the exact byte sequence as a
discrete production, the declaration MUST NOT use `as-transmitted`; it must
select another registered canonicalization algorithm whose definition
constructs the pre-image from first principles.

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
64-character lowercase hex string for every algorithm this document defines.
A reserved or never-defined token has no derived-identifier representation.
For an algorithm registered elsewhere, its representation is the one that
algorithm's registry entry declares.

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

If a payload profile applies a transformation before derived-identifier
computation, its specification MUST define that transformation and its order
relative to field exclusion and algorithm A so that producer and verifier
derive the same exact input. This document defines no such transform. Absent
an applicable profile declaration, the producer and verifier MUST use the
untransformed payload and exclusion procedure defined above.

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

Each digest context used by a typed reference MUST declare whether its
comparison value is raw octets, bare text, or prefixed text, and MUST define
the exact grammar of any textual form. In `cpb-refs`, raw octets are encoded
as a CBOR byte string and textual forms as a CBOR text string. A verifier MUST
NOT silently convert between these forms. A wire type or textual form that is
inconsistent with the uniquely selected digest context produces the Failed
state.

# Envelope Conventions {#envelope}

Every CPB Signed Statement MUST be a tagged COSE_Sign1 structure
{{RFC9052}} and MUST satisfy every applicable requirement of {{RFC9943}}.
CPB requirements are additive and do not replace or relax the SCITT
baseline. In particular, the protected header MUST contain the CWT Claims
header parameter (label 15), whose value includes `iss` (Claim label 1) and
`sub` (Claim label 2). Key identification, certificate carriage, and the
relationship among `kid`, `x5t`, and `x5chain` MUST follow {{RFC9943}}; CPB
does not define an alternative credential rule.

A CPB Signed Statement uses exactly one of the two modes below. Other COSE
header parameters are permitted only when {{RFC9052}}, {{RFC9943}}, this
document, or the applicable payload profile defines them. Producers MUST NOT add ad-hoc
protected-header parameters. CPB assigns no meaning to non-critical header
parameters defined elsewhere. The closed extension policy for the inner
`cpb-refs` map is specified in {{envelope-carriage}}.

## Full-Content Mode {#full-content-mode}

In Full-Content Mode, the payload supplied to COSE signing and verification
is the complete serialized statement content, whether that payload is
attached or detached as permitted by {{RFC9052}}. Protected `content_type`
(label 3) MUST identify the serialization selected by the payload profile
using a media type or content-format value permitted by {{RFC9943}} and
{{RFC6838}}. CPB neither constructs media-type names from payload-class names
nor registers a payload format. The RFC 9995 parameters 258, 259, and 260
MUST NOT appear in this mode.

## Hash Envelope Mode {#hash-envelope-mode}

In Hash Envelope Mode, let s be the complete statement content after any
carried derived identifier has been populated. The Signed Statement MUST
conform to the COSE Hash Envelope rules in {{RFC9995}} in addition to the
applicable {{RFC9943}} requirements stated above. The payload supplied to
COSE signing and verification MUST be the raw octet string:

~~~
RAW-DIGEST(A, s) = H_A(A(s))
~~~

It MUST NOT be the hexadecimal or other encoded CANONICAL-DIGEST value. If
the COSE payload is detached, the externally supplied payload is this same
raw digest value.

The profile's derived-identifier exclusion set MUST NOT be applied to this
Hash Envelope computation: RFC 9995 binds the complete statement content.
The derived identifier remains a separate computation over s with its
declared exclusion set as specified in {{derived-id}}. Even when both use the
same canonicalization and hash algorithm, a producer or verifier MUST NOT
assume the Hash Envelope payload is the raw representation of the derived
identifier. A verifier processing a carried derived identifier MUST check
that identifier separately from the Hash Envelope content binding.

The protected header MUST contain `payload-hash-alg` (CDDL
`payload_hash_alg`, label 258), identifying H_A by its COSE hash-algorithm
identifier, and `preimage-content-type` (CDDL
`payload_preimage_content_type`, label 259), identifying the media type or
content format of the exact canonical octets A(s) that were hashed. A
`payload-location` (CDDL `payload_location`, label 260) MAY also appear in
the protected header. As
required by {{RFC9995}}, labels 258 through 260 MUST NOT appear in the
unprotected header, and `content_type` (label 3) MUST NOT appear in either
header bucket.

The applicable payload profile MUST identify A and the complete preimage
construction. Label 258 selects only H_A; a verifier MUST NOT treat it as a
canonicalization-algorithm identifier. An algorithm used in Hash Envelope
Mode MUST have an unambiguous COSE hash-algorithm mapping in its
Canonicalization Algorithm Registry entry ({{iana-alg}}).

A verifier that has not obtained s can establish Signature-Valid status and,
after applying its issuer/key policy, can authenticate the digest claim, but
it has not verified the content binding.
To verify that binding, it MUST obtain s, compute A(s), apply the function
identified by label 258, and compare the raw result to the COSE payload.
`cpb-refs` MAY be used in either envelope mode, subject to
{{envelope-carriage}}.

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
Where a Transparency Service's VDS keys its log on a digest associated with
the derived identifier, the algorithms defined in this document produce a
32-byte RAW-DIGEST and a 64-character hexadecimal CANONICAL-DIGEST
representation of that value ({{representation}}). The VDS or an applicable
profile MUST state which one is its leaf input, and producer and verifier MUST
use that same representation. Algorithms registered later may have different
output sizes.

For example, when that declaration selects RAW-DIGEST and the carried derived
identifier is a 64-character hexadecimal string D, the leaf input is:

~~~
leaf_input = bytes.fromhex(D)    -- 32 raw bytes
~~~

Under that RAW-DIGEST declaration, the following is incorrect:

~~~
leaf_input = D.encode("utf-8")  -- 64 ASCII bytes, not RAW-DIGEST
~~~

If the declaration instead selects the textual CANONICAL-DIGEST, the latter
64 ASCII bytes are the declared input. A verifier constructing a leaf MUST
apply the declared selection and MUST NOT infer it from the apparent shape of
the value. Confusing raw bytes with their hexadecimal encoding produces a
different leaf hash.

# Typed Digest References (Information Model) {#typed-refs}

A typed digest reference is the mechanism by which one record cites an
external artifact — another record, an authorization document, a
configuration object, or any other verifiable item — by its content-address
without embedding it.

This section defines a typed digest reference as an abstract information
model: four members, their meaning, and their requiredness. It does not fix a
payload serialization. CPB defines an optional protected-header serialization
in {{envelope-carriage}}; a payload profile may instead define its own
serialization as described in {{payload-carriage}}.

A typed digest reference has the following members:

| Member | Value | Req | Meaning |
|---|---|---|---|
| type | text | REQUIRED | The artifact-type identifier defined by a stable specification that the consuming profile explicitly accepts. CPB does not register these values. |
| purpose | text | CONDITIONAL | Selects one digest context for the resolved type. It is REQUIRED when that type has multiple accepted contexts and otherwise follows {{comparability}}. |
| digest_alg | text | REQUIRED | The hash algorithm of the digest value (e.g., "SHA-256"). The canonicalization context of the cited artifact is resolved from the digest context selected by `type` and `purpose`, not from this field. |
| digest | digest in the context's declared representation | REQUIRED | The digest of the cited artifact, in the exact representation declared by the selected digest context. |

These are the only members of the CPB information model. A payload profile
may place profile-specific fields beside its rendering of a typed reference,
but those fields are not CPB typed-reference extensions and their processing
is governed solely by that profile. The `cpb-refs` map is closed in this
version; see {{envelope-carriage}}.

## Cross-Profile Comparability {#comparability}

Within typed-reference verification, the digest carried by the reference
and the digest recomputed over the referenced artifact are comparable only
when both are interpreted under the same established referenced-artifact
digest context and comparison representation.

A consuming profile that accepts typed references MUST identify, by stable
normative reference, every artifact-type declaration that it accepts. Each
declaration MUST bind an exact `type` token to one or more digest contexts.
Each context MUST state its preimage construction, canonicalization
algorithm, hash function, exact `digest_alg` token, output representation,
and a purpose label when required below. A deployment MAY select a subset of
the declarations its consuming profile permits, but it MUST NOT redefine a
token or any parameter of its cited declaration. CPB creates no artifact-type
registry and does not authorize discovery from an unspecified or mutable
registry snapshot.

The verifier MUST use `type` and, when present, `purpose` to select exactly
one accepted context:

* If exactly one context is accepted for `type`, `purpose` MAY be absent. If
  it is present, it MUST exactly match that context's declared purpose;
  otherwise the reference is Unresolved.
* If multiple contexts are accepted for `type`, every context MUST have a
  distinct, non-empty purpose label and the reference MUST carry `purpose`.
  An absent or non-matching value makes the reference Unresolved.
* If no declaration matches, or declarations from more than one normative
  source leave the selection ambiguous, the reference is Unresolved. The
  verifier MUST NOT choose by entry order, apparent recency, or preferred
  algorithm.
* A profile or deployment configuration containing duplicate `(type,
  purpose)` selections is invalid and MUST NOT be used for verification.

After selecting a context, the verifier MUST compare `digest_alg` with the
exact token declared by that context. Comparison is case-sensitive and
octet-for-octet: no case folding, alias table, or whitespace trimming is
permitted. A mismatch makes the reference Failed; the verifier MUST NOT
silently use the context's algorithm while ignoring the supplied value.

`digest_alg` is REQUIRED even though every algorithm registered in
{{iana-alg}} today names the same hash, SHA-256: it is the field that lets
a future Canonicalization Algorithm Registry entry using a different hash
land as a new token without a breaking change to this wire format, rather
than being decorative because only one value is legal now.

The hash algorithm is not chosen per reference. The selected digest context
determines it; `digest_alg` is a redundant consistency declaration for
algorithm agility and downgrade detection.

The verifier MUST next check that the carried value uses the selected
context's declared representation. A mismatch is Failed. If the
representation matches but the cited artifact cannot be obtained, the state
is Unresolved. If the context is valid but the verifier does not implement its
construction, the state is also Unresolved. Otherwise, the verifier
MUST recompute the digest using the selected context and compare it
byte-for-byte with `digest`. Equal values produce Verified; unequal values
produce Failed. A deterministic conversion
is permitted only when the selected context expressly defines that conversion
and its output comparison representation.

The citing record's own derived-identifier context need NOT be compatible
with the referenced artifact's digest context; those contexts govern
different computations.

The two values actually being compared must share an established comparison
context. Bare hexadecimal equality alone is not a join.

The enclosing Signed Statement's signature result is independent of these
states. A verifier SHOULD return the signature result and each reference
result separately. It MUST NOT treat a typed reference as authenticated or
actionable on behalf of the issuer unless the Signed Statement is
Issuer-Authenticated.
A Signature-Valid statement can contain an Unresolved or Failed reference;
a Verified digest match does not authenticate an issuer whose signature did
not validate.

The consuming profile MUST define the disposition of every non-Verified
state. It MUST NOT rely on an Unresolved, Failed, or Malformed reference as
evidence of a content binding.

## Carriage Selection {#carriage-selection}

A payload profile that uses CPB typed references MUST select exactly one
carrier for them in each Signed Statement: `cpb-refs` envelope carriage or a
profile-owned payload carriage. A producer MUST NOT use both carriers in one
Signed Statement, whether for the same or different citations. A
profile-aware verifier that detects both MUST classify the Signed Statement
as nonconforming and MUST NOT merge the sets or prefer one carrier. A generic
CPB verifier is not expected to recognize a payload profile's private
serialization.

## Envelope Carriage {#envelope-carriage}

A CPB-bound Signed Statement MAY carry its typed digest references as a
COSE protected header parameter, `cpb-refs`, registered in {{iana-header}}.
The parameter MUST NOT occur in the unprotected header. Its value is defined
by this CDDL {{RFC8610}}:

~~~
cpb-refs = [1*64 typed-digest-reference]

typed-digest-reference = {
  1 => type-tstr,  ; type
  ? 2 => purpose-tstr,  ; purpose
  3 => digest-alg-tstr,  ; digest_alg
  4 => digest-value  ; digest
}

type-tstr = tstr .size (1..255)
purpose-tstr = tstr .size (1..64)
digest-alg-tstr = tstr .size (1..32)
digest-value = tstr .size (1..128) / bstr .size (1..128)
~~~

The integer keys have these meanings:

| Key | Member | CBOR type |
|---|---|---|
| 1 | type | text string |
| 2 | purpose | text string |
| 3 | digest_alg | text string |
| 4 | digest | text string or byte string, matching the selected context's representation ({{representation}}) |

The encoded UTF-8 lengths of `type`, `purpose`, and `digest_alg` MUST be,
respectively, 1 through 255, 1 through 64, and 1 through 32 octets. The
encoded value at key 4 MUST be 1 through 128 octets. The array MUST contain
1 through 64 entries. These limits are part of the wire profile;
implementations MAY impose lower deployment limits only when their
registration or consuming policy advertises those limits before accepting
statements.

The map is closed. Keys other than 1 through 4 are not extensions: their
presence makes the entire `cpb-refs` value Malformed. Any missing required
key, wrong CBOR type, empty or oversized value, or array outside the declared
bounds has the same result. A future extension that changes the reference
map requires a standards update or a new COSE header parameter; it MUST NOT
be introduced through an unrecognized inner-map key.

CBOR map keys MUST be unique as required by this protocol's application of
{{RFC8949}}. A decoder MUST detect duplicate keys before any data-model
conversion that could discard them. Repeated array entries with the same
decoded four-member tuple are also forbidden. A duplicate key or repeated
entry makes the entire `cpb-refs` value Malformed; first-wins, last-wins,
partial-success, and duplicate-weighting behavior are prohibited. If any
array entry is Malformed, a verifier MUST NOT report another entry from that
header value as Verified. The COSE signature result remains independently
reportable.

The CDDL constrains the data model, not the choice among CBOR serializations.
CPB imposes no deterministic-encoding or definite-length requirement beyond
{{RFC8949}} and {{RFC9052}}. Test fixtures MAY pin one deterministic encoding
solely to make expected bytes reproducible. A conforming verifier MUST NOT
reject another otherwise valid encoding solely because its bytes differ from
the fixture encoding.

If a consuming profile requires understanding `cpb-refs` before accepting or
processing the Signed Statement, the producer MUST include the `cpb-refs`
label in the protected `crit` header parameter, and a verifier applying that
profile MUST reject a statement that omits that critical marking. When the
references are advisory to the applicable policy, the producer MAY omit the
label from `crit`. Unsupported critical use is a COSE processing failure as
specified by {{RFC9052}}. Critical marking does not make a Malformed,
Unresolved, or Failed reference valid.

`cpb-refs` is signature-covered because it is protected-header content, but
it becomes authenticated as an issuer claim only after the Signed Statement
is Issuer-Authenticated. It is not covered by the payload's derived identifier
({{derived-id}}), which is computed from the payload content alone.

## Payload Carriage {#payload-carriage}

This section is informative.

A payload profile MAY carry typed digest references in its own
serialization — JSON, CBOR, or any other format the payload class
defines — as part of the payload bytes that the derived identifier is
computed over. This document does not define that serialization: a
payload profile that carries references this way states its own field names,
container structure, extension behavior, and any profile-specific
requiredness beyond {{typed-refs}}'s information model. In Full-Content Mode,
the serialized reference data are part of the content supplied to COSE
signature verification. In Hash Envelope Mode, the raw digest of the complete
statement content is supplied instead, and the reference data are covered only
after the verifier obtains that content and validates the hash binding as
specified in {{hash-envelope-mode}}. Neither kind of coverage makes a typed
reference Verified without the processing in {{comparability}}.
{{appendix-d}} describes one profile-owned example without defining its wire
format here. The prohibition on dual carriage in {{carriage-selection}}
still applies.

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

When a payload profile uses CPB to bind an artifact of another type, it MUST
NOT require the CPB citation-binding verifier to interpret the other payload
profile's internal fields. The CPB relationship is expressed through a typed
reference ({{typed-refs}}) that resolves against the cited artifact type's own
digest-context declaration.

This constraint keeps CPB binding verification decomposable: a verifier
evaluates each digest under its own declared context. It does not prohibit an
application or consuming profile from defining additional joint semantics or
appraisal after the independent content bindings have been checked.

# Discovery Mirror {#discovery}

This section is informative.

A producer MAY place an unprotected COSE header parameter that mirrors the
derived identifier of the record when the applicable payload profile defines
that parameter's label, type, and processing. CPB does not assign a discovery
label or wire encoding. Any such parameter is advisory only: it can help log
tooling locate a record's content-address without parsing the payload, but it
carries no binding guarantee.

A verifier MUST NOT rely on an advisory mirror without obtaining the content
and recomputing its derived identifier under the applicable payload profile.
A mismatch is a defect in the record and MUST be reported.

Section 3.11.2 of {{I-D.birkholz-verifiable-agent-conversations}} defines an
unprotected `trace-metadata` map with optional `content-hash` and
`content-hash-alg` members. That is an analogous profile-owned discovery
mechanism. CPB does not assert wire compatibility with it.

# Extensibility and Cross-Cutting Facilities {#cross-cutting}

This section is informative.

This specification does not define selective disclosure, countersignature or
multi-party attestation, record-relation semantics, erasure tombstones,
producer timestamps or validity periods, batch aggregation, or profile
versioning. A companion or payload profile that defines one specifies its own
semantics and wire behavior; it does not thereby extend the closed `cpb-refs`
map.

# Security Considerations {#security}

## Preimages Are Bytes, Not Renderings

The preimage of RAW-DIGEST, and therefore of CANONICAL-DIGEST, is the octet
string produced by the canonicalization algorithm — not a rendered form, not
a console output, and not a string with added whitespace, trailing newlines,
or encoding differences. A producer that serializes then re-reads the payload
before computing the digest MUST ensure the byte sequence entering the hash
function is identical to what the canonicalization algorithm produces, not
what a deserializer happens to emit. Diagnosing divergence requires comparing
the exact octets, not visual representations.

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
silently refers to the new content. A payload profile that relies on CPB to
verify a citation MUST express it as a typed digest reference ({{typed-refs}})
that pins the content by its CANONICAL-DIGEST. Names, labels, and human-readable identifiers MAY appear
alongside a typed reference for display purposes but carry no evidentiary
weight.

When an artifact type cited in an immutable coordinate has no uniquely
resolvable, profile-authorized digest-context declaration, the reference is
Unresolved and the consuming profile determines the disposition
({{comparability}}). A verifier MUST NOT invent a mapping or reinterpret an
existing type token to make an earlier citation verifiable.

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

CPB provides integrity binding, not confidentiality. Full-Content Mode exposes
the statement payload unless another applicable mechanism protects it. Hash
Envelope Mode can withhold the preimage, but exposes a stable digest. COSE
protected headers are integrity-protected after successful signature
validation and issuer-authenticated only after the applicable key policy
succeeds; they are not encrypted. In particular, `cpb-refs` exposes each reference's
type, purpose, digest algorithm, and digest value, together with citation-graph
structure. These values can enable correlation across records and dictionary
attacks against low-entropy artifacts.

A producer SHOULD omit `cpb-refs` or use a profile-defined confidential
payload carrier when public header visibility is inappropriate. A consuming
profile MUST analyze whether its type and purpose values, stable digests, or
citation topology disclose identities, relationships, workflow state, or
otherwise sensitive information. `type` and `purpose` MUST NOT contain secrets
or unnecessary personal data.

Low-entropy fields are not confidential merely because they are digested
({{security}}). Salting, unlinkable identifiers, and selective-disclosure
commitments can reduce some risks, but each changes the digest context and
MUST be explicitly declared by the applicable profile. A verifier MUST NOT
introduce such a transformation implicitly.

An anchored record cannot be retracted: a Transparency Service's log is
append-only and a registered record persists. Payload classes SHOULD
specify which fields, if any, must not be present in a record that is
intended to be anchored.

# IANA Considerations {#iana}

This document requests the creation of one new IANA registry, the
Canonicalization Algorithm Registry ({{iana-alg}}), under a "Canonical
Payload Binding" heading, and one registration in an existing IANA
registry, the `cpb-refs` COSE Header Parameter ({{iana-header}}). The
Canonicalization Algorithm Registry uses the Specification Required
policy ({{RFC8126}}, Section 4.6); a Designated Expert is required for each
registration. This document neither creates nor depends on an artifact-type
registry. Artifact-type and digest-context declarations are owned and
selected by profiles as specified in {{comparability}}.

An active entry's algorithm semantics are immutable. If a behavior change is
needed, a new entry MUST be registered; an existing name MUST NOT be
reinterpreted. Status changes follow the rules below and the same
Specification Required policy. IANA is the registry maintainer; no source
repository or other body is an alternative registry authority. Before RFC
publication, the names in this document are draft-local and the table below
is only the requested initial registry contents.

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
* Status: `Active`, `Reserved`, or `Withdrawn`.
* Preimage construction: A normative description sufficient to implement the
  canonicalization or byte-selection operation deterministically.
* Hash function and typed-reference token: The hash function and the exact
  `digest_alg` string used by a digest context based on this entry.
* COSE hash algorithm: The integer COSE Algorithms registry value used for
  RFC 9995 Hash Envelope Mode, or "N/A" when that mode is unsupported.
* Output representation: The exact ENCODE_A operation and result type.
* Test vectors: Public positive and negative vectors covering preimage and
  output boundaries.
* Reference: The stable, publicly available specification that defines the
  algorithm.

An `Active` entry MUST complete every field other than permitting "N/A" for
the COSE hash algorithm when Hash Envelope Mode is unsupported. A `Reserved`
entry binds only its name and MAY use "N/A" for the remaining algorithm
fields. Promotion from `Reserved` to `Active` requires a complete registration.
An `Active` or `Reserved` entry MAY become `Withdrawn`; withdrawal is terminal,
prohibits new use, and does not erase an active entry's last definition, which
remains available for historical verification. A `Withdrawn` name MUST NOT be
reassigned.

The Designated Expert MUST verify that each required field is unambiguous, the
cited specification and vectors are publicly available for an active entry,
and the requested registration or status change does not alter the semantics
of an existing active or withdrawn definition.

Initial contents:

The preimage construction for each active entry is defined in
{{algorithms}}.

| Name | Status | Hash / token | COSE | Output | Test Vectors | Reference |
|---|---|---|---|---|---|---|
| jcs | Active | SHA-256 / `SHA-256` | -16 | 64-char lowerhex | {{test-vector-locations}} | This document |
| jcs-n | Withdrawn | SHA-256 / `SHA-256` | -16 | 64-char lowerhex | {{test-vector-locations}} | This document |
| cde-n | Withdrawn | N/A | N/A | N/A | N/A -- no definition exists | This document |
| as-transmitted | Active | SHA-256 / `SHA-256` | -16 | 64-char lowerhex | {{test-vector-locations}} | This document |

### Test Vector Locations {#test-vector-locations}

The public vector locations named by the initial registrations are:

* `jcs`: https://github.com/action-state-group/scitt-payload-binding/tree/main/vectors/jcs
* historical `jcs-n`: https://github.com/action-state-group/scitt-payload-binding/tree/main/vectors/jcs-n
* `as-transmitted`: https://github.com/action-state-group/scitt-payload-binding/tree/main/vectors/as-transmitted

A payload class or typed digest reference naming `cde-n` MUST NOT be
treated as verifiable under any vintage: the token was bound by a reserved
entry but never assigned a definition, so no construction exists to verify
against, and a verifier encountering it MUST fail closed; for a typed
reference, the outcome is Failed. A payload class or typed digest reference
naming `jcs-n` MUST NOT be newly declared;
records committed under it before 2026-08-18 are governed by the vintage
rule in {{algo-jcs-n}}. Both withdrawals are recorded terminal states, not
deletions: the tokens stay bound and are never assigned or reassigned. See
{{algo-cde-n}} and {{algo-jcs-n}}.

An artifact type MUST NOT declare `as-transmitted` without a byte-boundary
selector that cites a named production in the container specification
({{algo-as-transmitted}}). Without that selector, an `as-transmitted`
declaration states nothing: there is no field set, no exclusion set, and no
canonicalization to fall back on for the pre-image construction.

## COSE Header Parameters Registration {#iana-header}

This document requests registration of the following entry in the "COSE
Header Parameters" registry {{RFC9052}}, Section 11.1:

| Name | Label | Value Type | Value Registry | Description | Reference |
|---|---|---|---|---|---|
| cpb-refs | TBD1 | array | | A closed, bounded array of typed digest references encoded as specified in {{envelope-carriage}} | This document |

IANA is requested to assign an integer value for TBD1. The registry uses the
Specification Required policy ({{RFC8126}}, Section 4.6). `cpb-refs` may
appear in the protected header only and MUST NOT appear in the unprotected
header. Its critical-processing behavior and the distinction among
signature coverage, authentication, and reference verification are specified
in {{envelope-carriage}}.

# Related Work {#related}

{{RFC9995}} defines the protected parameters and COSE payload semantics for
signing a hash rather than its preimage. CPB Hash Envelope Mode
({{hash-envelope-mode}}) uses that format and adds the profile-selected
canonicalization step that precedes the registered hash function.

{{RFC9942}} defines generic COSE Receipts. The CCF Receipt Profile
{{I-D.ietf-scitt-receipts-ccf-profile}} defines one VDS-specific Receipt
profile. CPB does not alter either format.

{{I-D.hillier-scitt-arp}} independently derives a similar canonical claim
construction in its Sections 3 and 4.1. Its Claim Hash uses its own
normalization, deterministic encoding, and deployment-blinding rules. It is
not byte-compatible with a CPB `jcs` identifier, and implementations MUST NOT
substitute one construction for the other.

{{I-D.birkholz-verifiable-agent-conversations}} defines trace-metadata
at the conversation grain in Section 3.11.2, including optional content-hash
metadata in an unprotected header. {{discovery}} notes the analogous design
without claiming a shared label or wire format. CPB does not normatively
depend on that document.

{{I-D.le-scitt-derived-subjects}} derives a protected CWT `sub` value from an
application-admitted structured Value. It explicitly does not derive that
subject from the Statement payload or define generic payload binding. CPB
instead derives identifiers for Statement content and binds digest references;
it does not replace that document's subject-identity profile.

{{I-D.le-comparing-derived-identifiers}} gives general principles for fixing
the comparison domain, equivalence relation, and complete derivation semantics
of independently produced identifiers. It defines no wire syntax,
canonicalization format, or hash procedure. CPB instantiates such choices for
its narrower Statement-content and typed-reference mechanisms.

{{I-D.nobuo-scitt-protected-object-binding}} defines protected-object and
Statement-reference models, relationship vocabulary, and an optional graph
manifest. It does not define CPB's canonicalization algorithms, derived-
identifier procedure, or `cpb-refs` carrier; CPB does not import its graph
semantics.

{{RFC6920}} defines hash-based `ni` and `nih` names, URI/URL representations,
and associated registries. CPB defines the structured-content preimage and
digest context used for its bindings but defines no URI syntax or resolution
protocol.

{{I-D.sokolov-rats-aep-composition}} addresses the complementary problem in
the RATS domain: composing application-layer action evidence with remote
attestation. {{I-D.mih-sato-agent-accountability-composition}} defines
composition and conformance rules for multi-agent accountability chains.
They address composition and appraisal questions outside CPB's payload-neutral
binding rules; CPB does not import their payload semantics.

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

Use Full-Content Mode ({{full-content-mode}}): wrap the complete payload,
including the now-populated `record_id`, in an RFC 9943 Signed Statement.
Its protected header includes:

* `alg`: the producer's signing algorithm;
* `content_type`: `application/example+json`, used here only as the
  illustrative media type from the RFC 9943 examples;
* CWT Claims (label 15), including an `iss` such as
  `https://issuer.example` and a `sub` such as
  `urn:example:temperature-record:WS-42`; and
* key identification or certificate parameters conforming to RFC 9943.

A real `temperature-record` profile would specify an appropriate media type;
CPB does not register one.

**Step 5 — Register and receive a Receipt:**

Submit the Signed Statement to a SCITT Transparency Service. Attach the
returned Receipt to the unprotected header. The Transparent Statement is
now suitable for distribution to verifiers.

**Step 6 — Verify:**

A verifier validates the Signed Statement signature and RFC 9943 headers,
extracts the payload, strips `record_id`, applies JCS, recomputes SHA-256,
and compares the result to the carried `record_id`. If a Receipt is present,
the verifier separately verifies it under a trusted Transparency Service
key. The signature, content binding, and Receipt results remain distinct.

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

For this example, the profile selects payload carriage and therefore the
Signed Statement does not also contain `cpb-refs`. The profile accepts a
stable specification for `authorization-doc` that declares exactly one
digest context, using `jcs`, the `SHA-256` token, and lowercase hexadecimal
output. `purpose` is therefore omitted.

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

**Composability:** a profile-aware parser first extracts the reference from
the `decision-record` payload. Generic citation-binding verification then
needs the accepted `authorization-doc` digest-context declaration and cited
artifact, but no other `decision-record` semantics. Whether this citation
slot permits that type is determined by the consuming profile. Artifact
appraisal, authorization semantics, and application integration remain
separate.

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
Transparency Service (`RFC9162_SHA256` VDS; {{RFC9162}}). The log leaf was constructed as
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

# Profile-Owned Payload Carriage Example {#appendix-d}

This appendix is informative. Section 5.5.5 of
{{I-D.mih-scitt-agent-action-capsule}} defines a payload-level `references`
array. In revision -04, each entry's identity uses the profile-owned JSON
members `type`, `digest_alg`, and `digest`; the separate
`citation_purpose` member describes why the Capsule cites the target. That
field is not CPB's `purpose`, which selects a digest context.

This is an example of the profile-owned payload carriage described in
{{payload-carriage}}, not a CPB JSON wire format. CPB neither imports nor
redefines AAC's field names, additional members, or extension behavior.
Implementers of that carrier follow the cited AAC revision. An AAC consuming
profile that applies CPB verification also identifies by stable normative
reference the artifact-type and digest-context declarations it accepts, as
required by {{comparability}}, and does not include `cpb-refs` in the same
Signed Statement.

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
  (NFC + code-point sort + JCS) demonstrating that RFC 8785 JCS generalizes
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
