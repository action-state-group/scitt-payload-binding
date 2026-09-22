---
title: "Canonicalization Declaration for SCITT Signed Statements"
abbrev: "SCITT Canonicalization Declaration"
docname: draft-mih-sokolov-scitt-payload-binding-06
date: 2026-09-16
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
  RFC8785:
  RFC9052:
  RFC9943:
  RFC9995:

informative:
  RFC7515:
  RFC9901:
  I-D.mih-scitt-agent-action-capsule:
    title: "An Agent Action Capsule Profile for SCITT"
    date: 2026-08-28
    seriesinfo:
      Internet-Draft: draft-mih-scitt-agent-action-capsule-04
    author:
      - ins: S. Mih
        name: Steven Mih
        organization: Action State Group, Inc.
  I-D.schrock-ep-authorization-receipts:
    title: "Authorization Receipts for High-Risk Agent Actions"
    date: 2026-08-16
    seriesinfo:
      Internet-Draft: draft-schrock-ep-authorization-receipts-12
    author:
      - ins: I. Schrock
        name: Iman Schrock
        organization: EMILIA Protocol, Inc.
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
content, a content-addressed identifier derived from that form, and binding to
a SCITT Signed Statement and Receipt. This document, referred to as CPB,
specifies that construction as declarations rather than as a payload format. A
payload profile declares its canonicalization algorithm and exclusion set and
thereby obtains a reproducible derived identifier. A CPB Signed Statement
carries either the complete statement content as specified by RFC 9943 or a
digest of content held elsewhere using the COSE Hash Envelope of RFC 9995. An
IANA registry assigns the canonicalization algorithm identifiers that these
declarations name. CPB does not define payload content formats, artifact
types, or a mechanism for citing other artifacts by digest.

--- note_Note_to_Readers

This document is an individual submission. The intended venue is the SCITT
Working Group (scitt@ietf.org). Named acknowledgments in this document were
individually confirmed in writing by the named parties. **This revision is a
draft for co-author and working-group review only; it has not been submitted
to the datatracker.**

Revision -05 changed the title, which was "Canonical Payload Binding: A
Signed Statement Construction Profile", so that it names what the document
defines: how a Signed Statement declares the construction behind the digests
it carries, rather than the payload those digests cover. The draft name and
the short name CPB are unchanged pending the adopting working group's own
choice of short name and title. Revision -06 responds to WG scope review by
removing the typed digest reference mechanism and its supporting material;
see {{changes-05}}.

The source of this document and the companion interop record are maintained
at: https://github.com/action-state-group/scitt-payload-binding

--- middle

# Introduction {#intro}

A SCITT Signed Statement {{RFC9943}} frequently carries a digest in place of
the content it stands for: the digest of statement content held elsewhere
({{RFC9995}}), an identifier derived from that content, or the digest of
another artifact that the statement cites. For structured content, such a
digest depends on how the content was serialized before it was hashed, and
more than one serialization is in use. The question this document answers is
how a Signed Statement declares which derivation produced the digest it
carries, so that a verifier need not guess. Where nothing declares it,
independent implementations agree only by convention, and a verifier that
computes a different digest cannot tell a different derivation from
different content. Profiles that needed such digests have each restated
their own derivation, with small variations that defeat interoperability.

The question arises first in the software supply chain, which SCITT is
chartered to serve. Supply chain Signed Statements carry, or cite by digest,
structured documents such as software bills of materials, build records, and
attestations about software artifacts ({{RFC9943}}). When the digest of such a
document is computed over a serialization that nothing in the signed object
names, two conforming implementations can bind the same document to
different digests, and a verifier cannot select the construction that would
reproduce either.

Records of automated and agent actions raise the same question; the agent
action capsule profile {{I-D.mih-scitt-agent-action-capsule}} is one example
of a profile that uses CPB for this purpose.

This document, referred to as CPB, answers the question with declarations
rather than with a payload format. At its core are two things. First, the
Canonicalization Algorithm Registry ({{iana-alg}}), whose entries are names:
each active entry assigns an identifier to a construction specified
elsewhere, such as the JSON Canonicalization Scheme {{RFC8785}}, or to a rule
selecting octets that a container format already fixes, and pins the hash
function and output representation applied to the result ({{algorithms}}).
Second, verifier rules under which the declared construction is used and
never inferred, whether from the shape of a payload or from a header
parameter that identifies only a hash function ({{hash-envelope-mode}}). The
same rule, declare rather than infer, governs the other choices a verifier
would otherwise guess: which Verifiable Data Structure a Receipt uses
({{receipt-binding}}), and whether a log leaf is built from raw digest octets
or from their hexadecimal text ({{leaf-rule}}).

The COSE Hash Envelope {{RFC9995}} identifies a hash function and carries the
resulting digest; when structured content needs a deterministic preimage, CPB
names the profile-selected canonicalization and defines how the derived
identifier is computed with it ({{derived-id}}). CPB also supports the
ordinary RFC 9943 case in which the complete statement content, rather than
its digest, is supplied to COSE. CPB defines this binding mechanics, but it
does not define what any payload means, how it is serialized, or how a
Signed Statement cites other artifacts by digest.

## Out of Scope {#outofscope}

This document does not define:

* Payload formats — any payload format, payload serialization, or required
  payload structure. CPB's normative surface is the protected header, the
  Canonicalization Algorithm Registry ({{iana-alg}}), and producer and
  verifier behavior when computing and checking declared digests. What CPB
  asks of a payload profile is declarations, such as which registered
  identifier, exclusion set, and representation apply, not a structure for
  the payload to take.

* Payload semantics — what fields a payload contains, what their values mean,
  or what verdicts or decisions are carried. Those belong to payload profiles
  that use CPB as their binding layer.

* Artifact types and their digest contexts — which named categories of
  structured content exist, what fields and exclusion sets each declares,
  and which purpose labels its digest contexts use. Those declarations are
  owned by payload or consuming profiles and identified by stable normative
  references. CPB defines no artifact-type registry.

* Citing other artifacts by digest — a mechanism by which one record
  references another record or artifact and identifies what kind of thing is
  referenced. CPB's derived identifier ({{derived-id}}) addresses only the
  record that carries it.

* Application meaning — the real-world interpretation of any record
  anchored via this construction.

* Transparency Service registration policy — which records a Transparency
  Service will or must accept. Registration policy is a Transparency Service
  concern, not a statement profile concern.

* Transports — how registration requests or retrieval queries travel between
  producers, Transparency Services, or verifiers.

# Changes from -05 {#changes-05}

This revision responds to a SCITT Working Group scope review (Jon Geater,
scitt@ietf.org, 2026-09-14), which found the document, as reframed in -05,
still "adjacent" to WG charter: useful for "the principle of establishing
further interoperability among SCITT-using applications," but too wide
because it leans on the Agent Action Capsule and Agent Passport profiles,
and -- architecturally -- because the typed digest reference mechanism
amounted to introducing a new meta content-type for payloads-of-payloads, a
construction the working group considered and dropped early in its history.
-05's own change note described a wording and framing change only, with no
normative change; that could not answer a scope objection, since the
document was 47 pages before and after. This revision instead removes
content, and IS a normative change:

* Typed Digest References (the former Section 8 and its subsections, Profile
  Independence, Discovery Mirror, and Extensibility and Cross-Cutting
  Facilities) are removed in full, along with the `cpb-refs` COSE Header
  Parameter registration that carried them and the Immutable Coordinates,
  Tamper Evidence, and Long-Term Verifiability Considerations subsections of
  Security Considerations, which existed to support that mechanism. Removing
  it removes the shape of the objection, not merely its length: this
  document no longer states that a digest points at a thing of a declared
  type, only that given bytes were canonicalized a stated way. Where the
  removed mechanism finally lands -- a new short document, folded into the
  agent action capsule profile, or a non-normative application note -- is an
  open question outside this revision's scope; {{I-D.mih-scitt-agent-action-capsule}}
  and other documents that cite it are not orphaned by this removal, but
  neither are they satisfied by it yet.
* Related Work and the appendices (worked examples, and the IETF 126
  field-verified instances) are removed; they existed to support and
  demonstrate the removed mechanism and travel with it.
* {{algo-jcs-n}} and {{algo-cde-n}} are compressed to their disposition and a
  pointer to the repository's withdrawal audit
  (`docs/audits/jcsn-withdrawal-audit-2026-08-18.md`); the withdrawn
  constructions themselves are unchanged and remain there, not restated
  here.
* {{intro}} is rewritten to lead with the software supply chain as the
  motivating setting; the agent action capsule profile is named once, as one
  example, rather than framing the document's motivation and its evidence
  together.
* Acknowledgments folds in a contributor addition and a framing widening
  held as an unposted -06 acknowledgments-only revision (2026-09-12),
  superseded by this one rather than posted separately, plus two rewordings
  where a contribution's credit cited material removed above.
* No canonicalization algorithm, hash function, representation, or vector
  changes: `jcs` and `as-transmitted` ({{algo-jcs}}, {{algo-as-transmitted}})
  are unchanged, and the vectors at the locations in
  {{test-vector-locations}} are unchanged.

This revision is a draft for co-author and working-group review only. It has
not been submitted to the datatracker.

The editorial changes that produced -05 from -04, and -04 from -03, are
recorded in -05 and -04 respectively.

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
  ({{iana-alg}}). Every construction registered by this document
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
: A state of a Signed Statement. The COSE signature has been
  cryptographically validated under the selected verification key. This
  state alone does not establish that the key is authorized for the
  asserted issuer. Merely being encoded in a protected header does not
  establish this state.

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

# Canonicalization Algorithm Registrations {#algorithms}

Each entry in this section is a registration in the Canonicalization
Algorithm Registry ({{iana-alg}}). A registration assigns an identifier to a
construction that produces a canonical octet string from a structured value,
or to a rule that selects octets a container format already fixes, and pins
the hash function and output representation applied to the result. The
resulting octet string is the pre-image to CANONICAL-DIGEST. Where the
construction is specified elsewhere, the entry cites that specification
rather than restating it. A payload class declares exactly one
canonicalization algorithm; verifiers MUST NOT guess the algorithm from the
payload shape.

The identifiers registered by this document in the Canonicalization Algorithm
Registry ({{iana-alg}}) are:

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

Identifier:
: `jcs`

Normative reference:
: The JSON Canonicalization Scheme (JCS) {{RFC8785}}, applied directly to the
  octets supplied to the algorithm, with no normalization pass: no member is
  removed because its value is JSON null, an empty array, or an empty object.
  `jcs` places no additional restriction on JSON numbers beyond RFC 8785 itself:
  a JSON floating-point number is permitted and is serialized per the
  canonical ECMAScript-based number-to-string procedure RFC 8785 {{RFC8785}}
  Section 3.2.2.3 defines for IEEE 754 double-precision values. Two conforming
  implementations that parse the same numeric literal into the same
  double-precision value therefore produce byte-identical output; see
  {{floats}}.

Duplicate member names:
: Before converting the input JSON text to a data model, a producer or verifier
  MUST reject a duplicate member name in any object. Equality is tested on
  decoded Unicode member-name strings after JSON escape processing, with no
  Unicode normalization; NFC-equivalent but distinct strings are not duplicate
  names. RFC 8785 {{RFC8785}} operates on the post-parse data model and RFC 8259
  {{RFC8259}} leaves the handling of duplicate names unpredictable, so without
  this rule two conforming implementations could produce different canonical
  octets.

Digest context:
: This entry fixes the canonicalization, the hash function, and the output
  representation of any digest context that names it; the field set and the
  exclusion set belong to the profile that declares that context. The
  pre-image is the canonical UTF-8 octet string that JCS produces. The hash
  function is SHA-256, computed over that octet string. The output
  representation is the digest encoded as lowercase hexadecimal, a
  64-character ASCII string. For the value P supplied to the algorithm:

  ~~~
  CANONICAL-DIGEST(jcs, P) =
      lowercase_hex(SHA-256(JCS(P)))
  ~~~

Declaration rule:
: A payload class or digest context selects this construction by naming
  `jcs`. Exclusion-set removal is not part of this algorithm: the derived
  identifier construction ({{derived-id}}) removes the payload class's declared
  exclusion set before invoking the algorithm. The exclusion set is matched
  against the top-level member names of the payload only; a member of the same
  name nested inside a member's value is not removed. A payload profile MAY
  still declare its own stricter constraint (for example, requiring monetary
  fields to be exact decimal strings) — such a constraint is a payload-profile
  decision, not a requirement of this algorithm.

## Algorithm jcs-n (Withdrawn) {#algo-jcs-n}

Algorithm `jcs-n` is withdrawn (2026-08-18) -- terminal marking, never
deletion: the token stays bound, the definition it once carried is not
reassigned, and it is never carried forward as an active IANA algorithm. The
full historical construction and the withdrawal rationale (implementer
census, byte audit) are recorded in the repository audit at
`docs/audits/jcsn-withdrawal-audit-2026-08-18.md` and are not restated here.
`jcs` ({{algo-jcs}}) is the entry that replaces it going forward.

Withdrawal forecloses new declarations of `jcs-n`; it does not
retroactively invalidate records already sealed under it. A payload class
MUST NOT newly declare `jcs-n`. The vintage cutoff is the start of
2026-08-18 UTC. Pre-cutoff vintage is established only by profile-defined,
cryptographically verifiable evidence that binds the exact record, or its
digest under the declared context, to a time before that cutoff. A payload
timestamp, source-control commit date, file-system time, transport arrival
time, or other unauthenticated date MUST NOT be used as vintage evidence. A
verifier encountering `jcs-n` with evidence of a time at or after the
cutoff, or without sufficient evidence of a pre-cutoff vintage, MUST fail
closed. A historical identifier MUST NOT be relabelled to another algorithm
token or recomputed under another algorithm.

## Algorithm cde-n (Withdrawn) {#algo-cde-n}

Algorithm `cde-n` is withdrawn. It is a recorded terminal state, not a
deletion: the token was reserved for a deterministic CBOR canonicalization
profile, but it was never assigned a definition, and it will not be --
the same terminal-marking disposition as `jcs-n` ({{algo-jcs-n}}), recorded
in `docs/audits/jcsn-withdrawal-audit-2026-08-18.md`. The entry remains in
the Canonicalization Algorithm Registry ({{iana-alg}}) as withdrawn: the
reserved entry bound the token, so the token stays bound, never assigned,
never reassigned. A payload class naming `cde-n` MUST fail closed: the token
names no defined algorithm and never will.

## Algorithm as-transmitted {#algo-as-transmitted}

Algorithm `as-transmitted` is a rule about which octets are digested, not a
transformation of them. It applies no canonicalization. The digest pre-image
is the exact octet sequence already fixed by the container format or
cryptographic envelope carrying the payload -- for example, the signing input
over which a signature was computed. The signature (or other format-defined
byte-fixing) is what makes those bytes authoritative; re-canonicalizing them
would be redundant at best and would break the very binding that makes the
bytes authoritative at worst.

Identifier:
: `as-transmitted`

Normative reference:
: None of its own. The octets are named by the container specification that
  the declaring digest context cites in its byte-boundary selector, as the
  declaration rule below requires.

Digest context:
: This entry fixes the hash function and the output representation of any
  digest context that names it; in place of a field set, an exclusion set,
  and a canonicalization, that context states a byte-boundary selector. The
  hash function is SHA-256 and the output representation is 64-character
  lowercase hex, matching `jcs`. These are stated explicitly here as part of
  this entry, not inherited silently from the generic CANONICAL-DIGEST
  definition ({{conventions}}). For a byte sequence B identified by the
  declared byte-boundary selector:

  ~~~
  CANONICAL-DIGEST(as-transmitted, B) = lowercase_hex(SHA-256(B))
  ~~~

Declaration rule:
: Because there is no canonicalization step, `as-transmitted` has no field set
  and no exclusion set. A profile-owned artifact-type declaration that selects
  `as-transmitted` for a digest context MUST instead state a byte-boundary
  selector in place of a field set: a normative reference plus the name that
  referenced specification gives to the exact byte sequence in question. Two
  examples of a valid selector:

  * {{RFC7515}}, Section 5.1, `JWS Signing Input` -- the octets a JWS
    signature is computed over.
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

# The Derived Identifier {#derived-id}

The derived identifier of a record is computed as:

~~~
id = CANONICAL-DIGEST(A, payload minus exclusion_set)
~~~

where A is the canonicalization algorithm declared by the payload class and
the exclusion set is the set of fields declared by the payload class as
self-referential or chain-linkage fields. The derived identifier is a
64-character lowercase hex string for every construction this document
registers.
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
parameters defined elsewhere.

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
the derived identifier, the constructions registered by this document produce
a 32-byte RAW-DIGEST and a 64-character hexadecimal CANONICAL-DIGEST
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

# Privacy Considerations {#privacy}

CPB provides integrity binding, not confidentiality. Full-Content Mode exposes
the statement payload unless another applicable mechanism protects it. Hash
Envelope Mode can withhold the preimage, but exposes a stable digest. COSE
protected headers are integrity-protected after successful signature
validation and issuer-authenticated only after the applicable key policy
succeeds; they are not encrypted.

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
Payload Binding" heading. The Canonicalization Algorithm Registry uses the
Specification Required policy ({{RFC8126}}, Section 4.6); a Designated
Expert is required for each registration. This document neither creates nor
depends on an artifact-type registry.

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

Each entry pins the pre-image construction it names, its hash function, and
its output representation together as a single immutable triple, so that
changing any one of the three requires registering a new token rather than
reinterpreting an existing one — otherwise a token such as `jcs` would
silently come to mean more than its name states.

Registration template:

* Name: A short ASCII identifier suitable for use in protocol fields.
* Status: `Active`, `Reserved`, or `Withdrawn`.
* Preimage construction: A normative description sufficient to implement the
  canonicalization or byte-selection operation deterministically.
* Hash function and digest_alg token: The hash function and the exact
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

The preimage construction for each active entry is given in
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

A payload class naming `cde-n` MUST NOT be treated as verifiable under any
vintage: the token was bound by a reserved entry but never assigned a
definition, so no construction exists to verify against, and a verifier
encountering it MUST fail closed. A payload class naming `jcs-n` MUST NOT be
newly declared; records committed under it before 2026-08-18 are governed by
the vintage rule in {{algo-jcs-n}}. Both withdrawals are recorded terminal
states, not deletions: the tokens stay bound and are never assigned or
reassigned. See {{algo-cde-n}} and {{algo-jcs-n}}.

An artifact type MUST NOT declare `as-transmitted` without a byte-boundary
selector that cites a named production in the container specification
({{algo-as-transmitted}}). Without that selector, an `as-transmitted`
declaration states nothing: there is no field set, no exclusion set, and no
canonicalization to fall back on for the pre-image construction.

--- back

# Acknowledgments {#acknowledgments}
{:numbered="false"}

The following individuals contributed findings that directly shaped the
rules in this document, whether raised at the IETF 126 hackathon in Vienna
or through public review afterward. All attributions cite public artifacts.

**Contributors** \[all named attributions and contributor acknowledgments
individually confirmed: Anton Sokolov (confirmed 2026-07-24), Iman Schrock
(confirmed 2026-07-24), Tom Sato (confirmed 2026-07-25), Yong Bok Lee (Scott
Lee) (contributor attribution confirmed 2026-07-27), Tymofii Pidlisnyi (Agent Passport System,
confirmed 2026-07-24, on-issue), Karthik Rampalli (Glyphzero, confirmed
2026-07-25, email, with corrections), Imran Siddique (Opaque Systems,
confirmed 2026-09-11, on-issue)\]:

* Anton Sokolov (Tyche Institute) — assurance-boundary discipline
  underlying this document's declare-rather-than-infer rule, demonstrated
  at the IETF 126 hackathon by the A2A boundary-seal instance (a derived
  identifier used as a protocol gate).

* Yong Bok Lee (Scott Lee), Meridian Verity Group — ORPRG-derived
  cross-profile digest-context discipline: equal-looking digest text alone
  is not a valid join, a finding that fed the digest-context discipline
  underlying {{derived-id}} and {{representation}}. See
  {{I-D.lee-orprg-permit-receipts}}.

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

* Iman Schrock (EMILIA/EP) — confirmed 2026-07-24; wording narrowed at the
  contributor's request 2026-09-07 — the single-digest composition instance
  (`8cf0c36e...`), in which an authorization receipt
  {{I-D.schrock-ep-authorization-receipts}} and an action record produced by
  different implementations carry the same action digest, demonstrating that
  independently derived identifiers agree byte-for-byte under this
  document's canonicalization rules.

* Imran Siddique (Opaque Systems) — identifying that the `jcs-n` normalization
  pass was not needed, which led to its withdrawal and the registration of
  plain `jcs` (#34);
  the `digest_alg` consistency-declaration clarification and the withdrawal
  of `cde-n` (#36); and the verifier-behaviour rules for unregistered
  external artifact types (#35).

**Acknowledged** \[Amaury Chamayou confirmed 2026-07-24 (email)\]:

* Amaury Chamayou (Microsoft) — two-TS single-statement demonstration;
  the vds-from-protected-header finding subsequently mirrored in
  microsoft/scitt-ccf-ledger #424.
