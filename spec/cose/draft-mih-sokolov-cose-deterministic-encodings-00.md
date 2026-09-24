---
title: "Declaring the Deterministic Encoding of Hashed Content in COSE"
abbrev: "COSE Deterministic Encoding Declaration"
docname: draft-mih-sokolov-cose-deterministic-encodings-00
date: 2026-09-23
category: std
submissiontype: IETF
ipr: trust200902
area: "Security"
workgroup: "COSE"
keyword:
 - COSE
 - hash envelope
 - preimage
 - canonicalization
 - deterministic encoding
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
  RFC8610:
  RFC8949:
  RFC9052:
  RFC9995:

informative:
  RFC9943:
  I-D.ietf-cbor-cde:
  C2PASpec:
    title: "Content Credentials: C2PA Technical Specification 2.2"
    target: https://spec.c2pa.org/specifications/specifications/2.2/specs/_attachments/C2PA_Specification.pdf
    date: 2025-05-01
    author:
      - organization: Coalition for Content Provenance and Authenticity (C2PA)
  VTOSpec:
    title: "libp2p Verified Telemetry Object (VTO) Specification (work in progress)"
    target: https://github.com/seetadev/libp2p-vto-spec
    author:
      - organization: libp2p / seetadev (in-progress specification)

--- abstract

The COSE Hash Envelope carries the hash of content held elsewhere. When that
content is structured, more than one deterministic serialization of it may be
in use, and the Hash Envelope does not identify which one produced the hashed
bytes -- so a verifier cannot reliably recompute the hash. This document
defines a protected-header parameter, payload-preimage-encoding, that names
the deterministic encoding a producer applied before hashing a Hash Envelope
payload, and a small IANA registry of deterministic encoding identifiers,
populated at issuance with an entry for the Core Deterministic Encoding
Requirements of RFC 8949.
It extends the COSE Hash Envelope through the existing extension point.

--- note_Note_to_Readers

This document is an individual submission; the intended working group is the
COSE Working Group (cose@ietf.org). **This revision is a draft for co-author and working-group
review only; it has not been submitted to the datatracker.**

--- middle

# Introduction {#intro}

Structured content commonly has more than one deterministic serialization
in use. The COSE Hash Envelope {{RFC9995}} identifies the hash function
(258) and the content type of the hashed bytes (259), but not which of those
serializations produced them -- which a verifier needs to recompute the hash
of structured content, such as CBOR, and compare it to the payload.

This document defines one new protected-header parameter,
payload-preimage-encoding, naming that deterministic encoding, and a small
IANA registry of encoding identifiers. It changes nothing in {{RFC9995}}: the
Hash Envelope protected header already admits extension parameters through its
open CDDL member (`* (int / tstr) => any`), and this document adds a value
through that existing extension point. It names the deterministic encoding a
producer applied before hashing a Hash Envelope payload. The SCITT Signed
Statement {{RFC9943}} is one principal user of the Hash Envelope.

# Terminology {#terminology}

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
{{RFC2119}} {{RFC8174}} when, and only when, they appear in all capitals, as
shown here.

"COSE", "COSE_Sign1", and "protected header" are defined in {{RFC9052}};
"CDDL" in {{RFC8610}}; "Hash Envelope" and "preimage" in {{RFC9995}}.
The Hash Envelope labels this document builds on are 258 (payload-hash-alg)
and 259 (preimage-content-type).

# The payload-preimage-encoding Header Parameter {#header-param}

This document defines the parameter as:

TBD:
: payload-preimage-encoding. The deterministic encoding applied to
  structured content to produce the octets identified by
  preimage-content-type (259) and hashed to produce the payload identified
  by payload-hash-alg (258). The value is the integer Value (not the Name)
  assigned to an encoding in the COSE Deterministic Encodings registry
  ({{iana-encodings}}).

It amends the Hash_Envelope_Protected_Header CDDL of {{RFC9995}} Section 4
with one optional member, alongside the members for labels 258-260:

~~~ cddl
? &(payload_preimage_encoding: TBD) => int,
~~~

Label TBD MAY be present in the protected header and MUST NOT be present in
the unprotected header, following the placement rule {{RFC9995}} states for
labels 258 through 260.

# Producer and Verifier Behavior {#behavior}

When the preimage is structured content that was canonicalized before
hashing, the producer MUST set payload-preimage-encoding; the value MUST be
the encoding actually applied to produce the hashed octets.
An unstructured preimage -- for example application/octet-stream, an image,
or an archive -- has no deterministic encoding to name, and the parameter is
simply absent.

A verifier MUST NOT infer the preimage encoding from preimage-content-type
(259) or from the shape of the recomputed content. If
payload-preimage-encoding is absent or carries an unrecognized value, the
content binding cannot be verified by recomputation: the verifier MUST NOT
report that binding as verified, and MUST report it as unverified rather
than as failed. Unverified means the verifier lacked the information
needed to recompute; failed means a recomputation was performed and did
not match. A Hash Envelope sealed before this parameter was registered is
expected to lack it, and that absence is not a defect. Signature validity
is unaffected -- a verifier that has not established the content binding
can still report Signature-Valid status for the COSE_Sign1 itself.

An encoding's definition constrains the preimage-content-type (259) it may
be used with. A producer MUST NOT pair an encoding with an incompatible
content type (for example, cde with a non-CBOR content type such as
application/json), and a verifier MUST reject a Hash Envelope whose
payload-preimage-encoding and preimage-content-type (259) are inconsistent.

# Examples {#examples}

These use Extended Diagnostic Notation ({{RFC8610}} Appendix G), in the
style of {{RFC9995}} Section 4.1; signature and key material are truncated.

The preimage `{"b": 2, "a": 1}`, encoded per the Core Deterministic
Encoding Requirements of {{RFC8949}} Section 4.2.1 (bytewise key order,
placing "a" before "b"), is the 7-octet string `a2616101616202`, whose
SHA-256 digest is
`a0d3af9e86e5517f729bad0657e2c6f3b7d03899894c8d6b33759074c893b5e3`:

~~~
18([ # COSE_Sign1
  <<{
    / alg               / 1: -7, # ES256
    / hash algorithm    / 258: -16, # sha-256
    / preimage type     / 259: "application/cbor",
    / preimage encoding / TBD: 1, # cde
  }>>
  / unprotected / {},
  / payload     / h'a0d3af9e...c893b5e3', # digest above
  / signature   / h'304502210...3b1c9f0e'
])
~~~

## Where These Encodings Already Apply {#examples-deployed}

The entry in the registry ({{iana-encodings}}) is not hypothetical; it names an
encoding that a deployed specification, in a domain unrelated to the one that
motivated this document, already applies before hashing or signing structured
content.

cde: {{C2PASpec}} Section 10.1 states that a C2PA claim is encoded as CBOR and,
as such, "shall comply with the Core Deterministic Encoding Requirements of
CBOR (see RFC 8949, clause 4.2.1)" before it is hashed into the claim
signature. A Hash Envelope carrying such a claim as its preimage would set
payload-preimage-encoding to cde (Value 1) for exactly the reason {{C2PASpec}}
imposes that requirement: a verifier recomputing the claim's hash has to know
which deterministic encoding produced the bytes it is re-deriving.

cde: {{VTOSpec}}, an in-progress libp2p specification for the Verified
Telemetry Object (VTO), encodes each telemetry object with "definite-length
CBOR maps, deterministic key ordering by encoded-key bytes, IEEE 754 binary64
floats, and SHA-256 multihashes over the raw CBOR item" -- the Core
Deterministic Encoding Requirements of {{RFC8949}} Section 4.2.1 applied
before hashing. A producer emitting a VTO as a Hash Envelope preimage would set
payload-preimage-encoding to cde (Value 1), because VTO already encodes its
telemetry objects with that deterministic CBOR encoding before hashing, and a
verifier re-deriving the SHA-256 over the raw CBOR item has to know it.

# Security Considerations {#security}

## Preimages Are Bytes, Not Renderings {#security-bytes}

The preimage identified by 259 and encoded per TBD is the exact octet
string the named encoding produces -- not a rendered form or a string
differing from it by whitespace, newlines, or character-encoding choices.

A producer that re-reads stored content before hashing MUST ensure the
octets entering the hash function are byte-identical to the encoding's own
output; a deserialize-then-reserialize round trip is not guaranteed to
reproduce it, even for deterministic encodings ({{iana-encodings}}).

Likewise, the Hash Envelope payload is the raw digest octets the hash
function (258) produces, not a textual representation of that digest.
Whether a digest is rendered -- for example as 64-character lowercase
hexadecimal -- is a profile-level concern and is out of scope for this
document.

## Encoding Agility {#security-agility}

The COSE Deterministic Encodings registry ({{iana-encodings}}) grows by
registering a new value for a new encoding, never by reinterpreting the
octets an existing value governs; each entry's definition, once registered,
is immutable. A registered value MAY be withdrawn through the same Specification Required
review. Withdrawal is terminal: the token stays bound, no definition is ever
assigned or reassigned to it, and the value is not reused.

# Privacy Considerations {#privacy}

A digest over deterministically encoded content is a stable function of
that content, making the payload linkable across contexts where it recurs.
When the preimage is drawn from a low-entropy value space, encoding a
candidate under the named encoding and hashing it with 258 can recover the preimage by
comparison to the payload -- a risk that already exists wherever {{RFC9995}}
is used; naming the encoding removes ambiguity that might have slowed such an
attempt.

# IANA Considerations {#iana}

## COSE Header Parameters {#iana-header}

IANA is requested to register the following entry in the "COSE Header
Parameters" registry, in the "Integer values from 256 to 65535" range,
under the Specification Required policy ({{RFC8126}} Section 4.6) that
governs that range:

| Name | Label | Value Type | Value Registry | Description | Reference |
|---|---|---|---|---|---|
| payload-preimage-encoding | TBD (requested) | int | COSE Deterministic Encodings ({{iana-encodings}}) | Encoding applied before hashing a Hash Envelope payload | This document |

The suggested value is 271, the lowest unassigned integer in the COSE
Header Parameters registry as of 2026-09-22.

## COSE Deterministic Encodings Registry {#iana-encodings}

IANA is requested to create a new registry, "COSE Deterministic Encodings".
The registry names deterministic encodings of structured content; it carries
no Hash Envelope semantics of its own, and a value registered in it is
meaningful only through a parameter, such as payload-preimage-encoding
({{header-param}}), that gives the name a role. A registry, rather than a
fixed reference, is used because more than one deterministic encoding is
expected to be named for Hash Envelope use over time, from more than one
content-type family: the CBOR Common Deterministic Encoding {{I-D.ietf-cbor-cde}}, in
progress in the CBOR Working Group and distinct from the core requirements
RFC 8949 Section 4.2.1 defines, is an anticipated future registration.
Specification Required keeps each addition reviewed and immutable.
Registration policy: Specification Required ({{RFC8126}} Section 4.6), with
Designated Expert review. Registration template: Value, Name, Description,
Applicable Content Types, Reference. Initial contents:

| Value | Name | Description | Applicable Content Types | Reference |
|---|---|---|---|---|
| 1 | cde | CBOR deterministic encoding per the core deterministic encoding requirements of RFC 8949 Section 4.2.1 | CBOR content types, such as application/cbor | {{RFC8949}} Section 4.2.1 |

Value 1, cde, is the Core Deterministic Encoding Requirements of
{{RFC8949}} Section 4.2.1, part of STD 94.

The registry is open under the policy above, so encodings for other
structured content types can be added by later registrations, each citing
its own reference.

--- back
