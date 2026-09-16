---
title: "Preimage Encoding for COSE Hash Envelopes"
abbrev: "COSE Hash Envelope Preimage Encoding"
docname: draft-mih-sokolov-cose-hash-envelope-preimage-encoding-00
date: 2026-09-16
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
  RFC8785:
  RFC9943:

--- abstract

The COSE Hash Envelope lets a COSE_Sign1 carry the hash of content held
elsewhere, together with the hash algorithm, the content type of the hashed
bytes, and a hint for where to retrieve them. When the hashed content is
structured, more than one deterministic serialization of that content is
commonly in use, and the Hash Envelope does not identify which one produced
the hashed bytes. This document defines a protected-header parameter,
payload-preimage-encoding, that names the deterministic encoding a producer
applied before hashing, and a small IANA registry of encoding identifiers
led by the Core Deterministic Encoding Requirements of RFC 8949. It is an
extension to the COSE Hash Envelope, and the parameter it defines is usable
with any COSE_Sign1.

--- note_Note_to_Readers

This document is an individual submission. The intended venue is the COSE
Working Group (cose@ietf.org). **This revision is a draft for co-author and
working-group review only; it has not been submitted to the datatracker.**
The Acknowledgments name individuals whose review shaped this document's
approach; individually confirmed acknowledgment text will be finalized
before submission.

--- middle

# Introduction {#intro}

The COSE Hash Envelope {{RFC9995}} identifies the hash function (258) and
the content type of the hashed bytes (259), but not which of the (possibly
several) deterministic serializations of that content type produced them --
a fact a verifier needs to recompute the hash of structured content such as
JSON or CBOR and compare it to the payload.

This document defines one new protected-header parameter,
payload-preimage-encoding, naming the deterministic encoding applied before
hashing, and a small IANA registry of encoding identifiers. It extends the
COSE Hash Envelope without changing {{RFC9995}} itself: the protected
header already permits extension parameters (CDDL `* (int / tstr) =>
any`).

The SCITT Signed Statement {{RFC9943}} is one principal user of the Hash
Envelope; the parameter this document defines applies to any COSE_Sign1.

# Terminology {#terminology}

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
{{RFC2119}} {{RFC8174}} when, and only when, they appear in all capitals, as
shown here.

"COSE", "COSE_Sign1", and "protected header" are defined in {{RFC9052}};
"CDDL" in {{RFC8610}}; "preimage" in Section 2 of {{RFC9995}}. "Hash
Envelope" refers to the COSE_Sign1 construction of {{RFC9995}}, whose header
parameters 258, 259, and 260 (payload-hash-alg, preimage-content-type,
payload-location) together describe a payload that is the hash of content
available separately from the COSE_Sign1 itself.

# The payload-preimage-encoding Header Parameter {#header-param}

This document defines one new COSE header parameter:

261:
: payload-preimage-encoding. The deterministic encoding applied to
  structured content to produce the octets identified by
  preimage-content-type (259) and hashed to produce the payload identified
  by payload-hash-alg (258). The value is an identifier registered in the
  COSE Preimage Encodings registry ({{iana-encodings}}).

It amends the Hash_Envelope_Protected_Header CDDL of {{RFC9995}} Section 4
with one optional member, inserted alongside the members for labels
258-260:

~~~ cddl
? &(payload_preimage_encoding: 261) => int,
~~~

Label 261 MAY be present in the protected header and MUST NOT be present in
the unprotected header, the same placement rule {{RFC9995}} states for
labels 258 through 260. It MAY also appear in the protected header of a
COSE_Sign1 that is not a Hash Envelope, with the same meaning applied
directly to the payload octets, as a small, self-contained building block; a
signer that canonicalizes its payload before signing MAY use it without
adopting the rest of {{RFC9995}}. The rest of this document addresses Hash
Envelope Mode.

# Producer and Verifier Behavior {#behavior}

When the preimage is structured content that was canonicalized before
hashing, the producer SHOULD set payload-preimage-encoding; if set, the
value MUST be the encoding actually applied to produce the hashed octets.

A verifier MUST NOT infer the preimage encoding from preimage-content-type
(259) or from the shape of the recomputed content. If
payload-preimage-encoding is absent or carries a value the verifier does not
recognize, the content binding cannot be verified by recomputation: the
verifier fails closed on that binding and MUST NOT report it as verified.
Signature validity is unaffected -- a verifier that has not established the
content binding can still report Signature-Valid status for the COSE_Sign1
itself.

# Examples {#examples}

The following use Extended Diagnostic Notation ({{RFC8610}} Appendix G), in
the style of {{RFC9995}} Section 4.1; signature and key material are
illustrative and truncated.

The preimage `{"b": 2, "a": 1}`, encoded per the Core Deterministic
Encoding Requirements of {{RFC8949}} Section 4.2.1 (key order is bytewise,
placing "a" before "b" regardless of source order), is the 7-octet string
`a2616101616202`, whose SHA-256 digest is
`a0d3af9e86e5517f729bad0657e2c6f3b7d03899894c8d6b33759074c893b5e3`:

~~~
18([ # COSE_Sign1
  <<{
    / alg               / 1: -7, # ES256
    / hash algorithm    / 258: -16, # sha-256
    / preimage type     / 259: "application/cbor",
    / preimage encoding / 261: 1, # cbor-deterministic
  }>>
  / unprotected / {},
  / payload     / h'a0d3af9e...c893b5e3', # digest above
  / signature   / h'304502210...3b1c9f0e'
])
~~~

The same structure demonstrates value 2 with 259 `"application/json"` and
261 `2`: for the JCS {{RFC8785}}-canonicalized preimage
`{"a":{},"m":[],"s":"CPB","z":null}`, the payload is the SHA-256 digest
`7b3ef8ebf31ee38952860dd3f30c2e0d101dcdbcd9972e3ed8108ef9cff0d7cb`.

# Security Considerations {#security}

## Preimages Are Bytes, Not Renderings {#security-bytes}

The preimage identified by 259 and encoded per 261 is the exact octet
string the named encoding produces -- not a rendered form or a string
differing from it by whitespace, newlines, or character-encoding choices.

A producer that re-reads stored content before hashing MUST ensure the
octets entering the hash function are byte-identical to the encoding's own
output; a deserialize-then-reserialize round trip is not guaranteed to
reproduce it, even for encodings designed to be deterministic
({{iana-encodings}}).

## Encoding Agility {#security-agility}

The COSE Preimage Encodings registry ({{iana-encodings}}) grows by
registering a new value for a new encoding, never by reinterpreting the
octets an existing value already governs; each entry's definition, once
registered, is immutable.

# Privacy Considerations {#privacy}

A digest computed over deterministically encoded content is a stable
function of that content, making the payload linkable across contexts
where it recurs. When the preimage is drawn from a low-entropy value
space, encoding a candidate with 261 and hashing it with 258 can recover
the preimage by comparison to the payload -- a risk that already exists
wherever {{RFC9995}} is used; naming the encoding removes ambiguity that
might otherwise have slowed such an attempt.

# IANA Considerations {#iana}

## COSE Header Parameters {#iana-header}

IANA is requested to register the following entry in the "COSE Header
Parameters" registry, in the "Integer values from 256 to 65535" range, per
the Specification Required registration policy ({{RFC8126}} Section 4.6)
that governs that range:

| Name | Label | Value Type | Value Registry | Description | Reference |
|---|---|---|---|---|---|
| payload-preimage-encoding | 261 (requested) | int | COSE Preimage Encodings ({{iana-encodings}}) | Encoding applied before hashing a Hash Envelope payload | This document |

## COSE Preimage Encodings Registry {#iana-encodings}

IANA is requested to create a new registry, "COSE Preimage Encodings".
Registration policy: Specification Required ({{RFC8126}} Section 4.6); a
Designated Expert reviews each registration. Registration template: Value,
Name, Description, Reference.

Initial contents:

| Value | Name | Description | Reference |
|---|---|---|---|
| 0 | Reserved | | This document |
| 1 | cbor-deterministic | Core Deterministic Encoding Requirements for CBOR | {{RFC8949}} Section 4.2.1 |
| 2 | jcs | JSON Canonicalization Scheme | {{RFC8785}} (informative) |

Value 1, cbor-deterministic, is this registry's lead entry: {{RFC8949}}
Section 4.2.1, Core Deterministic Encoding Requirements, part of STD 94.
`draft-ietf-cbor-cde` is, at the time of writing, an expired working-group
Internet-Draft, not an RFC, and is not registered here.

Value 2, jcs, names {{RFC8785}} informatively: an Independent Submission
this document does not require any implementation to support, registered
because JCS preimages are already in deployed use.

--- back

# Acknowledgments {#acknowledgments}
{:numbered="false"}

Amaury Chamayou and Henk Birkholz reviewed this document's approach -- a
COSE header-parameter extension separated from the Signed Statement
profile it was drawn from -- and gave comments that shaped it. Confirmed
acknowledgment text will be finalized before submission.
