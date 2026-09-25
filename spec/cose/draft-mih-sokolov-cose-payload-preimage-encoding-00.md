---
title: "The COSE payload-preimage-encoding Header Parameter"
abbrev: "COSE payload-preimage-encoding"
docname: draft-mih-sokolov-cose-payload-preimage-encoding-00
date: 2026-09-22
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
  RFC6838:
  RFC7252:
  RFC8126:
  RFC8610:
  RFC8742:
  RFC8949:
  RFC9052:
  RFC9995:

informative:
  RFC9943:
  I-D.ietf-cbor-cde:

--- abstract

A COSE Hash Envelope carries the hash of a preimage held elsewhere. When
structured content is serialized into a preimage, the Hash Envelope does not
capture the specific encoding algorithm that was used. A verifier who has
access to the content, but not to the preimage itself, is therefore unable
to reliably confirm that this content matches the hash. This document
defines an extension to COSE Hash Envelope: an additional protected-header
parameter (payload-preimage-encoding) which captures the specific encoding a
producer applied to create the preimage, and a small IANA registry of
encoding identifiers whose initial entry is the Core Deterministic Encoding
Requirements of RFC 8949.

--- note_Note_to_Readers

This document is an individual submission; the intended working group is the
COSE Working Group (cose@ietf.org). **This revision is a draft for co-author and working-group
review only; it has not been submitted to the datatracker.**

--- middle

# Introduction {#intro}

Structured content formats often do not mandate a single deterministic
encoding algorithm, with the result that the same entity can be represented
by more than one sequence of serialized bytes. The COSE Hash Envelope
{{RFC9995}} format identifies the hash function (258) and the content type
of the preimage (259), but not which specific encoding produced it for
structured content. A verifier that holds the preimage bytes can hash them
and compare the result to the payload ({{RFC9995}} Section 5.3), but a
verifier that holds structured content, such as CBOR, only in decoded form
has to re-encode it first, and needs to know which specific algorithm to
use.

This document defines one new protected-header parameter,
payload-preimage-encoding, which captures that deterministic encoding, and a
small IANA registry of encoding identifiers. The Hash Envelope protected
header as specified in {{Section 4 of RFC9995}} admits extension parameters
(`* (int / tstr) => any`), and this document defines an additional parameter
through that existing extension point.

# Terminology {#terminology}

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
{{RFC2119}} {{RFC8174}} when, and only when, they appear in all capitals, as
shown here.

"COSE", "COSE_Sign1", and "protected header" are defined in {{RFC9052}};
"CDDL" in {{RFC8610}}; "Hash Envelope" and "preimage" in {{RFC9995}}.
As in {{RFC9995}}, the payload of a Hash Envelope is a digest, and the
preimage is the octet string that was hashed to produce it.
The Hash Envelope labels this document builds on are 258 (payload-hash-alg),
259 (preimage-content-type), and 260 (payload-location).

This document also uses the following terms:

Structured value:
: A value with internal structure, such as a CBOR data item, that a
  deterministic encoding serializes to create a preimage.

Content binding:
: The correspondence between content a verifier holds -- a preimage, or a
  structured value -- and the payload of a Hash Envelope. A verifier that
  checks a content binding reports one of three outcomes: verified, failed,
  or unverified.

Verified:
: The verifier hashed the preimage -- as held, or as re-created from a
  structured value -- with the payload-hash-alg (258) algorithm and obtained
  the payload, and did not find the protected header inconsistent
  ({{consistency}}).

Failed:
: The verifier found the protected header inconsistent ({{consistency}}),
  or hashed the preimage, as held or as re-created, and obtained a value
  other than the payload.

Unverified:
: Any other case; in particular, the verifier could not perform the
  comparison because it holds neither the preimage nor the information
  needed to re-create it ({{verification}}).

These outcomes concern the content binding only; signature validity is
determined independently of them ({{verification}}).

# The payload-preimage-encoding Header Parameter {#header-param}

This document defines the parameter as:

TBD\_1:
: payload-preimage-encoding. The deterministic encoding applied to a
  structured value to create the preimage, which has the content type given
  by preimage-content-type (259) and was hashed with the payload-hash-alg
  (258) algorithm to produce the payload. The value is the integer Value
  (not the Name) assigned to an encoding in the COSE Preimage Encodings
  registry ({{iana-encodings}}).

It extends {{RFC9995}} by adding one optional member to the
Hash_Envelope_Protected_Header CDDL of {{RFC9995}} Section 4, alongside the
members for labels 258-260. The extended rule restates the {{RFC9995}} rule
with that member added:

~~~ cddl
Hash_Envelope_Protected_Header_With_Encoding = {
    ? &(alg: 1) => int,
    &(payload_hash_alg: 258) => int,
    ? &(payload_preimage_content_type: 259) => uint / tstr,
    ? &(payload_location: 260) => tstr,
    ? &(payload_preimage_encoding: TBD_1) => int,
    * (int / tstr) => any
}
~~~

Label TBD\_1 MAY be present in the protected header and MUST NOT be present
in the unprotected header, following the placement rule {{RFC9995}} states
for labels 258 through 260. When label TBD\_1 is present,
preimage-content-type (259) MUST also be present ({{consistency}}).

# Producer and Verifier Behavior {#behavior}

## Producers {#producers}

When a producer creates the preimage by applying a deterministic encoding to
a structured value, it MUST include payload-preimage-encoding, and the value
MUST identify the encoding actually applied.
An unstructured preimage -- for example application/octet-stream, an image,
or an archive -- has no deterministic encoding to capture, and the parameter
is simply absent.

## Consistency with preimage-content-type {#consistency}

Each registered encoding lists the content types it applies to, as the
Applicable Content Types of its registry entry ({{iana-encodings}}). When
payload-preimage-encoding is present, preimage-content-type (259) MUST also
be present, and its value MUST match one of the Applicable Content Types of
the captured encoding:

* A 259 value that is a media-type name matches when its type and subtype --
  with any parameters removed, and compared case-insensitively ({{RFC6838}}
  Section 4.2) -- equal a listed media type, or when its subtype ends in a
  listed structured syntax suffix ({{RFC6838}} Section 4.2.8).

* A 259 value that is a Content-Format number matches when the CoAP
  Content-Formats registry ({{RFC7252}} Section 12.3) assigns that number to
  a matching media type with no content coding.

A producer MUST NOT emit a Hash Envelope that violates these rules -- for
example, one pairing core-deterministic with application/json. A verifier
that finds payload-preimage-encoding present with preimage-content-type
(259) absent, or with a 259 value that does not match the Applicable Content
Types of an encoding the verifier recognizes, MUST report the content
binding as failed, without attempting recomputation. This check comes
first, and takes precedence over {{verification}}.

## Verifying the Content Binding {#verification}

A verifier that holds the preimage itself -- for example, as retrieved from
payload-location (260) -- checks the content binding as {{RFC9995}}
Section 5.3 describes: it hashes the preimage with the payload-hash-alg (258)
algorithm and compares the result to the payload. That check needs no
encoding information, and applies whether or not payload-preimage-encoding
is present, subject to {{consistency}}.

A verifier that holds only a structured value -- for example, content it
received, stored, or decoded in a form other than the preimage itself --
has to re-create the preimage by encoding that value, and needs
payload-preimage-encoding to do so. Such a verifier MUST encode the value
with the encoding the parameter captures, and MUST NOT infer the encoding
from preimage-content-type (259) or from the structure of the value. If
payload-preimage-encoding is absent, or carries a value the verifier does
not recognize or implement, the verifier cannot re-create the preimage: it
MUST NOT report the content binding as verified, and MUST report it as
unverified rather than as failed.

A Hash Envelope produced without this parameter -- including any produced
before the parameter was registered -- is not defective: its content binding
can still be verified from the preimage octets. Signature validity is
unaffected by any content-binding outcome: a verifier that has not
established the content binding can still validate the signature of the
COSE_Sign1 as specified in {{RFC9052}}.

# Examples {#examples}

These use Extended Diagnostic Notation ({{RFC8610}} Appendix G), in the
style of {{RFC9995}} Section 4.1; signature and key material are truncated.

The structured value `{"b": 2, "a": 1}`, a CBOR map, encoded per the Core
Deterministic Encoding Requirements of {{RFC8949}} Section 4.2.1 (bytewise
key order, placing "a" before "b"), gives the 7-octet preimage
`a2616101616202`, whose SHA-256 digest is
`a0d3af9e86e5517f729bad0657e2c6f3b7d03899894c8d6b33759074c893b5e3`:

~~~
18([ # COSE_Sign1
  <<{
    / alg               / 1: -7, # ES256
    / hash algorithm    / 258: -16, # sha-256
    / preimage type     / 259: "application/cbor",
    / preimage encoding / TBD_1: 1, # core-deterministic
  }>>
  / unprotected / {},
  / payload     / h'a0d3af9e...c893b5e3', # digest above
  / signature   / h'304502210...3b1c9f0e'
])
~~~

# Security Considerations {#security}

## Preimages Are Bytes, Not Renderings {#security-bytes}

The preimage is the exact octet string that the encoding captured by TBD\_1
produces -- not a rendered form or a string differing from it by whitespace,
newlines, or character-encoding choices.

A deterministic encoding fixes the preimage for a given structured value, so
decoding a preimage and encoding the result again reproduces the preimage
only if decoding preserved that value exactly. Decoding into a programming
language's native types can lose distinctions the encoding depends on -- for
example, between integer and floating-point numbers, or the presence of a
tag. The core deterministic encoding requirements of {{RFC8949}} Section
4.2.1 also leave some choices to each application, such as those {{RFC8949}}
Section 4.2.2 describes for tags, large integers, and floating-point values;
those choices belong to the structured value, not to the encoding this
parameter captures. A producer that re-reads stored content before hashing
MUST ensure the preimage it hashes is byte-identical to the encoding's own
output. A verifier that re-creates a preimage from a structured value
({{verification}}) needs that value exactly as the producer encoded it;
otherwise its recomputed digest can differ from the payload, and the content
binding is then reported as failed.

Likewise, the Hash Envelope payload is the raw digest octets the hash
function (258) produces, not a textual representation of that digest.
Whether a digest is rendered -- for example as 64-character lowercase
hexadecimal -- is a profile-level concern and is out of scope for this
document.

## Encoding Agility {#security-agility}

The COSE Preimage Encodings registry ({{iana-encodings}}) grows by
registering a new value for a new encoding, never by reinterpreting the
preimages an existing value governs; each entry's definition, once registered,
is immutable. A registered value MAY be withdrawn through the same Specification Required
review. Withdrawal is terminal: the token stays bound, no definition is ever
assigned or reassigned to it, and the value is not reused.

# Privacy Considerations {#privacy}

A digest over deterministically encoded content is a stable function of
that content, making the payload linkable across contexts where it recurs.
When the structured value is drawn from a low-entropy value space, applying
the captured encoding to a candidate value and hashing the result with 258
can recover the value by comparison to the payload -- a risk that already
exists wherever {{RFC9995}} is used; capturing the encoding removes
ambiguity that might have slowed such an attempt.

# IANA Considerations {#iana}

## COSE Header Parameters {#iana-header}

IANA is requested to register the following entry in the "COSE Header
Parameters" registry, in the "Integer values from 256 to 65535" range,
under the Specification Required policy ({{RFC8126}} Section 4.6) that
governs that range:

| Name | Label | Value Type | Value Registry | Description | Reference |
| --- | --- | --- | --- | --- | --- |
| payload-preimage-encoding | TBD\_1 (requested) | int | COSE Preimage Encodings ({{iana-encodings}}) | Deterministic encoding applied to create the preimage of a Hash Envelope payload | This document |

The suggested value is 271, the lowest unassigned integer in the COSE
Header Parameters registry as of 2026-09-22.

## COSE Preimage Encodings Registry {#iana-encodings}

IANA is requested to create a new registry, "COSE Preimage Encodings".
A registry, rather than a fixed reference, is used because more than one
deterministic encoding of structured content is expected to be registered
for Hash Envelope use over time -- for example, the CBOR Common
Deterministic Encoding {{I-D.ietf-cbor-cde}}, in progress in the CBOR
Working Group and distinct from the core requirements RFC 8949 Section 4.2.1
defines, is an anticipated future registration -- and Specification Required
keeps each addition reviewed and immutable.
Registration policy: Specification Required ({{RFC8126}} Section 4.6), with
Designated Expert review. Registration template: Value, Name, Description,
Applicable Content Types, Reference. Applicable Content Types lists media
types and structured syntax suffixes, which are matched against
preimage-content-type (259) as {{consistency}} specifies. Initial contents:

| Value | Name | Description | Applicable Content Types | Reference |
| --- | --- | --- | --- | --- |
| 1 | core-deterministic | CBOR deterministic encoding per the core deterministic encoding requirements of RFC 8949 Section 4.2.1 | application/cbor, application/cbor-seq, application/cose, application/cose-key, application/cose-key-set, application/cose-x509, application/cwt; media types with the +cbor, +cbor-seq, +cose, or +cwt structured syntax suffix | {{RFC8949}} Section 4.2.1 |

Value 1, core-deterministic, is the lead entry: the Core Deterministic
Encoding Requirements of {{RFC8949}} Section 4.2.1, part of STD 94.
It fixes the encoding of a given CBOR data item; the application-level
choices that {{RFC8949}} Section 4.2.2 leaves open are not part of it
({{security-bytes}}).
For a CBOR sequence {{RFC8742}}, each data item in the sequence is encoded
according to these requirements.
The registry is open under the policy above, so encodings for other
structured content types can be added by later registrations, each citing
its own reference.

--- back
