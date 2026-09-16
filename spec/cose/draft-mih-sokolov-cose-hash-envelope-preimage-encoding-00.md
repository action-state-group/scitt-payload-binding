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

The COSE Hash Envelope {{RFC9995}} defines header parameters that let a
COSE_Sign1 carry the hash of content held elsewhere: payload-hash-alg (258)
identifies the hash function, preimage-content-type (259) identifies the
content format of the hashed bytes, and payload-location (260) hints at
where to retrieve them. Together they let a verifier that has obtained the
original content recompute the hash and compare it to the payload.

That comparison depends on one more fact {{RFC9995}} does not carry: when
the hashed content is structured (for example, JSON or CBOR), more than one
deterministic serialization of the same value is commonly in use, and a
verifier that serializes differently than the producer did computes a
different hash from identical content. {{RFC9995}} identifies the hash
function and the hashed bytes' content type, not which serialization
produced them.

This document defines one new protected-header parameter,
payload-preimage-encoding, naming the deterministic encoding applied before
hashing, and a small IANA registry of encoding identifiers. It extends the
COSE Hash Envelope without changing {{RFC9995}} itself: the Hash Envelope
protected header already permits extension parameters (CDDL `* (int / tstr)
=> any`), so this document registers a new header parameter rather than
amending 9995's own CDDL.

One principal user of the COSE Hash Envelope is the SCITT Signed Statement
{{RFC9943}}, which uses it to bind a Signed Statement to structured content
held elsewhere; this document does not depend on SCITT, and the parameter it
defines applies to any use of the Hash Envelope or of a plain COSE_Sign1.

# Terminology {#terminology}

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
{{RFC2119}} {{RFC8174}} when, and only when, they appear in all capitals, as
shown here.

"COSE", "COSE_Sign1", and "protected header" are defined in {{RFC9052}};
"CDDL" in {{RFC8610}}; "preimage" in Section 2 of {{RFC9995}}. "Hash
Envelope" refers to the COSE_Sign1 construction of {{RFC9995}}, whose header
parameters 258 (payload-hash-alg), 259 (preimage-content-type), and 260
(payload-location) together describe a payload that is the hash of content
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

The following examples use Extended Diagnostic Notation ({{RFC8610}}
Appendix G), in the style of {{RFC9995}} Section 4.1; signature and key
material are illustrative and truncated. Full digests are given once in
text and truncated in the COSE structure for line width.

## CBOR Deterministic Encoding Example {#example-cbor}

The preimage is the CBOR map `{"artifact": "manifest.spdx.json", "size":
48210}`, encoded per the Core Deterministic Encoding Requirements of
{{RFC8949}} Section 4.2.1, which sorts map keys by the bytewise order of
their own encodings, here placing "size" before "artifact":

~~~
a26473697a6519bc52686172746966616374726d616e696665
73742e737064782e6a736f6e
~~~

Its SHA-256 digest,
`cdb4930eaa6a019d6e27b1e93f9def8d5ab2e40382254f32b328f4637a446586`, is the
COSE_Sign1 payload:

~~~
18([ # COSE_Sign1
  <<{
    / alg               / 1: -7, # ES256
    / hash algorithm    / 258: -16, # sha-256
    / preimage type     / 259: "application/cbor",
    / preimage encoding / 261: 1, # cbor-deterministic
  }>>
  / unprotected / {},
  / payload     / h'cdb4930e...4637a446586', # digest above
  / signature   / h'304502210...3b1c9f0e'
])
~~~

## JCS Example {#example-jcs}

The preimage is the JSON value `{"z": null, "a": {}, "m": [], "s": "CPB"}`,
canonicalized per the JSON Canonicalization Scheme {{RFC8785}}, which sorts
object member names and retains null, empty-array, and empty-object
members; the canonical UTF-8 octet string is:

~~~
{"a":{},"m":[],"s":"CPB","z":null}
~~~

Its SHA-256 digest,
`7b3ef8ebf31ee38952860dd3f30c2e0d101dcdbcd9972e3ed8108ef9cff0d7cb`, is the
COSE_Sign1 payload:

~~~
18([ # COSE_Sign1
  <<{
    / alg               / 1: -7, # ES256
    / hash algorithm    / 258: -16, # sha-256
    / preimage type     / 259: "application/json",
    / preimage encoding / 261: 2, # jcs
  }>>
  / unprotected / {},
  / payload     / h'7b3ef8eb...9cff0d7cb', # digest above
  / signature   / h'3fa1c8e02...9d47b6a5'
])
~~~

# Security Considerations {#security}

## Preimages Are Bytes, Not Renderings {#security-bytes}

The preimage identified by preimage-content-type (259) and encoded per
payload-preimage-encoding (261) is the exact octet string the named
encoding produces -- not a rendered form, a console printout, or a string
that differs from the encoding's output by whitespace, trailing newlines, or
character-encoding choices.

A producer that stores structured content and later re-reads it before
hashing MUST ensure the octets entering the hash function are
byte-identical to the encoding's own output, not whatever a
deserialize-then-reserialize round trip happens to produce; the two are not
guaranteed equal even for encodings designed to be deterministic
({{iana-encodings}}). Diagnosing a mismatch requires comparing octets, not
visual representations of the content.

## Encoding Agility {#security-agility}

The COSE Preimage Encodings registry ({{iana-encodings}}) grows by
registering a new value for a new or differently scoped encoding, never by
reinterpreting the octets an existing value already governs. An entry's
definition, once registered, is immutable, so that an implementation
holding an old definition and one holding a new one either agree on what a
value means or one recognizes it as unregistered -- never that they
silently disagree on what the same value means.

# Privacy Considerations {#privacy}

A digest computed by Hash Envelope Mode over deterministically encoded
content is a stable function of that content, which makes the payload
linkable across contexts in which it recurs. When the preimage is drawn
from a small enumeration or another low-entropy value space, a party who
suspects a candidate preimage can encode it with 261, hash it with 258, and
compare the result to the payload, recovering the preimage without
obtaining it directly. Neither risk is introduced by 261 itself -- both
already exist wherever {{RFC9995}} is used -- but naming the encoding
removes any ambiguity that might otherwise have slowed such an attempt.

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
Section 4.2.1, Core Deterministic Encoding Requirements, part of STD 94. A
separate CBOR Common Deterministic Encoding effort is, at the time of
writing, an expired working-group Internet-Draft, not an RFC, and is not
registered here; a future RFC would receive its own registration, never a
reinterpretation of value 1.

Value 2, jcs, names {{RFC8785}}, cited informatively: an Independent
Submission that this document does not require any implementation to
support. It is registered because JCS preimages are already in deployed
use; Standards Track encodings such as value 1 remain this registry's
primary contents.

--- back

# Acknowledgments {#acknowledgments}
{:numbered="false"}

Amaury Chamayou and Henk Birkholz reviewed this document's approach -- a
COSE header-parameter extension separated from the Signed Statement
profile it was drawn from -- and gave comments that shaped it. Confirmed
acknowledgment text will be finalized before submission.
