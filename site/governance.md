# Governance

## Change controller today, and at RFC publication

CPB's two registries (Payload Canonicalization Algorithm Registry, Artifact
Type Registry) are interim: **Action State Group, Inc.** is the change
controller today, hosted in this GitHub repository. Registration follows
Specification Required ([RFC 8126 §4.6](https://www.rfc-editor.org/rfc/rfc8126#section-4.6)),
with Designated Expert review for each entry.

On IETF working-group adoption of the specification, the registry moves with
the document to a repository of the working group's choosing. **At RFC
publication, change control transfers to IANA**, and the registries this
repository maintains become the normative IANA registries CPB's IANA
Considerations section establishes.

**Identifiers are stable across that transfer.** An identifier registered
here — live or provisional — carries forward under the same name and the
same registered semantics when IANA takes over; the transfer is not a
re-adjudication. See the IANA-forwarding clause in
[`spec/cpb-registry-policy.md`](https://github.com/action-state-group/scitt-payload-binding/blob/main/spec/cpb-registry-policy.md)
for the full statement and its citation of RFC 7120 early allocation as the
analog. **That policy document is currently a DRAFT, held pending sign-off
from both co-authors** — it is not yet ratified, and this page will be
updated once it is.

## Designated Expert review

Every entry that reaches the live registry tables passes Designated Expert
review — not a rubber stamp on green CI, but human judgment on evidence CI
cannot evaluate: whether a cited discriminating vector actually
distinguishes this construction from its neighbours, whether a named
consuming profile is a real normative use, and whether the registrant's
relationship to the construction they're registering is disclosed. See
`REGISTRY.md`'s Designated Expert Admission Checklist in the source
repository for the exact gates.

## Donation-by-design

The stated intent for the CPB document family — this specification, the
neutral reference libraries, and the registries they define — is to donate
the repositories, the naming, and the reference verification services to a
neutral foundation rather than have them remain permanently controlled by
any single company. This registry is built to be handed off, not held onto:
every entry's provenance, every conformance vector, and every registration
decision is recorded in public, versioned, plain-text form for exactly that
reason.

## Neutrality

CPB is not, and will never be, branded to any single registrant's product.
Agent Action Capsule is one registered artifact type among peers — the same
standing as `machine-mandate`, `mesh-inference-exchange`, `cll-checkpoint`,
or a future `vto` and `trace-trust-record` entry. Nothing in CPB's
specification text, registries, or this site favors one registrant's
vocabulary, commercial terms, or governance over another's.
