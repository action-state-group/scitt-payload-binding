# Governance

## Change controller today, and at RFC publication

CPB (posted revision -05) asks IANA for **one** new registry, the
Canonicalization Algorithm Registry, under Specification Required
([RFC 8126 §4.6](https://www.rfc-editor.org/rfc/rfc8126#section-4.6)) with a
Designated Expert for each registration. It also asks for one `cpb-refs`
entry in the existing COSE Header Parameters registry. **CPB creates no
artifact-type registry.** Artifact types and their digest contexts are owned
by the profiles that define them.

**IANA is the registry maintainer.** Before RFC publication, the names in the
draft are draft-local, and its table is only the requested initial contents.
This repository keeps a working record and history, not an interim registry
of record.

**What the editors undertake about identifier stability.** The IANA
Considerations section will ask that each canonicalization-algorithm token in
its initial contents be established under the same name, with the same
semantics and status. The editors will not themselves rename or reassign one.
What an IANA registry contains at establishment is settled by IANA and by the
responsible working group, not by the authors of an individual
Internet-Draft. This is therefore an undertaking rather than a guarantee, and
building on a pre-IANA token carries that residual risk. Artifact-type names
are outside the undertaking; they belong to their profiles. The full
statement is the IANA-forwarding clause in
[`spec/cpb-registry-policy.md`](https://github.com/action-state-group/scitt-payload-binding/blob/main/spec/cpb-registry-policy.md),
which also explains why it is weaker than RFC 7120 early allocation rather
than a counterpart to it. That policy takes effect when its ratification pull
request merges with both co-authors' approval at the exact head SHA.

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

The registry policy makes a firm neutrality commitment: CPB is never
branded to any single registrant's product. Agent Action Capsule has the same
standing as every other profile: it owns its own artifact-type declaration,
in its own draft, as `machine-mandate`, `trace-trust-record` and `vto` own
theirs. Nothing in CPB's specification text, its registry, or this site
favors one registrant's vocabulary, commercial terms or governance over
another's. The policy takes effect when its ratification pull request merges
(see above).
