# Canonical Payload Binding (CPB)

CPB defines how to compute a stable, cross-language digest identifier over a
structured payload — a canonicalization algorithm plus a declared field set,
exclusion set, and representation — and how to carry that identifier as a
typed reference from a signed record. It is the binding layer beneath any
number of payload profiles; it does not define what those profiles mean.

CPB is specified in an IETF Internet-Draft and developed in the open. This
site is the public index for its two registries and their conformance
evidence — nothing here is specific to any one registrant's product.

**Specification:** `draft-mih-sokolov-scitt-payload-binding` —
[view on the IETF Datatracker](https://datatracker.ietf.org/doc/draft-mih-sokolov-scitt-payload-binding/).

**Source and registries:**
[`action-state-group/scitt-payload-binding`](https://github.com/action-state-group/scitt-payload-binding)
(this repository is the interim registry of record — see
[Governance](governance.md) for what happens to that at RFC publication).

## Co-authors

| Name | Affiliation |
|---|---|
| Steven Mih | Action State Group |
| Anton Sokolov | TalTech / Tyche Institute |

## On this site

- **[Registries](registry.md)** — the Payload Canonicalization Algorithm
  Registry and the Artifact Type Registry: what's live, what's provisional,
  and what's reserved.
- **[Vector suite](vectors.md)** — the conformance vectors every registered
  construction is checked against, and how to run them yourself.
- **[Implementations & registrants](implementations.md)** — who has
  registered a construction here, and what consumes it.
- **[Governance](governance.md)** — who controls this registry today, what
  changes at RFC publication, and the donation-by-design intent behind that.

## Registering a construction

Anyone can propose a canonicalization algorithm or artifact type. Start at
[`registry/README.md`](https://github.com/action-state-group/scitt-payload-binding/blob/main/registry/README.md)
in the source repository — fill in the template, and CI validates your
filing mechanically before a human ever has to read it by hand.
