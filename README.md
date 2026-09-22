# Canonical Payload Binding (CPB)

Dedicated home for **`draft-mih-sokolov-scitt-payload-binding`** — the Canonical
Payload Binding profile — and its implementation and interoperability material.

## What CPB is

Independently written systems that anchor records to a [SCITT](https://datatracker.ietf.org/wg/scitt/about/)
Transparency Service keep re-deriving the same construction. CPB extracts those
**four moves** into a single reusable, **payload-neutral** profile:

1. **Canonicalize** — a payload class declares exactly one canonicalization
   algorithm and its exclusion set.
2. **Derive an identifier** — a content-addressed identifier is derived from the
   canonical form.
3. **Bind a receipt** — the SCITT receipt is carried in the unprotected header of
   the Signed Statement, bound to the statement.
4. **Cite externals** — a typed reference mechanism lets one record cite another
   by digest across profile boundaries.

A payload class declares its canonicalization algorithm and exclusion set **once**
and inherits the derived-identifier, statement-to-receipt binding, and typed
digest reference semantics without restating the mechanics in every profile.

## The specification

- [`spec/draft-mih-sokolov-scitt-payload-binding-03.txt`](spec/draft-mih-sokolov-scitt-payload-binding-03.txt)
  — the current revision (`.md` source and rendered `.xml` alongside; earlier
  revisions are retained in `spec/`).
- Datatracker: [datatracker.ietf.org/doc/draft-mih-sokolov-scitt-payload-binding](https://datatracker.ietf.org/doc/draft-mih-sokolov-scitt-payload-binding/)
- Intended venue: the SCITT Working Group (`scitt@ietf.org`). This is an
  individual submission; the short name and title are expected to be settled by
  the adopting working group.

## First payload profile

The **Agent Action Capsule** was the first payload profile to use the CPB
construction. See **[action-state-group/agent-action-capsule](https://github.com/action-state-group/agent-action-capsule)**
for that profile, its profile-owned artifact and digest-context declarations,
its interop record, and reference material.

## `cpb-check` — conformance checker

Check any CPB record against the P/R grammar rules from the command line.

```sh
pip install ./lib                      # install from repo root
cpb-check record.json                  # human-readable verdict + path
cpb-check record.json --json           # machine-readable JSON
echo $?                                # 0 grammar-conforming · 1 non-conforming · 2 error
cpb-check --self-test                  # run the built-in vector suite
```

**Phase 1** (this release): P normal-form walk and R wire-layer checks
(number-token form, duplicate-key rejection).  Digest recomputation and
`canonicalization_id` resolution (verdicts `digest-mismatch` / `unknown-id`)
are Phase 2, held for G1 (the emitter shipping the id field).

The duplicate-preserving raw-bytes lexer is the most security-relevant
component: `json.loads` silently collapses duplicate keys before any rule
sees them; `cpb-check` reports them at their exact JSON path. A successful
Phase 1 result is `conforming`, not `verified`: this command does not resolve a
digest context, retrieve a cited artifact, recompute its digest, or compare it
with a carried value.

## Reference implementation and conformance vectors

The reference library is in `lib/cpb/`. Conformance vectors live in
`vectors/`: start with `jcs/` for the registered `jcs` construction and with
`subject-binding-diff/` for its discriminating pairs against the withdrawn
`jcs-n` construction. The broader `jcs-n/kats/` suite is retained as the
historical record for that withdrawn construction; `cpb-check/` covers the
grammar checker. Run `cpb-check --self-test` to execute the grammar-checker
suite.

## Registries

CPB-03 requests one new IANA **Canonicalization Algorithm Registry**, under a
Specification Required policy, and registration of `cpb-refs` in the existing
COSE Header Parameters registry. The proposed initial algorithm contents are in
the draft; IANA becomes the registry authority if the document is published.

CPB-03 does **not** define or depend on a universal artifact-type registry.
Artifact-type and digest-context declarations are owned by payload or consuming
profiles and are accepted only through stable normative references selected by
those profiles.

[`REGISTRY.md`](REGISTRY.md) and
[`spec/cpb-provisional-registry.md`](spec/cpb-provisional-registry.md) preserve
earlier repository experiments and provenance. They are non-normative for
CPB-03, are not an alternative registry authority, and do not make an artifact
type or digest context valid merely by listing it.

## Cross-cutting facilities and companion documents

Facilities that are common across payload classes (see the draft's
**Extensibility and Cross-Cutting Facilities** section, §10) are defined by
**companion documents** rather than restated per profile.

## Review and contributing

Review happens **in the issue tracker**. See the pinned **"CPB -00 review
thread."** Issues and pull requests are labeled:

- `cpb` — the specification.
- `cpb-registry` — historical repository registry material and proposed
  canonicalization-algorithm registration work.

---

_The `-00` as posted references its original source repository; the `-01`
revision updates that pointer to this repository._
