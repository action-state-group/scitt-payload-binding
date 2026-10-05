# Canonicalization Declaration for SCITT Signed Statements (CPB)

Home of the Internet-Draft **`draft-mih-sokolov-scitt-payload-binding`** —
*Canonicalization Declaration for SCITT Signed Statements* — together with its
reference library, conformance vectors, registry material, and a second,
related Internet-Draft. CPB is the document's working short name (it was
formerly titled "Canonical Payload Binding"); the draft name and short name
are unchanged until an adopting working group settles them.

Both documents are individual Internet-Drafts. Neither is a Working Group
document.

## The specification

| Revision | State | Files |
|---|---|---|
| **-05** | Latest posted revision (Datatracker, 2026-09-13) | [`.txt`](spec/draft-mih-sokolov-scitt-payload-binding-05.txt) · [`.xml`](spec/draft-mih-sokolov-scitt-payload-binding-05.xml) · [`.md`](spec/draft-mih-sokolov-scitt-payload-binding-05.md) |
| **-06** | Working revision in this tree, not posted. Changes the Acknowledgments only; no normative change (see its "Changes from -05" section) | [`.txt`](spec/draft-mih-sokolov-scitt-payload-binding-06.txt) · [`.xml`](spec/draft-mih-sokolov-scitt-payload-binding-06.xml) · [`.md`](spec/draft-mih-sokolov-scitt-payload-binding-06.md) |

- Datatracker: [datatracker.ietf.org/doc/draft-mih-sokolov-scitt-payload-binding](https://datatracker.ietf.org/doc/draft-mih-sokolov-scitt-payload-binding/)
- Intended venue: the SCITT Working Group (`scitt@ietf.org`).
- Earlier revisions -00 through -05 are kept in [`spec/`](spec/). The posted
  -02 to -05 `.xml`/`.txt` files are the IETF archive bytes, restored for
  diffing; [`spec/README.md`](spec/README.md) records their provenance and
  hashes. The working revision is the one named by `DRAFT` in
  [`spec/Makefile`](spec/Makefile); it is the only revision the build and CI
  act on.

## What the draft defines

A SCITT Signed Statement often carries a digest in place of the content it
stands for. For structured content, that digest depends on how the content
was serialized before hashing. CPB specifies how a Signed Statement
**declares** the construction behind the digests it carries, so a verifier
never has to infer it. It does this with declarations, not with a payload
format. In -06:

1. **Canonicalization Algorithm Registrations.** A payload class declares
   exactly one registered canonicalization algorithm (and its exclusion set).
   The active registrations are `jcs` (plain RFC 8785 JCS, SHA-256, lowercase
   hex) and `as-transmitted` (no canonicalization; digest over octets fixed by
   a cited production of the container format). `jcs-n` and `cde-n` are
   withdrawn.
2. **The Derived Identifier.** A content-addressed identifier derived from
   the declared canonical form.
3. **Envelope Conventions.** A CPB Signed Statement uses exactly one of two
   modes: *Full-Content Mode* (the complete statement content is the COSE
   payload, as in RFC 9943) or *Hash Envelope Mode*, the RFC 9995 COSE Hash
   Envelope alternative, where the payload is the raw digest of content held
   elsewhere. The Hash Envelope's `payload-hash-alg` identifies only the hash
   function; it is never treated as a canonicalization identifier.
4. **Statement-to-Receipt Binding.** Per that section, a producer registers
   the Signed Statement with a SCITT Transparency Service and attaches "the
   returned Receipt to the unprotected header, forming a Transparent
   Statement." The profile is VDS-agnostic; a verifier reads the VDS
   identifier from the Receipt's protected header and never infers it. The
   "Leaf Construction" subsection requires the VDS or profile to declare
   whether a log leaf uses the raw digest octets or their hexadecimal text.
5. **Typed Digest References (Information Model).** An *abstract* typed
   digest reference with four members — `type`, `purpose`, `digest_alg`,
   `digest` — and verifier rules for selecting a digest context
   ("Cross-Profile Comparability"). The model fixes no serialization. A
   Signed Statement selects exactly one carrier ("Carriage Selection"):
   - **Envelope Carriage** — the ONE optional protected-header encoding CPB
     defines, the COSE header parameter `cpb-refs` (a closed, bounded CBOR
     array; "The parameter MUST NOT occur in the unprotected header"); or
   - **Payload Carriage** (informative) — a payload profile's own
     serialization inside the payload.

The draft requests one new IANA registry, the Canonicalization Algorithm
Registry (Specification Required), and one registration, `cpb-refs`, in the
existing COSE Header Parameters registry. It states that it "neither creates
nor depends on an artifact-type registry": artifact-type and digest-context
declarations are owned by payload or consuming profiles. IANA is the registry
maintainer once the document is published; before that, the draft's table is
only the requested initial contents.

The Agent Action Capsule profile is one payload profile that uses CPB; see
[action-state-group/agent-action-capsule](https://github.com/action-state-group/agent-action-capsule).

## Second Internet-Draft: `spec/cose/`

[`draft-mih-sokolov-cose-det-encodings-00`](spec/cose/draft-mih-sokolov-cose-det-encodings-00.md)
([`.txt`](spec/cose/draft-mih-sokolov-cose-det-encodings-00.txt),
[`.xml`](spec/cose/draft-mih-sokolov-cose-det-encodings-00.xml)) —
*The COSE payload-preimage-encoding Header Parameter*, intended for the COSE
Working Group: a protected-header parameter naming the deterministic encoding
applied before hashing a COSE Hash Envelope payload, plus a small registry of
deterministic encoding identifiers. **Not yet posted**: the Datatracker has no
record of this draft name (checked 2026-10-04). Built from
[`spec/cose/Makefile`](spec/cose/Makefile).

## Reference library and `cpb-check`

[`lib/`](lib/) holds the Python reference library (`lib/cpb/`); see
[`lib/README.md`](lib/README.md). It installs a conformance checker,
`cpb-check`, for the P/R grammar rules:

```sh
pip install ./lib                      # install from repo root
cpb-check record.json                  # human-readable verdict + path
cpb-check record.json --json           # machine-readable JSON
echo $?                                # 0 grammar-conforming · 1 non-conforming · 2 error
cpb-check --self-test                  # run the packaged vector suite
```

Phase 1 covers the P normal-form walk and R wire-layer checks (number-token
form, duplicate-key rejection). Digest recomputation and `canonicalization_id`
resolution are Phase 2. A successful result is `conforming`, not `verified`:
the command does not resolve a digest context, retrieve a cited artifact, or
recompute and compare a digest. Its duplicate-preserving raw-bytes lexer
reports duplicate keys at their exact JSON path, before `json.loads` could
collapse them. `--self-test` exits non-zero if no vector was checked or if
either expected verdict went unexercised. The packaged copy of the checker
vectors is [`lib/cpb/_vectors/cpb-check/`](lib/cpb/_vectors/cpb-check/).

## Conformance vectors: `vectors/`

The suite is spec-derived and payload-neutral; full layout, vector format and
per-vector tables are in [`vectors/README.md`](vectors/README.md).
Implementations MUST pass every vector not marked `must_fail: true` and MUST
reject every vector marked `must_fail: true`.

| Directory | What it tests |
|---|---|
| [`jcs/`](vectors/jcs/) | Active `jcs` algorithm — two-sided PASS / MUST-FAIL pair |
| [`as-transmitted/`](vectors/as-transmitted/) | Active `as-transmitted` algorithm — exact named-production byte selection vs. hex-text substitution |
| [`subject-binding-diff/`](vectors/subject-binding-diff/) | Discriminating pairs: plain `jcs` vs. withdrawn `jcs-n` |
| [`jcs-n/`](vectors/jcs-n/) | Historical record for withdrawn `jcs-n`: `kats/`, `derived-id/`, `assembled-preimage/` |
| [`typed-refs/`](vectors/typed-refs/) | Typed digest reference verification, PASS and MUST-FAIL, including `cpb-refs` envelope carriage and RFC 9995 Hash Envelope cases |
| [`representation-contrast/`](vectors/representation-contrast/) | Raw 32-octet digest vs. its 64-character text |
| [`profile-independence/`](vectors/profile-independence/) | Citing another profile by typed reference only |
| [`domain-transforms/`](vectors/domain-transforms/) | Stream reassembly before digesting; truncated stream MUST fail |
| [`multimodal/`](vectors/multimodal/) | Binary content carried as a base64 string |
| [`registry/`](vectors/registry/) | Registry-snapshot lookup verdicts (unknown id, id unknown to a pinned snapshot), exercised by `lib/tests/test_registry.py` |
| [`cpb-check/`](vectors/cpb-check/) | Grammar-checker conforming / non-conforming records |

Also in `vectors/`: [`CANONICALIZATION_DECLARATION.md`](vectors/CANONICALIZATION_DECLARATION.md)
(declared transforms and domains), [`generate.py`](vectors/generate.py)
(validate pinned digests, `--mutate` byte-flip check) and
[`harness.py`](vectors/harness.py) (run an external implementation against
the suite with `verify-impl`, or expose the reference implementation with
`reference-impl`).

Checking tooling:

```sh
python3 .github/check_vectors.py vectors/          # standalone, stdlib-only checker
python3 .github/check_vectors.py --candidate DIR   # registrant pre-submission self-check
make validate-entry DIR=path/to/your/vectors       # same, via the root Makefile
python3 vectors/generate.py vectors/               # recompute pinned digests
```

[`.github/check_vectors.py`](.github/check_vectors.py) recomputes every pinned
value independently and requires every MUST-FAIL vector to match a declared
failure category, with mutation probes that must flip the result.

## Registry material: `registry/`, `registry.json`, `REGISTRY.md`

This repository holds repository-level registry material alongside the draft:

- [`REGISTRY.md`](REGISTRY.md) — repository registry history and working
  tables. It states its own status at the top: non-normative, not an
  alternative to IANA, and listing a type or digest context there does not
  register it or make it usable for verification.
- [`registry.json`](registry.json) — generated from `REGISTRY.md` by
  [`.github/gen_registry.py`](.github/gen_registry.py) (schema:
  [`.github/registry_schema.json`](.github/registry_schema.json)); a
  content-addressed snapshot carrying `snapshot_sha256`.
- [`registry/`](registry/) — a schema-validated filing format; see
  [`registry/README.md`](registry/README.md). It contains
  [`entry.schema.json`](registry/entry.schema.json), the filing template
  [`entries/TEMPLATE.yaml`](registry/entries/TEMPLATE.yaml), and these filed
  entries:

  | Entry | Rung / status (as filed) |
  |---|---|
  | [`agent-action-capsule.yaml`](registry/entries/agent-action-capsule.yaml) | owner_authored / owner-confirmed |
  | [`cll-checkpoint.yaml`](registry/entries/cll-checkpoint.yaml) | provisional / provisional |
  | [`mesh-inference-exchange.yaml`](registry/entries/mesh-inference-exchange.yaml) | provisional / provisional |
  | [`vto.yaml`](registry/entries/vto.yaml) | reserved / reserved |

- [`spec/cpb-provisional-registry.md`](spec/cpb-provisional-registry.md) and
  [`spec/cpb-registry-policy.md`](spec/cpb-registry-policy.md) — provisional
  filings and the registration policy draft referenced by `registry/README.md`.

**Filing an entry** (per `registry/README.md`): copy `TEMPLATE.yaml` to
`registry/entries/<name>.yaml` and answer its questions; optionally commit
vectors under `vectors/<name>/` and point `fixtures.vectors_dir` at them; open
a pull request. Green CI means a schema-valid, mechanically checked filing; it
does not replace Designated Expert or human review.

CI workflows for this material:

- [`registry-entries.yml`](.github/workflows/registry-entries.yml) — runs
  [`.github/validate_registry_entries.py`](.github/validate_registry_entries.py)
  on `registry/entries` (schema validation, plus `check_vectors.py` on any
  declared vector directory) and its tests.
- [`registry.yml`](.github/workflows/registry.yml) — `gen_registry.py --check`
  keeps `registry.json` in sync with `REGISTRY.md`, plus its tests.
- [`candidate-validate.yml`](.github/workflows/candidate-validate.yml) — runs
  `check_vectors.py --candidate` on pull requests touching `vectors/`.

## Static site: `site/`

[`site/`](site/) holds Markdown pages for a standalone project site —
`index.md`, `registry.md`, `vectors.md`, `implementations.md`,
`governance.md` — and two scripts (see [`site/README.md`](site/README.md);
not deployed):

```sh
python3 site/generate.py           # regenerate site/registry.md from registry.json + registry/entries/*.yaml
python3 site/generate.py --check   # exit 1 if site/registry.md is stale
pip install markdown
python3 site/build.py              # render the pages to site/dist/*.html (git-ignored)
python3 site/build.py --serve      # build, then serve site/dist on :8000
```

## Audits: `docs/audits/`

- [`docs/audits/jcsn-withdrawal-audit-2026-08-18.md`](docs/audits/jcsn-withdrawal-audit-2026-08-18.md)
  — the inspectable record behind the `jcs-n` withdrawal.

## Other CI

[`spec.yml`](.github/workflows/spec.yml) rebuilds the working draft and diffs
it against the tracked `.xml`/`.txt`;
[`vectors.yml`](.github/workflows/vectors.yml) and
[`python.yml`](.github/workflows/python.yml) run the vector checker and the
library tests; [`leak-lint.yml`](.github/workflows/leak-lint.yml),
[`neutrality.yml`](.github/workflows/neutrality.yml) and
[`dco.yml`](.github/workflows/dco.yml) enforce public-repository hygiene and
DCO sign-off.

## Governance, review and contributing

- [`GOVERNANCE.md`](GOVERNANCE.md) — how the project is run; it governs both
  Internet-Drafts. In short: editorial, example, vector, tooling, CI and
  registry-housekeeping changes land without waiting; normative changes need
  an issue and a 14-day comment window; any Datatracker submission needs every
  author's agreement.
- [`MAINTAINERS.md`](MAINTAINERS.md) — repository maintainers and
  Internet-Draft authors.
- [`CONTRIBUTING.md`](CONTRIBUTING.md), [`SECURITY.md`](SECURITY.md),
  [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md), [`RELEASING.md`](RELEASING.md).

Review happens in the issue tracker. Issues and pull requests are labeled
`cpb` (the specification) and `cpb-registry` (registry material and proposed
canonicalization-algorithm registration work).

---

_The `-00` as posted references its original source repository; the `-01`
revision updates that pointer to this repository._
