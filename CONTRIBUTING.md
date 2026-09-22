# Contributing to scitt-payload-binding

This repository hosts an **open specification** — the IETF Internet-Draft
`draft-mih-sokolov-scitt-payload-binding` — together with a reference library
and conformance vectors. Contributions are welcome.

## The specification is an IETF contribution (BCP 78 / BCP 79)

The draft is intended for discussion in the IETF — the working group is to be
determined — and for eventual contribution to an appropriate standards body as
the ecosystem matures.

By proposing a change to the specification text (anything under `spec/`), you
agree that your contribution is made under, and is governed by:

- **BCP 78** — Rights Contributors Provide to the IETF Trust, and
- **BCP 79** — Intellectual Property Rights in IETF Technology
  (including the IPR disclosure obligations therein).

Substantive technical discussion belongs on the relevant IETF mailing list and
in the IETF process, not only in GitHub issues; this repository is the editor's
source, not the venue of record. The authoritative version of the draft is the
one on the IETF Datatracker.

## Code and conformance contributions (Revised BSD)

Contributions to the reference library (`lib/`), build tooling (`spec/Makefile`,
scripts), and test vectors (`vectors/`) are licensed under the **Revised BSD
License** (BSD-3-Clause; see LICENSE).

### Developer Certificate of Origin (DCO)

This project uses the [Developer Certificate of Origin 1.1](https://developercertificate.org/).
Sign off every commit:

```bash
git commit -s -m "your message"
```

No CLA is required — the DCO is the whole agreement.

## Scope discipline (review gates, not preferences)

1. **Standard-only.** This repository carries the open specification, its
   reference library, and conformance vectors — nothing product-specific,
   tenant-specific, or internal. PRs that import application/product internals
   will be declined.
2. **Standards honesty.** The SCITT and COSE documents this draft builds on are,
   where still Internet-Drafts, not published RFCs; never cite an unassigned RFC
   number. This draft's own status is an individual I-D, not a WG document —
   don't claim WG adoption it does not have.
3. **Conformance is external.** Correctness claims rest on agreement with
   independent references and on the frozen conformance vectors under
   `vectors/`. A wire-facing change comes with cross-checked evidence and
   negative (MUST-reject) tests, not just round-trip tests.
4. **The draft is the source of truth.** When the reference library and the
   draft disagree, fix the library or open an erratum against the draft — never
   let the two silently diverge.

## Building the draft

See `spec/Makefile` and the README. The committed `.xml` must be RFCXML v3
(RFC 7991); the build converts kramdown-rfc's v2 output with `xml2rfc --v2v3`.

## Security

Please report suspected vulnerabilities privately — see SECURITY.md. Do not open
a public issue for a suspected vulnerability.
