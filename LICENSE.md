# License

This repository holds Internet-Drafts **and** a reference implementation, so it
carries three terms. Which one applies depends on the file.

## The Internet-Drafts

The Internet-Drafts in `spec/` — `draft-mih-sokolov-scitt-payload-binding` and
`spec/cose/draft-mih-sokolov-cose-det-encodings` — are contributions to the
IETF. They are subject to the IETF Trust Legal Provisions (BCP 78) and the IETF
IPR rules (BCP 79), and are licensed under the IETF Trust's `trust200902` terms.
See <https://trustee.ietf.org/> for details. IPR disclosures, if any, are filed
with the submission.

Authorship of a draft is an IETF matter held under BCP 78 and BCP 79. It is
neither conferred nor removed by this file, nor by `MAINTAINERS.md`.

## The reference implementation, conformance vectors and tooling

`lib/`, `vectors/`, `registry/`, `site/` and the scripts under `.github/` are
licensed under the **BSD 3-Clause License** (below), matching the other
Internet-Draft repositories in this family — `agent-action-capsule` and
`checkpointed-local-log`.

BSD 3-Clause is deliberate for the vectors: a conformance vector is only useful
if any implementer can copy it into their own test suite without a licence
question, including implementers who are not us.

```
BSD 3-Clause License

Copyright (c) 2026 Action State Group, Inc. and the Canonical Payload Binding
contributors.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

## Everything else

All remaining content — `README.md`, `REGISTRY.md`, `GOVERNANCE.md`,
`MAINTAINERS.md`, `RELEASING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`,
`docs/` and `CONTRIBUTING.md` — is licensed under Creative Commons Attribution
4.0 International (CC-BY-4.0): <https://creativecommons.org/licenses/by/4.0/>.
This matches `agent-accountability-composition`.
