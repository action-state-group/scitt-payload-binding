<!-- SPDX-License-Identifier: Apache-2.0 -->
# Releasing a revision

This repository's output is not a merged pull request. It is a revision of
`draft-mih-sokolov-scitt-payload-binding` posted to the IETF datatracker.
Everything else is work in progress.

## The freeze rule

**A revision's files are frozen the moment that revision is posted.** Once
`-NN` exists on the datatracker it is immutable there, so continuing to edit
`spec/draft-...-NN.md` silently accumulates changes under a number that is
already taken, and the repository stops being able to say what any published
number contains.

After posting `-NN`, the first edit that follows opens `-NN+1`.

> **Current divergence — read before cutting the next revision.** `-01` was
> posted on 2026-07-27 (1512 lines). The in-tree `-01` has since grown to 2184
> lines: **+672 lines, +44 %**, adding `3.2 Algorithm cde-n (Withdrawn)`,
> `3.3 Algorithm as-transmitted`, `13.2.1 agent-action-capsule` and
> `13.2.2 machine-mandate`. None of that is visible to anyone reading the
> published draft. Those changes belong to `-02`.

## Cutting a revision

1. `git mv` the three `spec/draft-...-NN.{md,txt,xml}` files to `-NN+1`, update
   the `docname` in the front matter, and set `DRAFT` in `spec/Makefile`. The
   `spec` workflow reads `DRAFT` from the Makefile, so that one edit moves the
   gate with it.
2. Do this when **no pull requests are open**. Every open branch touching
   `spec/` will conflict otherwise, and the conflict lands in generated files
   where it is most tedious to resolve.
3. Audit references to the old number. Not all of them should move: a citation
   to what `-01` *published* stays `-01`, while a citation to the current text
   becomes `-02`. As of 2026-08-20 there are 33 such references outside
   `spec/` — in `vectors/`, `lib/` and the tests — and they are not
   mechanically interchangeable.

## Pre-submission checklist

```bash
cd spec
make refresh-refs      # re-fetch bibliography; a superseded I-D reference must not ride along
make rebuild           # force a full rebuild -- never trust mtime after a merge or checkout
make idnits            # nit check
cd .. && python3 .github/gen_registry.py --check   # registry.json current with REGISTRY.md
```

Then confirm, by reading the built `.txt` rather than by trusting the build log:

- every change intended for this revision is present in the rendered output;
- the registry sections match `REGISTRY.md`;
- no entry cites a status outside the vocabulary in `REGISTRY.md`.

Submit at <https://datatracker.ietf.org/submit/>. Either author may post.
Check the cut-off calendar first: submissions close before each IETF meeting
(for IETF 127, San Francisco, 2026-11-14, the cut-off is **2026-11-02 23:59 UTC**).

## Why the reference cache is committed

`spec/.refcache/` is tracked. An uncached build fetches one file per external
reference from `bib.ietf.org`, so an outage there fails the `spec` gate on every
open pull request at once, for reasons that have nothing to do with any of them.
Committing the cache makes builds hermetic and reproducible; `make refresh-refs`
is the only thing that should change it.
