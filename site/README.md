# CPB public site content — scaffold, not deployed

This directory is static content for a **separate, dedicated CPB site**
(`canonicalpayloadbinding.org` — domain registration pending Steven; ruled
2026-09-02) — **not** for `agentactioncapsule.org`. Hosting CPB's public
registry index under AAC's domain would confirm the "CPB is an AAC annex"
misreading already circulating, which is exactly backwards: CPB is the
neutral, cross-organization substrate; Agent Action Capsule is one
registrant among several (alongside VTO, TRACE, and others), not the
registry's owner.

**Nothing here is deployed by this change.** These are the files to publish
once the domain lands — spec-first and minimal by design, matching the plan:
a Datatracker link, the Home-1 registry tables, the vector suite, an
implementations/registrants list, both co-authors, and one governance line.
No build step, no framework, no analytics, no styling beyond what plain
Markdown gives a static-site renderer for free.

## Files

| File | Purpose |
|---|---|
| [`index.md`](index.md) | Home page — what CPB is, and links to everything below. |
| [`registry.md`](registry.md) | Home-1: the live + provisional registry tables. **Generated** — see below. |
| [`vectors.md`](vectors.md) | The conformance vector suite as public evidence, with links into `vectors/`. |
| [`implementations.md`](implementations.md) | Registrants and implementations. **Non-AAC entries are listed first** — see ordering note in that file. |
| [`governance.md`](governance.md) | Change controller, donation-by-design intent, and the in-progress operational policy. |
| [`generate.py`](generate.py) | Regenerates `registry.md` from `registry.json` and `registry/entries/*.yaml` — the source of truth, not hand-copied prose. |

## Regenerating `registry.md`

```sh
python3 site/generate.py
```

Run this after any change to `registry.json` or `registry/entries/*.yaml` and
commit the result together, the same discipline `gen_registry.py` already
uses for `REGISTRY.md` → `registry.json`. `registry.md` is derived output;
hand-editing it will be overwritten the next time this runs.

## What "built on CPB" means for `agentactioncapsule.org`

Per the ruling, `agentactioncapsule.org` gains only a `built on CPB →`
dependency link **pointing down** to this future site — the reverse
direction of what a casual reader might expect from "AAC came first
historically." Actually implementing that link is a change to the
`agentactioncapsule-site` repository, out of scope for this repo and this
task; noted here so the pointer isn't lost.
