# Vector suite

Every construction registered in CPB's two registries is backed by
conformance vectors — not prose claims about behavior, but inputs with
pinned expected outputs (and, for every requirement, MUST-FAIL
counterparts) that are mechanically executed in CI on every change. This is
what "vector-backed" means throughout CPB: the suite must be able to fail,
or a passing run proves nothing.

## Run it yourself

```sh
git clone https://github.com/action-state-group/scitt-payload-binding
cd scitt-payload-binding

# Validate every pinned vector (no dependencies beyond Python stdlib):
python3 .github/check_vectors.py vectors/

# Full harness — cross-language conformance in both directions:
python3 vectors/harness.py verify-impl "<your-implementation-command>" vectors/
```

See [`vectors/README.md`](https://github.com/action-state-group/scitt-payload-binding/blob/main/vectors/README.md)
in the source repository for the full suite layout, and
[`vectors/CANONICALIZATION_DECLARATION.md`](https://github.com/action-state-group/scitt-payload-binding/blob/main/vectors/CANONICALIZATION_DECLARATION.md)
for the versioned declaration of every transform and domain the suite
covers.

## What's checked, mechanically

- **Known-Answer Tests** for every registered canonicalization algorithm.
- **Derived-identifier construction** — the digest-context field set,
  exclusion set, and representation, executed against real inputs.
- **Typed-reference verification** — both PASS and MUST-FAIL cases.
- **Two-sidedness** — every registered name is checked for both a positive
  case and a MUST-FAIL case; a one-direction-only submission is flagged,
  not silently admitted.
- **Mutation testing** on the checker itself — a check that cannot be
  observed to fail is not evidence, so every negative-case check family
  carries a condition-removed mutant that must flip the result.

## For registrants

If you're filing a new entry, `make validate-entry DIR=path/to/your/vectors`
runs the identical mechanical checks and coverage report CI runs, entirely
against your own fork, before you open a PR. See
[`registry/README.md`](https://github.com/action-state-group/scitt-payload-binding/blob/main/registry/README.md)
for the full registration path.
