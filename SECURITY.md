# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities **privately**:

- **GitHub:** use *Security → Report a vulnerability* on this repository
  (GitHub private vulnerability reporting), or
- **Email:** security@actionstate.ai with `[scitt-payload-binding security]` in
  the subject.

Please do not open a public issue for a suspected vulnerability. We aim to
acknowledge reports within 72 hours.

## Scope

- The reference library under `lib/`.
- The conformance vectors under `vectors/` (a vector that should fail
  verification but passes, or vice versa, is in scope).

A *cryptographic or verification bypass* — a declared canonicalization or
preimage encoding under which distinct content produces the same digest, or
under which a verifier accepts a content binding it should reject — is the
highest-priority class.

## Specification issues

Ambiguities, under-specifications, or honest-but-misleading prose about
standards status in the Internet-Draft are not security vulnerabilities — raise
those as public issues, or on the relevant IETF mailing list. This project
treats standards honesty as a correctness property.

## Supported versions

The latest revision of the draft and the latest released reference library
receive fixes.
