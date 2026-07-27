# CPB Reference Library

Spec-pure Python reference library for **Canonical Payload Binding**
(`draft-mih-sokolov-scitt-payload-binding-00`).

Implements three CPB mechanisms with no payload-profile semantics:

| Module | Spec section | What it implements |
|---|---|---|
| `cpb.canonicalize` | §3.1 | Algorithm `jcs-n`: normalize → JCS → SHA-256 → lowercase hex |
| `cpb.derive_id` | §4 | Derived identifier: `CANONICAL-DIGEST(A, payload minus exclusion_set)` |
| `cpb.typed_ref` | §6 | Typed digest reference: construction and verification |

## Install

```
pip install -e ".[dev]"   # from this directory
```

## Quick start

```python
from cpb import derive_id, make_typed_ref, verify_typed_ref, ArtifactTypeRegistryEntry

# Derived identifier (§4)
payload = {
    "station_id": "WS-42",
    "timestamp": "2026-07-24T00:00:00Z",
    "celsius": "21.3",
    "record_id": None,
}
record_id = derive_id(payload, exclusion_set={"record_id"})
# → "1009a072df7fc0bfc6fcf49ca2f194067f6c0136c871a88d4fbd66a13361c1d1"

# Typed reference (§6)
auth_doc_entry = ArtifactTypeRegistryEntry(
    name="authorization-doc",
    exclusion_set=frozenset(["doc_id"]),
)
auth_doc = {
    "doc_id": None,
    "subject": "WS-42",
    "scope": "temperature-write",
    "issued_at": "2026-07-24T00:00:00Z",
}
ref = make_typed_ref(auth_doc, auth_doc_entry)
# ref.digest → "0c837d01faa4106c63367f199af9bfa729d1917f36dc91f9dfeb6de6ec7c6bdb"

# Verify the reference
verify_typed_ref(ref, auth_doc, auth_doc_entry)  # raises on mismatch
```

## Test suite

Tests are driven by the conformance vector suite in `../vectors/`:

```
pytest
```

All PASS vectors must produce the expected digest; all MUST-FAIL vectors must
raise the appropriate exception. The test suite is the vector suite itself.
