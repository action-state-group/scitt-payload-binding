# SPDX-License-Identifier: BSD-3-Clause
"""Strict carrier tests for the CPB protected-header representation."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from cpb import canonical_digest
from cpb.cose_refs import (
    CborMap,
    CborTag,
    CoseSign1,
    CpbRefsError,
    CpbRefsLocationError,
    DuplicateCborKeyError,
    MalformedCborError,
    cose_signature1_structure,
    decode_cose_sign1,
    encode_deterministic_cbor,
    extract_cpb_refs,
)
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

CPB_REFS = -65537  # Private Use for tests; the draft's IANA value is TBD.
VECTORS = Path(__file__).parents[2] / "vectors"


def _reference(*, purpose: str | None = "identifier") -> dict[int, object]:
    reference: dict[int, object] = {
        1: "application/example+json",
        3: "SHA-256",
        4: bytes.fromhex("11" * 32),
    }
    if purpose is not None:
        reference[2] = purpose
    return reference


def _sign1(
    *,
    refs: object | None = None,
    unprotected_refs: object | None = None,
    critical: bool = True,
) -> bytes:
    protected: dict[object, object] = {1: -8}
    if refs is not None:
        protected[CPB_REFS] = refs
        if critical:
            protected[2] = [CPB_REFS]
    unprotected: dict[object, object] = {}
    if unprotected_refs is not None:
        unprotected[CPB_REFS] = unprotected_refs
    return encode_deterministic_cbor(
        CborTag(
            18,
            [
                encode_deterministic_cbor(protected),
                unprotected,
                b'{"temperature":"21.5"}',
                b"\x22" * 64,
            ],
        )
    )


def test_extracts_closed_typed_reference_from_protected_header() -> None:
    encoded = _sign1(refs=[_reference()])
    refs = extract_cpb_refs(encoded, CPB_REFS, required=True, require_critical=True)

    assert len(refs) == 1
    assert refs[0].type == "application/example+json"
    assert refs[0].purpose == "identifier"
    assert refs[0].digest_alg == "SHA-256"
    assert refs[0].digest == bytes.fromhex("11" * 32)


def test_purpose_may_be_absent_but_not_null() -> None:
    encoded = _sign1(refs=[_reference(purpose=None)])
    assert extract_cpb_refs(encoded, CPB_REFS, required=True)[0].purpose is None

    malformed = _reference()
    malformed[2] = None
    with pytest.raises(CpbRefsError, match="purpose must be"):
        extract_cpb_refs(_sign1(refs=[malformed]), CPB_REFS, required=True)


def test_rejects_unprotected_or_noncritical_required_carriage() -> None:
    with pytest.raises(CpbRefsLocationError, match="unprotected"):
        extract_cpb_refs(
            _sign1(refs=[_reference()], unprotected_refs=[_reference()]),
            CPB_REFS,
            required=True,
        )

    with pytest.raises(CpbRefsError, match="listed in crit"):
        extract_cpb_refs(
            _sign1(refs=[_reference()], critical=False),
            CPB_REFS,
            required=True,
            require_critical=True,
        )


@pytest.mark.parametrize(
    "refs, message",
    [
        ([], "non-empty array"),
        ([{1: "type", 3: "SHA-256"}], "missing required"),
        ([{1: "type", 3: "SHA-256", 4: b"x", 5: "extension"}], "unknown"),
        ([[1, 2, 3, 4]], "CBOR map"),
    ],
)
def test_rejects_malformed_reference_shapes(refs: object, message: str) -> None:
    with pytest.raises(CpbRefsError, match=message):
        extract_cpb_refs(_sign1(refs=refs), CPB_REFS, required=True)


def test_rejects_duplicate_reference_tuple() -> None:
    with pytest.raises(CpbRefsError, match="repeats"):
        extract_cpb_refs(
            _sign1(refs=[_reference(), _reference()]),
            CPB_REFS,
            required=True,
        )


def test_decoder_rejects_duplicate_map_keys_before_dict_conversion() -> None:
    # Tag(18), array(4), protected=bstr({1:-8,1:-7}), {}, payload, signature.
    encoded = bytes.fromhex("d28445a201270126a0410040")
    with pytest.raises(DuplicateCborKeyError, match="duplicate"):
        decode_cose_sign1(encoded)


def test_decoder_accepts_empty_protected_header_short_form() -> None:
    encoded = encode_deterministic_cbor(CborTag(18, [b"", {}, b"payload", b"signature"]))
    cose = decode_cose_sign1(encoded)
    assert cose.protected == CborMap(())


@pytest.mark.parametrize(
    "encoded",
    [
        bytes.fromhex("d8128440a04040"),  # tag 18 encoded non-canonically
        bytes.fromhex("d29f40a04040ff"),  # indefinite-length array
        bytes.fromhex("d28441a0a0f9000040"),  # floating-point payload
        bytes.fromhex("d28445a202800127a04040"),  # protected map keys out of order
    ],
)
def test_decoder_rejects_non_deterministic_or_unsupported_cbor(encoded: bytes) -> None:
    with pytest.raises(MalformedCborError):
        decode_cose_sign1(encoded, require_deterministic=True)


@pytest.mark.parametrize(
    "encoded",
    [
        bytes.fromhex("d8128440a04040"),  # non-preferred tag encoding
        bytes.fromhex("d29f40a04040ff"),  # indefinite-length outer array
        bytes.fromhex("d28445a202800127a04040"),  # non-deterministic map order
        bytes.fromhex("d28444bf0127ffa04040"),  # indefinite protected map
    ],
)
def test_default_decoder_accepts_legal_non_deterministic_cbor(encoded: bytes) -> None:
    assert isinstance(decode_cose_sign1(encoded), CoseSign1)


def test_signature_structure_commits_to_protected_cpb_refs() -> None:
    original = decode_cose_sign1(_sign1(refs=[_reference()]))
    changed_reference = _reference()
    changed_reference[4] = bytes.fromhex("12" * 32)
    changed = decode_cose_sign1(_sign1(refs=[changed_reference]))

    assert cose_signature1_structure(original) != cose_signature1_structure(changed)


def test_pinned_cose_vector_decodes_verifies_and_binds_target() -> None:
    vector = json.loads(
        (VECTORS / "typed-refs/pass/03-envelope-header-carriage.json").read_text()
    )
    encoded = bytes.fromhex(vector["cose_sign1_bytes_hex"])
    cose = decode_cose_sign1(encoded)

    assert cose.protected_bytes.hex() == vector["protected_header"]["bytes_hex"]
    assert cose.payload is not None and cose.payload.hex() == vector["payload_hex"]
    to_be_signed = cose_signature1_structure(cose)
    assert to_be_signed.hex() == vector["signature_structure_hex"]
    assert cose.signature.hex() == vector["signature"]["signature_hex"]
    public_key = Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(vector["signature"]["public_key_hex"])
    )
    public_key.verify(cose.signature, to_be_signed)

    refs = extract_cpb_refs(
        encoded,
        vector["protected_header"]["cpb_refs_label"],
        required=True,
        require_critical=True,
    )
    assert len(refs) == 1 and refs[0].as_dict() == vector["typed_reference"]

    context = vector["digest_context_declaration"]["contexts"][0]
    cited = vector["cited_artifact"]
    recomputed = canonical_digest(
        cited["payload"],
        set(context["exclusion_set"]),
        algorithm=context["algorithm"],
    )
    assert recomputed == cited["raw_digest_hex"] == refs[0].digest

    # Change only the protected reference digest, retain the original
    # signature, and prove that the signature no longer verifies.
    changed_ref = CborMap(
        tuple(
            (key, "1" + value[1:] if key == 4 else value)
            for key, value in cose.protected.get(CPB_REFS)[0].pairs
        )
    )
    changed_protected = CborMap(
        tuple(
            (key, [changed_ref] if key == CPB_REFS else value)
            for key, value in cose.protected.pairs
        )
    )
    changed_cose = CoseSign1(
        protected_bytes=encode_deterministic_cbor(changed_protected),
        protected=changed_protected,
        unprotected=cose.unprotected,
        payload=cose.payload,
        signature=cose.signature,
    )
    with pytest.raises(InvalidSignature):
        public_key.verify(cose.signature, cose_signature1_structure(changed_cose))


def test_pinned_rfc9995_hash_envelope_obeys_header_and_payload_rules() -> None:
    vector = json.loads(
        (VECTORS / "typed-refs/pass/04-rfc9995-hash-envelope.json").read_text()
    )
    encoded = bytes.fromhex(vector["cose_sign1_bytes_hex"])
    cose = decode_cose_sign1(encoded)
    public_key = Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(vector["signature"]["public_key_hex"])
    )

    assert cose.protected_bytes.hex() == vector["protected_header"]["bytes_hex"]
    assert cose_signature1_structure(cose).hex() == vector["signature_structure_hex"]
    public_key.verify(cose.signature, cose_signature1_structure(cose))
    assert 258 in cose.protected and cose.protected.get(258) == -16
    assert 259 in cose.protected and cose.protected.get(259) == "application/json"
    assert 3 not in cose.protected and 3 not in cose.unprotected
    assert cose.payload == hashlib.sha256(bytes.fromhex(vector["payload_preimage_hex"])).digest()

    refs = extract_cpb_refs(
        encoded,
        vector["protected_header"]["cpb_refs_label"],
        required=True,
        require_critical=True,
    )
    assert len(refs) == 1 and refs[0].as_dict() == vector["typed_reference"]


def test_pinned_multicontext_vector_is_signed_but_target_is_unresolved() -> None:
    vector = json.loads(
        (
            VECTORS
            / "typed-refs/fail/07-header-carriage-purpose-absent-multi-context.json"
        ).read_text()
    )
    encoded = bytes.fromhex(vector["cose_sign1_bytes_hex"])
    cose = decode_cose_sign1(encoded)
    public_key = Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(vector["signature"]["public_key_hex"])
    )
    assert cose_signature1_structure(cose).hex() == vector["signature"][
        "signature_structure_hex"
    ]
    public_key.verify(cose.signature, cose_signature1_structure(cose))

    refs = extract_cpb_refs(
        encoded,
        vector["protected_header"]["cpb_refs_label"],
        required=True,
        require_critical=True,
    )
    assert len(refs) == 1 and refs[0].purpose is None
    contexts = vector["artifact_type_registry_entry"]["digest_contexts"]
    assert len(contexts) > 1
