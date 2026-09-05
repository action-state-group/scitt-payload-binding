# SPDX-License-Identifier: BSD-3-Clause
"""Strict carrier tests for the CPB protected-header representation."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from cpb import canonical_digest
from cpb.cose_refs import (
    FULL_CONTENT_MODE,
    HASH_ENVELOPE_MODE,
    CborMap,
    CborTag,
    CoseHeaderError,
    CoseSign1,
    CpbRefsError,
    CpbRefsLocationError,
    CriticalHeaderError,
    DuplicateCborKeyError,
    MalformedCborError,
    SignedStatementError,
    cose_signature1_structure,
    decode_cose_sign1,
    encode_deterministic_cbor,
    extract_cpb_refs,
    validate_cose_headers,
    validate_cpb_signed_statement,
)

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
    protected_extra: dict[object, object] | None = None,
    unprotected_extra: dict[object, object] | None = None,
    payload: bytes | None = b'{"temperature":"21.5"}',
) -> bytes:
    protected: dict[object, object] = {1: -8}
    if refs is not None:
        protected[CPB_REFS] = refs
        if critical:
            protected[2] = [CPB_REFS]
    unprotected: dict[object, object] = {}
    if unprotected_refs is not None:
        unprotected[CPB_REFS] = unprotected_refs
    if protected_extra:
        protected.update(protected_extra)
    if unprotected_extra:
        unprotected.update(unprotected_extra)
    return encode_deterministic_cbor(
        CborTag(
            18,
            [
                encode_deterministic_cbor(protected),
                unprotected,
                payload,
                b"\x22" * 64,
            ],
        )
    )


def _valid_statement(mode: str, *, payload: bytes | None = None) -> bytes:
    if payload is None:
        payload = b'{"temperature":"21.5"}' if mode == FULL_CONTENT_MODE else b"\x11" * 32
    protected: dict[object, object] = {
        1: -8,
        2: [CPB_REFS],
        4: b"cpb-test-kid",
        15: {1: "https://issuer.example", 2: "urn:example:artifact:1"},
        CPB_REFS: [_reference()],
    }
    if mode == FULL_CONTENT_MODE:
        protected[3] = "application/json"
    else:
        protected[258] = -16
        protected[259] = "application/json"
    return _sign1(
        refs=None,
        critical=False,
        protected_extra=protected,
        payload=payload,
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
    "critical_value, message",
    [
        ([], "non-empty array"),
        (CPB_REFS, "non-empty array"),
        ([True], "not a COSE header label"),
        ([CPB_REFS, CPB_REFS], "repeats header label"),
        ([999], "absent from the protected header"),
    ],
)
def test_rejects_malformed_or_dangling_crit(
    critical_value: object,
    message: str,
) -> None:
    encoded = _sign1(
        refs=[_reference()],
        critical=False,
        protected_extra={2: critical_value},
    )
    with pytest.raises(CriticalHeaderError, match=message):
        extract_cpb_refs(encoded, CPB_REFS, required=True)


def test_rejects_unprotected_crit_and_cross_bucket_header_duplicates() -> None:
    unprotected_crit = _sign1(
        refs=[_reference()],
        critical=False,
        unprotected_extra={2: [CPB_REFS]},
    )
    with pytest.raises(CriticalHeaderError, match="only in the protected"):
        extract_cpb_refs(unprotected_crit, CPB_REFS, required=True)

    repeated_bucket_label = _sign1(
        refs=[_reference()],
        protected_extra={42: "protected"},
        unprotected_extra={42: "unprotected"},
    )
    with pytest.raises(CoseHeaderError, match="both protected and unprotected"):
        extract_cpb_refs(repeated_bucket_label, CPB_REFS, required=True)


def test_rejects_unprocessed_critical_label_and_accepts_declared_support() -> None:
    encoded = _sign1(
        refs=[_reference()],
        critical=False,
        protected_extra={2: [CPB_REFS, 42], 42: "application-defined"},
    )
    with pytest.raises(CriticalHeaderError, match="42.*not declared understood"):
        extract_cpb_refs(encoded, CPB_REFS, required=True)

    refs = extract_cpb_refs(
        encoded,
        CPB_REFS,
        required=True,
        understood_critical_labels={42},
    )
    assert len(refs) == 1


def test_validates_hand_built_header_maps_not_only_decoder_output() -> None:
    duplicate_protected = CoseSign1(
        protected_bytes=b"",
        protected=CborMap(((1, -8), (1, -7))),
        unprotected=CborMap(()),
        payload=b"payload",
        signature=b"signature",
    )
    with pytest.raises(DuplicateCborKeyError, match="duplicate"):
        validate_cose_headers(duplicate_protected)

    invalid_label = CoseSign1(
        protected_bytes=b"",
        protected=CborMap(((b"not-a-label", "value"),)),
        unprotected=CborMap(()),
        payload=b"payload",
        signature=b"signature",
    )
    with pytest.raises(CoseHeaderError, match="non-COSE header label"):
        validate_cose_headers(invalid_label)


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


@pytest.mark.parametrize("mode", [FULL_CONTENT_MODE, HASH_ENVELOPE_MODE])
def test_validates_complete_cpb_statement_modes(mode: str) -> None:
    cose = decode_cose_sign1(_valid_statement(mode))
    kwargs = (
        {"expected_payload_hash_alg": -16, "expected_hash_size": 32}
        if mode == HASH_ENVELOPE_MODE
        else {}
    )
    refs = validate_cpb_signed_statement(
        cose,
        CPB_REFS,
        mode=mode,
        cpb_refs_required=True,
        cpb_refs_critical=True,
        **kwargs,
    )
    assert len(refs) == 1


@pytest.mark.parametrize(
    "protected_update, removed_label, message",
    [
        ({}, 15, "requires CWT Claims"),
        ({15: "not-a-map"}, None, "must be a CBOR map"),
        ({15: {2: "urn:example:artifact:1"}}, None, "text iss"),
        ({15: {1: "https://issuer.example"}}, None, "text sub"),
        ({15: {1: 7, 2: "urn:example:artifact:1"}}, None, "text iss"),
        ({}, 4, "requires protected kid"),
        ({4: "not-bytes"}, None, "kid.*byte string"),
        ({34: None}, None, "x5t.*integer-or-text hash algorithm"),
        ({33: []}, None, "x5chain.*at least two byte strings"),
    ],
)
def test_rejects_rfc9943_baseline_defects(
    protected_update: dict[object, object],
    removed_label: int | None,
    message: str,
) -> None:
    cose = decode_cose_sign1(_valid_statement(FULL_CONTENT_MODE))
    protected = dict(cose.protected.pairs)
    if removed_label is not None:
        protected.pop(removed_label)
    protected.update(protected_update)
    malformed = decode_cose_sign1(
        _sign1(critical=False, protected_extra=protected, payload=cose.payload)
    )
    with pytest.raises(SignedStatementError, match=message):
        validate_cpb_signed_statement(
            malformed,
            CPB_REFS,
            mode=FULL_CONTENT_MODE,
            cpb_refs_required=True,
        )


@pytest.mark.parametrize(
    "credential",
    [
        {34: [-16, b"\x55" * 32]},
        {33: b"single-der-certificate"},
        {33: [b"leaf-der", b"issuer-der"]},
    ],
)
def test_rfc9943_accepts_protected_x509_identity_without_kid(
    credential: dict[int, object],
) -> None:
    cose = decode_cose_sign1(_valid_statement(FULL_CONTENT_MODE))
    protected = dict(cose.protected.pairs)
    protected.pop(4)
    protected.update(credential)
    statement = decode_cose_sign1(
        _sign1(critical=False, protected_extra=protected, payload=cose.payload)
    )
    refs = validate_cpb_signed_statement(
        statement,
        CPB_REFS,
        mode=FULL_CONTENT_MODE,
        cpb_refs_required=True,
    )
    assert len(refs) == 1


@pytest.mark.parametrize(
    "claim_label, claim_name, invalid_value",
    [
        (1, "iss", "not a URI: contains spaces"),
        (2, "sub", "urn:invalid-percent:%zz"),
    ],
)
def test_rfc9943_rejects_invalid_string_or_uri_claims(
    claim_label: int,
    claim_name: str,
    invalid_value: str,
) -> None:
    cose = decode_cose_sign1(_valid_statement(FULL_CONTENT_MODE))
    protected = dict(cose.protected.pairs)
    claims = dict(protected[15].pairs)
    claims[claim_label] = invalid_value
    protected[15] = claims
    malformed = decode_cose_sign1(
        _sign1(critical=False, protected_extra=protected, payload=cose.payload)
    )

    with pytest.raises(SignedStatementError, match=rf"CWT {claim_name}.*StringOrURI"):
        validate_cpb_signed_statement(
            malformed,
            CPB_REFS,
            mode=FULL_CONTENT_MODE,
            cpb_refs_required=True,
        )


@pytest.mark.parametrize("issuer", ["", "x" * 8193])
def test_rfc9943_enforces_x509_issuer_length(issuer: str) -> None:
    cose = decode_cose_sign1(_valid_statement(FULL_CONTENT_MODE))
    protected = dict(cose.protected.pairs)
    protected[15] = {1: issuer, 2: "artifact"}
    protected[34] = [-16, b"\x55" * 32]
    malformed = decode_cose_sign1(
        _sign1(critical=False, protected_extra=protected, payload=cose.payload)
    )

    with pytest.raises(SignedStatementError, match="1..8192 characters"):
        validate_cpb_signed_statement(
            malformed,
            CPB_REFS,
            mode=FULL_CONTENT_MODE,
            cpb_refs_required=True,
        )


def test_rfc9943_allows_empty_string_or_uri_claims_with_kid_identity() -> None:
    """The explicit 1..8192 issuer bound is conditional on protected X.509."""

    cose = decode_cose_sign1(_valid_statement(FULL_CONTENT_MODE))
    protected = dict(cose.protected.pairs)
    protected[15] = {1: "", 2: ""}
    statement = decode_cose_sign1(
        _sign1(critical=False, protected_extra=protected, payload=cose.payload)
    )

    refs = validate_cpb_signed_statement(
        statement,
        CPB_REFS,
        mode=FULL_CONTENT_MODE,
        cpb_refs_required=True,
    )
    assert len(refs) == 1


@pytest.mark.parametrize(
    "protected_identity",
    [
        {4: b"certificate-key-id"},
        {34: [-16, b"\x66" * 32]},
    ],
)
def test_rfc9943_allows_unprotected_x5chain_with_protected_x5t_or_kid(
    protected_identity: dict[int, object],
) -> None:
    cose = decode_cose_sign1(_valid_statement(FULL_CONTENT_MODE))
    protected = dict(cose.protected.pairs)
    protected.pop(4)
    protected.update(protected_identity)
    statement = decode_cose_sign1(
        _sign1(
            critical=False,
            protected_extra=protected,
            unprotected_extra={33: [b"leaf-der", b"issuer-der"]},
            payload=cose.payload,
        )
    )

    refs = validate_cpb_signed_statement(
        statement,
        CPB_REFS,
        mode=FULL_CONTENT_MODE,
        cpb_refs_required=True,
    )
    assert len(refs) == 1


@pytest.mark.parametrize(
    "label, value, message",
    [
        (34, [True, b"hash"], "unprotected x5t"),
        (34, [-16, "not-bytes"], "unprotected x5t"),
        (33, [b"only-one"], "unprotected x5chain"),
        (33, [b"leaf", "not-bytes"], "unprotected x5chain"),
    ],
)
def test_rfc9360_rejects_malformed_unprotected_x509_parameters(
    label: int,
    value: object,
    message: str,
) -> None:
    cose = decode_cose_sign1(_valid_statement(FULL_CONTENT_MODE))
    malformed = decode_cose_sign1(
        _sign1(
            critical=False,
            protected_extra=dict(cose.protected.pairs),
            unprotected_extra={label: value},
            payload=cose.payload,
        )
    )

    with pytest.raises(SignedStatementError, match=message):
        validate_cpb_signed_statement(
            malformed,
            CPB_REFS,
            mode=FULL_CONTENT_MODE,
            cpb_refs_required=True,
        )


def test_unprotected_x5chain_does_not_replace_protected_key_identity() -> None:
    cose = decode_cose_sign1(_valid_statement(FULL_CONTENT_MODE))
    protected = dict(cose.protected.pairs)
    protected.pop(4)
    malformed = decode_cose_sign1(
        _sign1(
            critical=False,
            protected_extra=protected,
            unprotected_extra={33: b"leaf-der"},
            payload=cose.payload,
        )
    )

    with pytest.raises(SignedStatementError, match="unprotected x5chain requires"):
        validate_cpb_signed_statement(
            malformed,
            CPB_REFS,
            mode=FULL_CONTENT_MODE,
            cpb_refs_required=True,
        )


@pytest.mark.parametrize("forbidden_label", [258, 259, 260])
@pytest.mark.parametrize("bucket", ["protected", "unprotected"])
def test_full_content_rejects_hash_envelope_headers(
    forbidden_label: int,
    bucket: str,
) -> None:
    cose = decode_cose_sign1(_valid_statement(FULL_CONTENT_MODE))
    protected = dict(cose.protected.pairs)
    unprotected: dict[object, object] = {}
    value: object = -16 if forbidden_label == 258 else "application/json"
    (protected if bucket == "protected" else unprotected)[forbidden_label] = value
    malformed = decode_cose_sign1(
        _sign1(
            critical=False,
            protected_extra=protected,
            unprotected_extra=unprotected,
            payload=cose.payload,
        )
    )
    with pytest.raises(SignedStatementError, match="MUST NOT appear in Full-Content"):
        validate_cpb_signed_statement(
            malformed,
            CPB_REFS,
            mode=FULL_CONTENT_MODE,
            cpb_refs_required=True,
        )


def test_full_content_requires_protected_well_typed_content_type() -> None:
    cose = decode_cose_sign1(_valid_statement(FULL_CONTENT_MODE))
    protected = dict(cose.protected.pairs)
    protected.pop(3)
    missing = decode_cose_sign1(
        _sign1(critical=False, protected_extra=protected, payload=cose.payload)
    )
    with pytest.raises(SignedStatementError, match="requires content_type"):
        validate_cpb_signed_statement(missing, CPB_REFS, mode=FULL_CONTENT_MODE)

    protected[3] = -1
    wrong_type = decode_cose_sign1(
        _sign1(critical=False, protected_extra=protected, payload=cose.payload)
    )
    with pytest.raises(SignedStatementError, match="unsigned integer or text"):
        validate_cpb_signed_statement(wrong_type, CPB_REFS, mode=FULL_CONTENT_MODE)


@pytest.mark.parametrize(
    "removed_label, message",
    [
        (258, "requires payload-hash-alg"),
        (259, "requires preimage-content-type"),
    ],
)
def test_hash_envelope_requires_cpb_protected_headers(
    removed_label: int,
    message: str,
) -> None:
    cose = decode_cose_sign1(_valid_statement(HASH_ENVELOPE_MODE))
    protected = dict(cose.protected.pairs)
    protected.pop(removed_label)
    malformed = decode_cose_sign1(
        _sign1(critical=False, protected_extra=protected, payload=cose.payload)
    )
    with pytest.raises(SignedStatementError, match=message):
        validate_cpb_signed_statement(malformed, CPB_REFS, mode=HASH_ENVELOPE_MODE)


@pytest.mark.parametrize("label", [258, 259, 260])
def test_hash_envelope_rejects_its_parameters_unprotected(label: int) -> None:
    cose = decode_cose_sign1(_valid_statement(HASH_ENVELOPE_MODE))
    protected = dict(cose.protected.pairs)
    if label in protected:
        value = protected.pop(label)
    else:
        value = "https://payload.example/artifact"
    malformed = decode_cose_sign1(
        _sign1(
            critical=False,
            protected_extra=protected,
            unprotected_extra={label: value},
            payload=cose.payload,
        )
    )
    with pytest.raises(SignedStatementError, match=f"label {label}.*unprotected"):
        validate_cpb_signed_statement(malformed, CPB_REFS, mode=HASH_ENVELOPE_MODE)


@pytest.mark.parametrize("bucket", ["protected", "unprotected"])
def test_hash_envelope_forbids_content_type_in_both_buckets(bucket: str) -> None:
    cose = decode_cose_sign1(_valid_statement(HASH_ENVELOPE_MODE))
    protected = dict(cose.protected.pairs)
    unprotected: dict[object, object] = {}
    (protected if bucket == "protected" else unprotected)[3] = "application/json"
    malformed = decode_cose_sign1(
        _sign1(
            critical=False,
            protected_extra=protected,
            unprotected_extra=unprotected,
            payload=cose.payload,
        )
    )
    with pytest.raises(SignedStatementError, match="forbids content_type"):
        validate_cpb_signed_statement(malformed, CPB_REFS, mode=HASH_ENVELOPE_MODE)


@pytest.mark.parametrize(
    "label, value, message",
    [
        (258, "SHA-256", "label 258.*integer"),
        (259, -1, "label 259.*unsigned integer or text"),
        (260, b"https://payload.example", "label 260.*text string"),
    ],
)
def test_hash_envelope_rejects_wrong_parameter_types(
    label: int,
    value: object,
    message: str,
) -> None:
    cose = decode_cose_sign1(_valid_statement(HASH_ENVELOPE_MODE))
    protected = dict(cose.protected.pairs)
    protected[label] = value
    malformed = decode_cose_sign1(
        _sign1(critical=False, protected_extra=protected, payload=cose.payload)
    )
    with pytest.raises(SignedStatementError, match=message):
        validate_cpb_signed_statement(malformed, CPB_REFS, mode=HASH_ENVELOPE_MODE)


def test_hash_envelope_binds_expected_algorithm_and_raw_digest_size() -> None:
    cose = decode_cose_sign1(_valid_statement(HASH_ENVELOPE_MODE))
    with pytest.raises(SignedStatementError, match="does not match.*COSE hash algorithm"):
        validate_cpb_signed_statement(
            cose,
            CPB_REFS,
            mode=HASH_ENVELOPE_MODE,
            expected_payload_hash_alg=-44,
        )
    with pytest.raises(SignedStatementError, match="32 bytes.*64 bytes"):
        validate_cpb_signed_statement(
            cose,
            CPB_REFS,
            mode=HASH_ENVELOPE_MODE,
            expected_payload_hash_alg=-16,
            expected_hash_size=64,
        )


def test_hash_envelope_accepts_detached_raw_digest_for_size_validation() -> None:
    attached = decode_cose_sign1(_valid_statement(HASH_ENVELOPE_MODE))
    protected = dict(attached.protected.pairs)
    detached = decode_cose_sign1(
        _sign1(critical=False, protected_extra=protected, payload=None)
    )
    refs = validate_cpb_signed_statement(
        detached,
        CPB_REFS,
        mode=HASH_ENVELOPE_MODE,
        cpb_refs_required=True,
        detached_payload=b"\x11" * 32,
        expected_payload_hash_alg=-16,
        expected_hash_size=32,
    )
    assert len(refs) == 1


def test_statement_validation_accepts_ordinary_nonpreferred_cbor() -> None:
    deterministic = _valid_statement(FULL_CONTENT_MODE)
    assert deterministic[0] == 0xD2  # preferred one-byte encoding of tag 18
    nonpreferred = b"\xd8\x12" + deterministic[1:]

    cose = decode_cose_sign1(nonpreferred)
    refs = validate_cpb_signed_statement(
        cose,
        CPB_REFS,
        mode=FULL_CONTENT_MODE,
        cpb_refs_required=True,
        cpb_refs_critical=True,
    )
    assert len(refs) == 1
    with pytest.raises(MalformedCborError, match="non-shortest"):
        decode_cose_sign1(nonpreferred, require_deterministic=True)


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

    refs = validate_cpb_signed_statement(
        cose,
        vector["protected_header"]["cpb_refs_label"],
        mode=vector["statement_mode"],
        cpb_refs_required=True,
        cpb_refs_critical=True,
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

    refs = validate_cpb_signed_statement(
        cose,
        vector["protected_header"]["cpb_refs_label"],
        mode=vector["statement_mode"],
        cpb_refs_required=True,
        cpb_refs_critical=True,
        expected_payload_hash_alg=-16,
        expected_hash_size=32,
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

    refs = validate_cpb_signed_statement(
        cose,
        vector["protected_header"]["cpb_refs_label"],
        mode=FULL_CONTENT_MODE,
        cpb_refs_required=True,
        cpb_refs_critical=True,
    )
    assert len(refs) == 1 and refs[0].purpose is None
    contexts = vector["artifact_type_registry_entry"]["digest_contexts"]
    assert len(contexts) > 1
