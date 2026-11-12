"""Contract and boundary tests for CTF-03, CTF-04, and evidence intake/capture bounds (CTF-05)."""

from __future__ import annotations

import base64
import io
import json
import os
import sys
import tarfile
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import jsonschema
import pytest

from ctf_mcp.contracts import (
    BoundsExceededError,
    ConfigurationError,
    ContractViolationError,
    CursorError,
    CursorPayload,
    EvidenceAccessDeniedError,
    EvidenceNotFoundError,
    EvidenceVaultPort,
    PageEncoding,
    PathSecurityError,
    sha256_bytes,
)
from ctf_mcp.evidence.capture import (
    ArchiveLimits,
    BoundedCaptureBuffer,
    capture_bounded_stream,
    validate_archive_bytes,
)
from ctf_mcp.evidence.importer import BoundedEvidenceImporter
from ctf_mcp.evidence.paging import CursorSigner, validate_evidence_page_schema
from ctf_mcp.evidence.redaction import EvidenceRedactor
from ctf_mcp.evidence.vault import EvidenceVault
from ctf_mcp.storage import Storage

REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = REPO_ROOT / "schemas" / "evidence-page.schema.json"
HMAC_KEY = b"0123456789abcdef0123456789abcdef"
SAN_ARGS_SHA = "a" * 64


def _seed_run_and_action(
    storage: Storage,
    *,
    run_id: str = "run-1",
    principal_id: str = "alice",
    action_id: str = "act-1",
    request_id: str = "req-1",
) -> None:
    now = "2026-11-13T00:00:00+00:00"
    with storage.transaction() as conn:
        existing_run = conn.execute(
            "SELECT 1 FROM runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        if existing_run is None:
            conn.execute(
                """
                INSERT INTO runs (
                    run_id, owner_principal_id, task_id, mode, scope_revision,
                    manifest_json, budget_spec_json, remaining_ms, remaining_bytes,
                    remaining_calls, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    principal_id,
                    "task-1",
                    "offline_ctf",
                    "scope-1",
                    "{}",
                    "{}",
                    60_000,
                    10_000_000,
                    40,
                    now,
                ),
            )
        conn.execute(
            """
            INSERT INTO actions (
                action_id, principal_id, run_id, request_id, expected_revision,
                capability_name, operation, adapter_revision, canonical_args_sha256,
                sanitized_args_json, scope_revision, state, reserved_ms, reserved_bytes,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                action_id,
                principal_id,
                run_id,
                request_id,
                1,
                "artifact.inspect",
                "strings",
                "rev-1",
                SAN_ARGS_SHA,
                "{}",
                "scope-1",
                "completed",
                1000,
                10000,
                now,
                now,
            ),
        )


def _make_vault(tmp_path: Path, **kwargs) -> tuple[Storage, EvidenceVault]:
    storage = Storage(tmp_path / "state" / "harness.db")
    storage.initialize()
    vault = EvidenceVault(
        storage=storage,
        vault_root=tmp_path / "vault",
        cursor_hmac_key=HMAC_KEY,
        **kwargs,
    )
    return storage, vault


def _read_all_pages(
    vault: EvidenceVault,
    *,
    run_id: str,
    principal_id: str,
    evidence_id: str,
    max_chars: int | None = None,
    max_decode_bytes: int | None = None,
):
    pages = []
    cursor = None
    while True:
        page = vault.read_page(
            run_id=run_id,
            principal_id=principal_id,
            evidence_id=evidence_id,
            cursor=cursor,
            max_chars=max_chars,
            max_decode_bytes=max_decode_bytes,
        )
        validate_evidence_page_schema(page, schema_path=SCHEMA_PATH)
        pages.append(page)
        if page.next_cursor is None:
            break
        cursor = page.next_cursor
    return pages


# ---------------------------------------------------------------------------
# CTF-03: Immutable Vault Storage, Multi-page UTF-8 & Binary Reassembly, EOF
# ---------------------------------------------------------------------------


def test_vault_satisfies_protocol_and_forbids_auto_git(tmp_path: Path) -> None:
    storage, vault = _make_vault(tmp_path)
    assert isinstance(vault, EvidenceVaultPort)

    with pytest.raises(ConfigurationError):
        EvidenceVault(
            storage=storage,
            vault_root=tmp_path / "vault2",
            cursor_hmac_key=HMAC_KEY,
            automatic_git_export=True,
        )


def test_ctf03_long_utf8_multibyte_paging_and_reassembly(tmp_path: Path) -> None:
    storage, vault = _make_vault(tmp_path)
    _seed_run_and_action(storage)

    # Mix 1-byte ASCII, 3-byte Japanese, and 4-byte emoji across > 4000 char pages
    text = ("Aあいう🔥" * 2400) + "終端"
    raw = text.encode("utf-8")
    expected_sha = sha256_bytes(raw)

    manifest = vault.store_raw(
        run_id="run-1",
        owner_principal_id="alice",
        action_id="act-1",
        data=raw,
        media_type="text/plain; charset=utf-8",
        capture_complete=True,
        omission_reason=None,
        source_artifact_hashes=("b" * 64,),
        adapter_revision="adapter-1",
        sanitized_args_sha256=SAN_ARGS_SHA,
    )
    assert manifest.view_sha256 == expected_sha
    assert manifest.view_revision == "raw-v1"
    blob_path = tmp_path / "vault" / "blobs" / expected_sha[:2] / expected_sha
    assert blob_path.is_file()
    assert blob_path.read_bytes() == raw

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())

    # Test with both default 4000-char cap and tight byte cap forcing split near multi-byte boundaries
    for byte_cap in (None, 100):
        pages = _read_all_pages(
            vault,
            run_id="run-1",
            principal_id="alice",
            evidence_id=manifest.evidence_id,
            max_decode_bytes=byte_cap,
        )
        assert len(pages) >= 3
        for idx, p in enumerate(pages):
            validator.validate(p.model_dump(mode="json"))
            assert p.encoding == PageEncoding.UTF8
            assert len(p.content) <= 4000
            assert p.capture_complete is True
            assert p.omission_reason is None
            if idx < len(pages) - 1:
                assert p.next_cursor is not None
                assert p.next_offset_bytes == pages[idx + 1].offset_bytes
            else:
                assert p.next_cursor is None
                assert p.next_offset_bytes == p.view_bytes

        reassembled = "".join(p.content for p in pages)
        assert reassembled == text
        assert sha256_bytes(reassembled.encode("utf-8")) == pages[0].view_sha256

    # Repeated cursor returns exact same immutable page
    p1 = vault.read_page(run_id="run-1", principal_id="alice", evidence_id=manifest.evidence_id)
    p2_a = vault.read_page(
        run_id="run-1", principal_id="alice", evidence_id=manifest.evidence_id, cursor=p1.next_cursor
    )
    p2_b = vault.read_page(
        run_id="run-1", principal_id="alice", evidence_id=manifest.evidence_id, cursor=p1.next_cursor
    )
    assert p2_a == p2_b


def test_ctf03_binary_base64_paging_empty_view_and_incomplete_capture(tmp_path: Path) -> None:
    storage, vault = _make_vault(tmp_path)
    _seed_run_and_action(storage, action_id="act-bin", request_id="req-bin")
    _seed_run_and_action(storage, action_id="act-empty", request_id="req-empty")
    _seed_run_and_action(storage, action_id="act-trunc", request_id="req-trunc")

    # 1. Binary payload > 3000 bytes (requires multiple base64 pages under 4000 char cap)
    binary_data = bytes((i * 37) % 256 for i in range(7501))
    bin_manifest = vault.store_raw(
        run_id="run-1",
        owner_principal_id="alice",
        action_id="act-bin",
        data=binary_data,
        media_type="application/octet-stream",
        capture_complete=True,
        omission_reason=None,
        source_artifact_hashes=(),
        adapter_revision="adapter-1",
        sanitized_args_sha256=SAN_ARGS_SHA,
    )
    bin_pages = _read_all_pages(
        vault, run_id="run-1", principal_id="alice", evidence_id=bin_manifest.evidence_id
    )
    assert len(bin_pages) == 3  # 3000 + 3000 + 1501
    for p in bin_pages:
        assert p.encoding == PageEncoding.BASE64
        assert len(p.content) <= 4000
    reassembled_bin = b"".join(base64.b64decode(p.content, validate=True) for p in bin_pages)
    assert reassembled_bin == binary_data
    assert sha256_bytes(reassembled_bin) == bin_manifest.view_sha256

    # 2. Empty view produces single empty terminal page
    empty_manifest = vault.store_raw(
        run_id="run-1",
        owner_principal_id="alice",
        action_id="act-empty",
        data=b"",
        media_type="text/plain",
        capture_complete=True,
        omission_reason=None,
        source_artifact_hashes=(),
        adapter_revision="adapter-1",
        sanitized_args_sha256=SAN_ARGS_SHA,
    )
    empty_pages = _read_all_pages(
        vault, run_id="run-1", principal_id="alice", evidence_id=empty_manifest.evidence_id
    )
    assert len(empty_pages) == 1
    assert empty_pages[0].view_bytes == 0
    assert empty_pages[0].offset_bytes == 0
    assert empty_pages[0].next_offset_bytes == 0
    assert empty_pages[0].content == ""
    assert empty_pages[0].next_cursor is None

    # 3. Incomplete capture preserves capture_complete=False & omission_reason even at EOF
    trunc_manifest = vault.store_raw(
        run_id="run-1",
        owner_principal_id="alice",
        action_id="act-trunc",
        data=b"partial-output-" * 400,
        media_type="text/plain",
        capture_complete=False,
        omission_reason="Action output byte quota (6000 bytes) exceeded.",
        source_artifact_hashes=(),
        adapter_revision="adapter-1",
        sanitized_args_sha256=SAN_ARGS_SHA,
    )
    trunc_pages = _read_all_pages(
        vault, run_id="run-1", principal_id="alice", evidence_id=trunc_manifest.evidence_id
    )
    assert len(trunc_pages) >= 2
    for p in trunc_pages:
        assert p.capture_complete is False
        assert p.omission_reason == "Action output byte quota (6000 bytes) exceeded."
    assert trunc_pages[-1].next_cursor is None


# ---------------------------------------------------------------------------
# CTF-04: Access Control, Cross-Run/Principal Denial, Redaction & Cursor Checks
# ---------------------------------------------------------------------------


def test_ctf04_cross_run_cross_principal_and_cursor_tampering_rejected(tmp_path: Path) -> None:
    storage, vault = _make_vault(tmp_path)
    _seed_run_and_action(storage, run_id="run-1", principal_id="alice", action_id="act-1", request_id="r1")
    _seed_run_and_action(storage, run_id="run-2", principal_id="alice", action_id="act-2", request_id="r2")
    _seed_run_and_action(storage, run_id="run-3", principal_id="bob", action_id="act-3", request_id="r3")

    m1 = vault.store_raw(
        run_id="run-1",
        owner_principal_id="alice",
        action_id="act-1",
        data=b"hello-" * 1000,
        media_type="text/plain",
        capture_complete=True,
        omission_reason=None,
        source_artifact_hashes=(),
        adapter_revision="adapter-1",
        sanitized_args_sha256=SAN_ARGS_SHA,
    )
    m2 = vault.store_raw(
        run_id="run-2",
        owner_principal_id="alice",
        action_id="act-2",
        data=b"other-" * 1000,
        media_type="text/plain",
        capture_complete=True,
        omission_reason=None,
        source_artifact_hashes=(),
        adapter_revision="adapter-1",
        sanitized_args_sha256=SAN_ARGS_SHA,
    )

    # Direct cross-run and cross-principal read_page / get_manifest denied
    with pytest.raises(EvidenceAccessDeniedError):
        vault.read_page(run_id="run-2", principal_id="alice", evidence_id=m1.evidence_id)
    with pytest.raises(EvidenceAccessDeniedError):
        vault.read_page(run_id="run-1", principal_id="bob", evidence_id=m1.evidence_id)
    with pytest.raises(EvidenceAccessDeniedError):
        vault.get_manifest(run_id="run-3", principal_id="bob", evidence_id=m1.evidence_id)

    page1 = vault.read_page(
        run_id="run-1", principal_id="alice", evidence_id=m1.evidence_id, max_chars=100
    )
    assert page1.next_cursor is not None
    # Content-addressed deduplication: storing identical bytes for another action succeeds cleanly
    _seed_run_and_action(storage, run_id="run-1", principal_id="alice", action_id="act-dup", request_id="r-dup")
    m1_dup = vault.store_raw(
        run_id="run-1",
        owner_principal_id="alice",
        action_id="act-dup",
        data=b"hello-" * 1000,
        media_type="text/plain",
        capture_complete=True,
        omission_reason=None,
        source_artifact_hashes=(),
        adapter_revision="adapter-1",
        sanitized_args_sha256=SAN_ARGS_SHA,
    )
    assert m1_dup.view_sha256 == m1.view_sha256

    # Mid-UTF-8-codepoint offset cursor -> CursorError
    _seed_run_and_action(storage, run_id="run-1", principal_id="alice", action_id="act-utf8", request_id="r-utf8")
    m_utf8 = vault.store_raw(
        run_id="run-1",
        owner_principal_id="alice",
        action_id="act-utf8",
        data="🔥あ".encode("utf-8"),
        media_type="text/plain",
        capture_complete=True,
        omission_reason=None,
        source_artifact_hashes=(),
        adapter_revision="adapter-1",
        sanitized_args_sha256=SAN_ARGS_SHA,
    )
    mid_cursor = CursorSigner(HMAC_KEY).sign(
        CursorPayload(
            run_id="run-1",
            principal_id="alice",
            evidence_id=m_utf8.evidence_id,
            view_sha256=m_utf8.view_sha256,
            view_revision="raw-v1",
            offset_bytes=1,  # inside 4-byte emoji
            issued_at=datetime.now(UTC),
        )
    )
    with pytest.raises(CursorError):
        vault.read_page(
            run_id="run-1", principal_id="alice", evidence_id=m_utf8.evidence_id, cursor=mid_cursor
        )

    # Cursor from run-1 used against run-2 or principal bob -> EvidenceAccessDeniedError
    with pytest.raises(EvidenceAccessDeniedError):
        vault.read_page(
            run_id="run-2", principal_id="alice", evidence_id=m1.evidence_id, cursor=page1.next_cursor
        )
    with pytest.raises(EvidenceAccessDeniedError):
        vault.read_page(
            run_id="run-1", principal_id="bob", evidence_id=m1.evidence_id, cursor=page1.next_cursor
        )

    # Cursor from m1 used against m2 (same principal, wrong evidence_id)
    page2 = vault.read_page(
        run_id="run-2", principal_id="alice", evidence_id=m2.evidence_id, max_chars=100
    )
    with pytest.raises(EvidenceAccessDeniedError):
        vault.read_page(
            run_id="run-1", principal_id="alice", evidence_id=m1.evidence_id, cursor=page2.next_cursor
        )

    # Same run/principal, different evidence_id -> CursorError
    _seed_run_and_action(storage, run_id="run-1", principal_id="alice", action_id="act-1b", request_id="r1b")
    m1b = vault.store_raw(
        run_id="run-1",
        owner_principal_id="alice",
        action_id="act-1b",
        data=b"second-" * 1000,
        media_type="text/plain",
        capture_complete=True,
        omission_reason=None,
        source_artifact_hashes=(),
        adapter_revision="adapter-1",
        sanitized_args_sha256=SAN_ARGS_SHA,
    )
    with pytest.raises(CursorError):
        vault.read_page(
            run_id="run-1", principal_id="alice", evidence_id=m1b.evidence_id, cursor=page1.next_cursor
        )

    # Tampered / malformed cursors -> CursorError
    tampered_chars = list(page1.next_cursor)
    tampered_chars[5] = "A" if tampered_chars[5] != "A" else "B"
    with pytest.raises(CursorError):
        vault.read_page(
            run_id="run-1",
            principal_id="alice",
            evidence_id=m1.evidence_id,
            cursor="".join(tampered_chars),
        )
    with pytest.raises(CursorError):
        vault.read_page(run_id="run-1", principal_id="alice", evidence_id=m1.evidence_id, cursor="not-valid!")

    # Out-of-range cursor (even with genuine HMAC signature) -> CursorError
    signer = CursorSigner(HMAC_KEY)
    oob_cursor = signer.sign(
        CursorPayload(
            run_id="run-1",
            principal_id="alice",
            evidence_id=m1.evidence_id,
            view_sha256=m1.view_sha256,
            view_revision="raw-v1",
            offset_bytes=m1.byte_length + 10,
            issued_at=datetime.now(UTC),
        )
    )
    with pytest.raises(CursorError):
        vault.read_page(
            run_id="run-1", principal_id="alice", evidence_id=m1.evidence_id, cursor=oob_cursor
        )


def test_ctf04_redaction_invalidates_prior_cursor_with_and_without_revocation(tmp_path: Path) -> None:
    storage, vault = _make_vault(tmp_path)
    _seed_run_and_action(storage)
    redactor = EvidenceRedactor(vault)

    data = ("prefix " * 30 + "SYNTHETIC_SECRET_TOKEN_123 " + "suffix " * 30).encode("utf-8")
    m = vault.store_raw(
        run_id="run-1",
        owner_principal_id="alice",
        action_id="act-1",
        data=data,
        media_type="text/plain",
        capture_complete=True,
        omission_reason=None,
        source_artifact_hashes=(),
        adapter_revision="adapter-1",
        sanitized_args_sha256=SAN_ARGS_SHA,
    )
    raw_page1 = vault.read_page(
        run_id="run-1", principal_id="alice", evidence_id=m.evidence_id, max_chars=50
    )
    assert raw_page1.next_cursor is not None

    # Create redacted view WITHOUT revoking raw-v1 first -> old cursor rejected because active view changed
    res1 = redactor.create_redacted_view(
        run_id="run-1",
        principal_id="alice",
        evidence_id=m.evidence_id,
        revoke_prior_views=False,
    )
    assert res1.redacted_view.view_revision == "redacted-v1"
    with pytest.raises(EvidenceAccessDeniedError):
        vault.read_page(
            run_id="run-1",
            principal_id="alice",
            evidence_id=m.evidence_id,
            cursor=raw_page1.next_cursor,
        )

    # Also test explicit revocation of raw-v1 and all views
    vault.revoke_view(
        run_id="run-1",
        principal_id="alice",
        evidence_id=m.evidence_id,
        view_revision="raw-v1",
    )
    # Latest redacted-v1 still readable from scratch
    redacted_page1 = vault.read_page(
        run_id="run-1", principal_id="alice", evidence_id=m.evidence_id, max_chars=50
    )
    assert redacted_page1.view_revision == "redacted-v1"

    # Revoke all views -> even fresh read_page(cursor=None) is denied
    vault.revoke_view(run_id="run-1", principal_id="alice", evidence_id=m.evidence_id)
    with pytest.raises(EvidenceAccessDeniedError):
        vault.read_page(run_id="run-1", principal_id="alice", evidence_id=m.evidence_id)


# ---------------------------------------------------------------------------
# CTF-05: Pre-Buffering Capture Quotas, Archive Bombs, and Bounded Importer
# ---------------------------------------------------------------------------


def test_ctf05_bounded_capture_buffer_and_archive_bounds() -> None:
    # Stream quota triggers immediately
    buf = BoundedCaptureBuffer(
        max_action_bytes=100,
        max_stream_bytes=20,
        max_run_remaining_bytes=100,
    )
    assert buf.append(b"1234567890", stream="stdout") is True
    assert buf.append(b"abcdefghijklmno", stream="stdout") is False
    assert buf.should_stop is True
    assert buf.append(b"more-data", stream="stdout") is False  # nothing buffered after cutoff
    res = buf.finalize()
    assert res.data == b"1234567890abcdefghij"
    assert res.bytes_captured == 20
    assert res.capture_complete is False
    assert res.omission_reason is not None and "Stream" in res.omission_reason
    assert res.sha256 == sha256_bytes(res.data)

    # Run quota tighter than action quota
    stream_res = capture_bounded_stream(
        io.BytesIO(b"X" * 50),
        max_action_bytes=40,
        max_run_remaining_bytes=12,
        chunk_size=8,
    )
    assert stream_res.data == b"X" * 12
    assert stream_res.capture_complete is False
    assert stream_res.limit_scope == "run"

    # Valid small zip passes
    good_bio = io.BytesIO()
    with zipfile.ZipFile(good_bio, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("notes.txt", b"hello archive world")
    good_info = validate_archive_bytes(good_bio.getvalue(), limits=ArchiveLimits())
    assert good_info.entry_count == 1

    # High expansion ratio zip bomb rejected
    bomb_bio = io.BytesIO()
    with zipfile.ZipFile(bomb_bio, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("bomb.txt", b"A" * 200_000)
    with pytest.raises(BoundsExceededError):
        validate_archive_bytes(
            bomb_bio.getvalue(),
            limits=ArchiveLimits(max_uncompressed_bytes=10_000_000, max_expansion_ratio=20.0),
        )

    # Excessive nesting depth rejected
    nested_bytes = good_bio.getvalue()
    for lvl in range(3):
        lvl_bio = io.BytesIO()
        with zipfile.ZipFile(lvl_bio, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(f"layer{lvl}.zip", nested_bytes)
        nested_bytes = lvl_bio.getvalue()
    with pytest.raises(BoundsExceededError):
        validate_archive_bytes(nested_bytes, limits=ArchiveLimits(max_archive_depth=2))

    # Traversal entry inside archive rejected
    trav_bio = io.BytesIO()
    with zipfile.ZipFile(trav_bio, "w") as zf:
        zf.writestr("../escape.txt", b"pwn")
    with pytest.raises(PathSecurityError):
        validate_archive_bytes(trav_bio.getvalue(), limits=ArchiveLimits())

    # Symlink inside tar archive rejected, and tar.gz expansion bomb rejected
    tar_sym_bio = io.BytesIO()
    with tarfile.open(fileobj=tar_sym_bio, mode="w:gz") as tf:
        info = tarfile.TarInfo("sym")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        tf.addfile(info)
    with pytest.raises(PathSecurityError):
        validate_archive_bytes(tar_sym_bio.getvalue(), limits=ArchiveLimits(), filename="sym.tar.gz")

    tar_bomb_bio = io.BytesIO()
    with tarfile.open(fileobj=tar_bomb_bio, mode="w:gz") as tf:
        payload = b"\x00" * 100_000
        info = tarfile.TarInfo("zeros.bin")
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))
    with pytest.raises(BoundsExceededError):
        validate_archive_bytes(
            tar_bomb_bio.getvalue(),
            limits=ArchiveLimits(max_uncompressed_bytes=50_000),
            filename="bomb.tar.gz",
        )


def test_ctf05_10_bounded_importer_enforces_ids_symlinks_bounds_and_hashes(tmp_path: Path) -> None:
    storage, vault = _make_vault(tmp_path)
    _seed_run_and_action(storage)

    staging = tmp_path / "staging"
    staging.mkdir()
    outside = tmp_path / "host_secret.txt"
    outside.write_bytes(b"SECRET_OUTSIDE")

    # Reject privileged identity
    with pytest.raises(ConfigurationError):
        BoundedEvidenceImporter(vault=vault, staging_root=staging, importer_identity="root")

    importer = BoundedEvidenceImporter(
        vault=vault,
        staging_root=staging,
        max_import_bytes=1024,
    )

    good_file = staging / "obj-001"
    good_payload = b"verified-guest-output"
    good_file.write_bytes(good_payload)

    receipt = importer.import_object(
        run_id="run-1",
        owner_principal_id="alice",
        action_id="act-1",
        object_id="obj-001",
        expected_sha256=sha256_bytes(good_payload),
        expected_size_bytes=len(good_payload),
        media_type="text/plain",
        capture_complete=True,
        omission_reason=None,
        source_artifact_hashes=(),
        adapter_revision="adapter-1",
        sanitized_args_sha256=SAN_ARGS_SHA,
    )
    assert receipt.verified_sha256 == sha256_bytes(good_payload)

    # Path traversal in opaque ID or staging_relpath -> PathSecurityError
    with pytest.raises(PathSecurityError):
        importer.import_object(
            run_id="run-1",
            owner_principal_id="alice",
            action_id="act-1",
            object_id="../host_secret.txt",
            expected_sha256=sha256_bytes(b"SECRET_OUTSIDE"),
            media_type="text/plain",
            capture_complete=True,
            omission_reason=None,
            source_artifact_hashes=(),
            adapter_revision="adapter-1",
            sanitized_args_sha256=SAN_ARGS_SHA,
        )

    # Oversized staged file -> BoundsExceededError
    big_file = staging / "big-obj"
    big_data = b"Z" * 2048
    big_file.write_bytes(big_data)
    with pytest.raises(BoundsExceededError):
        importer.import_object(
            run_id="run-1",
            owner_principal_id="alice",
            action_id="act-1",
            object_id="big-obj",
            expected_sha256=sha256_bytes(big_data),
            media_type="application/octet-stream",
            capture_complete=True,
            omission_reason=None,
            source_artifact_hashes=(),
            adapter_revision="adapter-1",
            sanitized_args_sha256=SAN_ARGS_SHA,
        )

    # Hash mismatch -> ContractViolationError (not imported!)
    with pytest.raises(ContractViolationError):
        importer.import_object(
            run_id="run-1",
            owner_principal_id="alice",
            action_id="act-1",
            object_id="obj-001",
            expected_sha256="f" * 64,
            media_type="text/plain",
            capture_complete=True,
            omission_reason=None,
            source_artifact_hashes=(),
            adapter_revision="adapter-1",
            sanitized_args_sha256=SAN_ARGS_SHA,
        )

    # Missing staged file -> EvidenceNotFoundError
    with pytest.raises(EvidenceNotFoundError):
        importer.import_object(
            run_id="run-1",
            owner_principal_id="alice",
            action_id="act-1",
            object_id="nonexistent-obj",
            expected_sha256="0" * 64,
            media_type="text/plain",
            capture_complete=True,
            omission_reason=None,
            source_artifact_hashes=(),
            adapter_revision="adapter-1",
            sanitized_args_sha256=SAN_ARGS_SHA,
        )

    # Windows junction / symlink escape blocked
    if sys.platform == "win32":
        import _winapi

        outside_dir = tmp_path / "outside_dir"
        outside_dir.mkdir()
        (outside_dir / "leak.txt").write_bytes(b"JUNC_SECRET")
        _winapi.CreateJunction(str(outside_dir), str(staging / "junc"))
        with pytest.raises(PathSecurityError):
            importer.import_object(
                run_id="run-1",
                owner_principal_id="alice",
                action_id="act-1",
                object_id="junc-leak",
                staging_relpath="junc/leak.txt",
                expected_sha256=sha256_bytes(b"JUNC_SECRET"),
                media_type="text/plain",
                capture_complete=True,
                omission_reason=None,
                source_artifact_hashes=(),
                adapter_revision="adapter-1",
                sanitized_args_sha256=SAN_ARGS_SHA,
            )

    try:
        os.symlink(outside, staging / "sym-leak")
    except (OSError, NotImplementedError):
        pass
    else:
        with pytest.raises(PathSecurityError):
            importer.import_object(
                run_id="run-1",
                owner_principal_id="alice",
                action_id="act-1",
                object_id="sym-leak",
                expected_sha256=sha256_bytes(b"SECRET_OUTSIDE"),
                media_type="text/plain",
                capture_complete=True,
                omission_reason=None,
                source_artifact_hashes=(),
                adapter_revision="adapter-1",
                sanitized_args_sha256=SAN_ARGS_SHA,
            )
