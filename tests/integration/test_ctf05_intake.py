"""Integration tests for CTF-05 bounded offline intake and archive-bomb defenses."""

from __future__ import annotations

import gzip
import io
import os
import stat
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

from ctf_mcp.contracts import (
    BoundsExceededError,
    BudgetSpec,
    ContractViolationError,
    PathSecurityError,
    RunMode,
    ScopeDeniedError,
    sha256_bytes,
)
from ctf_mcp.gateway import ArtifactIntakeService, IntakeLimits
from ctf_mcp.storage import Storage


def _seed_run(storage: Storage, *, run_id: str = "run-1", owner: str = "alice") -> None:
    spec = BudgetSpec()
    with storage.transaction() as conn:
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
                owner,
                "task-1",
                RunMode.OFFLINE_CTF.value,
                "scope-1",
                "{}",
                spec.model_dump_json(),
                spec.run_budget_seconds * 1000,
                spec.max_evidence_bytes_per_run,
                spec.max_tool_calls,
                "2026-11-13T00:00:00+00:00",
            ),
        )


def _make_zip_bytes(entries: list[tuple[str, bytes, int | None]]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, content, unix_mode in entries:
            zi = zipfile.ZipInfo(name)
            zi.compress_type = zipfile.ZIP_DEFLATED
            if unix_mode is not None:
                zi.external_attr = (unix_mode & 0xFFFF) << 16
            zf.writestr(zi, content)
    return buf.getvalue()


def test_ctf05_valid_intake_sha256_and_run_isolation(tmp_path: Path) -> None:
    storage = Storage(tmp_path / "harness.db")
    storage.initialize()
    _seed_run(storage, run_id="run-1", owner="alice")
    _seed_run(storage, run_id="run-2", owner="bob")
    _seed_run(storage, run_id="run-3", owner="alice")

    source_dir = tmp_path / "iso_mount"
    source_dir.mkdir()
    payload = b"\x7fELF\x02\x01\x01\x00" + b"synthetic-challenge-binary" * 10
    (source_dir / "samples").mkdir()
    (source_dir / "samples" / "chal.bin").write_bytes(payload)

    vault_dir = tmp_path / "private_vault"
    intake = ArtifactIntakeService(storage, vault_dir)

    record = intake.ingest_from_workspace(
        run_id="run-1",
        principal_id="alice",
        source_root=source_dir,
        rel_path="samples/chal.bin",
        media_type="application/octet-stream",
    )
    assert record.artifact_id.startswith("art_")
    assert record.sha256 == sha256_bytes(payload)
    assert record.byte_length == len(payload)
    assert "samples/chal.bin" not in record.artifact_id

    fetched = intake.get_artifact(run_id="run-1", principal_id="alice", artifact_id=record.artifact_id)
    assert fetched == record

    with intake.open_artifact(
        run_id="run-1", principal_id="alice", artifact_id=record.artifact_id
    ) as fh:
        assert fh.read() == payload

    resolved = intake.resolve_artifact_path(
        run_id="run-1", principal_id="alice", artifact_id=record.artifact_id
    )
    assert resolved.read_bytes() == payload

    # Cross-principal and cross-run access must fail
    with pytest.raises(ScopeDeniedError):
        intake.get_artifact(run_id="run-1", principal_id="bob", artifact_id=record.artifact_id)
    with pytest.raises(ScopeDeniedError):
        intake.get_artifact(run_id="run-2", principal_id="alice", artifact_id=record.artifact_id)
    with pytest.raises(ContractViolationError):
        intake.get_artifact(run_id="run-3", principal_id="alice", artifact_id=record.artifact_id)


def test_ctf05_blocks_traversal_symlinks_junctions_and_oversized_files(tmp_path: Path) -> None:
    storage = Storage(tmp_path / "harness.db")
    storage.initialize()
    _seed_run(storage, run_id="run-1", owner="alice")

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.bin").write_bytes(b"SECRET")

    source_dir = tmp_path / "iso_mount"
    source_dir.mkdir()
    (source_dir / "too_big.bin").write_bytes(b"A" * 2048)

    intake = ArtifactIntakeService(
        storage,
        tmp_path / "vault",
        limits=IntakeLimits(max_intake_bytes=1024),
    )

    # Traversal / absolute / Windows drive rejection
    for unsafe_path in ("../outside/secret.bin", "/etc/passwd", "C:\\outside\\secret.bin"):
        with pytest.raises(PathSecurityError):
            intake.ingest_from_workspace(
                run_id="run-1",
                principal_id="alice",
                source_root=source_dir,
                rel_path=unsafe_path,
            )

    # Windows NTFS junction rejection
    if sys.platform == "win32":
        import _winapi

        junc = source_dir / "junc"
        _winapi.CreateJunction(str(outside), str(junc))
        with pytest.raises(PathSecurityError):
            intake.ingest_from_workspace(
                run_id="run-1",
                principal_id="alice",
                source_root=source_dir,
                rel_path="junc/secret.bin",
            )

    # Symlink rejection (when OS permits symlink creation)
    sym = source_dir / "sym.bin"
    try:
        os.symlink(outside / "secret.bin", sym)
    except (OSError, NotImplementedError):
        pass
    else:
        with pytest.raises(PathSecurityError):
            intake.ingest_from_workspace(
                run_id="run-1",
                principal_id="alice",
                source_root=source_dir,
                rel_path="sym.bin",
            )

    # Oversized file rejection
    with pytest.raises(BoundsExceededError):
        intake.ingest_from_workspace(
            run_id="run-1",
            principal_id="alice",
            source_root=source_dir,
            rel_path="too_big.bin",
        )

    assert intake.list_artifacts(run_id="run-1", principal_id="alice") == []


def test_ctf05_archive_bomb_depth_entries_bytes_ratio_and_safe_zip(tmp_path: Path) -> None:
    storage = Storage(tmp_path / "harness.db")
    storage.initialize()
    _seed_run(storage, run_id="run-1", owner="alice")

    limits = IntakeLimits(
        max_intake_bytes=1024 * 1024,
        max_archive_depth=2,
        max_archive_entries=5,
        max_decompressed_bytes=16384,
        max_expansion_ratio=15.0,
        ratio_grace_bytes=2048,
    )
    intake = ArtifactIntakeService(storage, tmp_path / "vault", limits=limits)

    # 1. Valid benign ZIP passes
    safe_zip = _make_zip_bytes(
        [
            ("readme.txt", b"hello challenge\n", None),
            ("data.bin", os.urandom(256), None),
        ]
    )
    rec = intake.ingest_bytes(
        run_id="run-1",
        principal_id="alice",
        data=safe_zip,
        media_type="application/zip",
        filename_hint="chal.zip",
    )
    assert rec.sha256 == sha256_bytes(safe_zip)

    # 2. Decompressed bytes limit exceeded
    over_bytes_zip = _make_zip_bytes([("big.bin", os.urandom(20000), None)])
    with pytest.raises(BoundsExceededError):
        intake.ingest_bytes(
            run_id="run-1",
            principal_id="alice",
            data=over_bytes_zip,
            media_type="application/zip",
        )

    # 3. Expansion ratio bomb (>15x on >=2048 B)
    ratio_bomb_zip = _make_zip_bytes([("zeros.bin", b"\x00" * 12000, None)])
    with pytest.raises(BoundsExceededError):
        intake.ingest_bytes(
            run_id="run-1",
            principal_id="alice",
            data=ratio_bomb_zip,
            media_type="application/zip",
        )

    # 4. Entry count limit exceeded (>5 entries)
    many_entries_zip = _make_zip_bytes([(f"f{i}.txt", b"hi", None) for i in range(6)])
    with pytest.raises(BoundsExceededError):
        intake.ingest_bytes(
            run_id="run-1",
            principal_id="alice",
            data=many_entries_zip,
            media_type="application/zip",
        )

    # 5. Nesting depth limit exceeded (depth 3 > max_archive_depth=2)
    layer = _make_zip_bytes([("leaf.txt", b"leaf", None)])
    for lvl in range(3):
        layer = _make_zip_bytes([(f"nested_{lvl}.zip", layer, None)])
    with pytest.raises(BoundsExceededError):
        intake.ingest_bytes(
            run_id="run-1",
            principal_id="alice",
            data=layer,
            media_type="application/zip",
        )

    # 6. GZIP bomb exceeding decompressed bytes / ratio
    gz_bomb = gzip.compress(b"\x00" * 20000)
    with pytest.raises(BoundsExceededError):
        intake.ingest_bytes(
            run_id="run-1",
            principal_id="alice",
            data=gz_bomb,
            media_type="application/gzip",
        )

    # 7. Archive member traversal & symlink rejection
    traversal_zip = _make_zip_bytes([("../evil.txt", b"x", None)])
    with pytest.raises(PathSecurityError):
        intake.ingest_bytes(
            run_id="run-1",
            principal_id="alice",
            data=traversal_zip,
            media_type="application/zip",
        )

    symlink_zip = _make_zip_bytes([("link.txt", b"/etc/passwd", stat.S_IFLNK | 0o777)])
    with pytest.raises(PathSecurityError):
        intake.ingest_bytes(
            run_id="run-1",
            principal_id="alice",
            data=symlink_zip,
            media_type="application/zip",
        )

    # TAR symlink rejection
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w") as tf:
        ti = tarfile.TarInfo("sym_escape")
        ti.type = tarfile.SYMTYPE
        ti.linkname = "../../secret"
        tf.addfile(ti)
    with pytest.raises(PathSecurityError):
        intake.ingest_bytes(
            run_id="run-1",
            principal_id="alice",
            data=tar_buf.getvalue(),
            media_type="application/x-tar",
        )
