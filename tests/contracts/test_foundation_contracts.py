"""Contract tests for P1 foundation (contracts, config, storage, and fs_guard)."""

from __future__ import annotations

import ast
import base64
import json
import os
import sqlite3
import stat
import sys
import tomllib
from pathlib import Path
from types import SimpleNamespace

import jsonschema
import pytest
from pydantic import ValidationError

from ctf_mcp.config import (
    get_cursor_hmac_key,
    load_config_file,
    load_runtime_settings,
)
from ctf_mcp.contracts import (
    ActionLifecycleState,
    BoundsExceededError,
    CapabilityDescriptor,
    CapabilityLimits,
    ConfigurationError,
    ContractViolationError,
    EnvelopeStatus,
    ErrorDetail,
    EvidencePage,
    ExecutionClass,
    InvalidStateTransitionError,
    PageEncoding,
    PathSecurityError,
    ProvenanceInfo,
    ResultEnvelope,
    RunMode,
    ScopePolicy,
    TransportMode,
    UsageMetrics,
    canonical_digest,
    lifecycle_to_envelope_status,
    sha256_bytes,
    validate_action_transition,
)
from ctf_mcp.fs_guard import safe_open_read, safe_read_bounded, safe_write_atomic
from ctf_mcp.storage import REQUIRED_TABLES, Storage

REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = REPO_ROOT / "schemas" / "evidence-page.schema.json"
SYNTHETIC_PAGE_PATH = REPO_ROOT / "examples" / "evidence-page.synthetic.json"
EXAMPLE_CONFIG_PATH = REPO_ROOT / "configs" / "offline-pilot.example.json"


# ---------------------------------------------------------------------------
# 1. State Transitions & ResultEnvelope Mapping (docs/11 section 2)
# ---------------------------------------------------------------------------


def test_action_lifecycle_valid_and_invalid_transitions() -> None:
    validate_action_transition(ActionLifecycleState.PROPOSED, ActionLifecycleState.RESERVED)
    validate_action_transition(ActionLifecycleState.RESERVED, ActionLifecycleState.RUNNING)
    validate_action_transition(
        ActionLifecycleState.RUNNING, ActionLifecycleState.RECONCILIATION_REQUIRED
    )
    validate_action_transition(
        ActionLifecycleState.RECONCILIATION_REQUIRED, ActionLifecycleState.FAILED
    )

    with pytest.raises(InvalidStateTransitionError):
        validate_action_transition(ActionLifecycleState.PROPOSED, ActionLifecycleState.COMPLETED)

    with pytest.raises(InvalidStateTransitionError):
        validate_action_transition(ActionLifecycleState.COMPLETED, ActionLifecycleState.RUNNING)

    with pytest.raises(InvalidStateTransitionError):
        validate_action_transition(
            ActionLifecycleState.RECONCILIATION_REQUIRED, ActionLifecycleState.RESERVED
        )


def test_lifecycle_to_envelope_status_mapping() -> None:
    assert (
        lifecycle_to_envelope_status(ActionLifecycleState.COMPLETED, has_tool_receipt=True)
        == EnvelopeStatus.OK
    )
    assert lifecycle_to_envelope_status(ActionLifecycleState.FAILED) == EnvelopeStatus.TOOL_ERROR
    assert lifecycle_to_envelope_status(ActionLifecycleState.DENIED) == EnvelopeStatus.DENIED
    assert (
        lifecycle_to_envelope_status(
            ActionLifecycleState.EXPIRED, expiry_reason="scope expired before launch"
        )
        == EnvelopeStatus.DENIED
    )
    assert lifecycle_to_envelope_status(ActionLifecycleState.PARTIAL) == EnvelopeStatus.PARTIAL
    assert lifecycle_to_envelope_status(ActionLifecycleState.TIMEOUT) == EnvelopeStatus.TIMEOUT
    assert lifecycle_to_envelope_status(ActionLifecycleState.CANCELLED) == EnvelopeStatus.CANCELLED

    with pytest.raises(InvalidStateTransitionError):
        lifecycle_to_envelope_status(ActionLifecycleState.RECONCILIATION_REQUIRED)

    with pytest.raises(InvalidStateTransitionError):
        lifecycle_to_envelope_status(ActionLifecycleState.RUNNING)

    with pytest.raises(ContractViolationError):
        lifecycle_to_envelope_status(ActionLifecycleState.COMPLETED, has_tool_receipt=False)

    with pytest.raises(ContractViolationError):
        lifecycle_to_envelope_status(ActionLifecycleState.EXPIRED)


def test_result_envelope_and_scope_invariants() -> None:
    # tool_error cannot pretend to be error-free
    with pytest.raises(ValidationError):
        ResultEnvelope(
            run_id="r1",
            action_id="a1",
            status=EnvelopeStatus.TOOL_ERROR,
            summary="failed",
            usage=UsageMetrics(wall_ms=10, output_bytes=0),
            provenance=ProvenanceInfo(adapter_revision="abc", scope_revision="s1"),
        )

    # Extra unknown fields are rejected
    with pytest.raises(ValidationError):
        ResultEnvelope.model_validate(
            {
                "run_id": "r1",
                "action_id": "a1",
                "status": "ok",
                "summary": "ok",
                "usage": {"wall_ms": 10, "output_bytes": 0},
                "provenance": {"adapter_revision": "abc", "scope_revision": "s1"},
                "unexpected": 123,
            }
        )

    # offline_ctf rejects network / submission capabilities
    with pytest.raises(ValidationError):
        ScopePolicy(
            scope_revision="s1",
            scope_sha256="0" * 64,
            mode=RunMode.OFFLINE_CTF,
            task_id="t1",
            authorization_reference="local-fixture",
            allowed_execution_classes=(ExecutionClass.NETWORK,),
            allowed_capabilities=("artifact.inspect",),
        )


def test_capability_descriptor_and_canonical_digest() -> None:
    desc = CapabilityDescriptor(
        name="artifact.inspect",
        adapter_id="static-core",
        adapter_commit="0123456789abcdef",
        dependency_lock_sha256="a" * 64,
        descriptor_sha256="b" * 64,
        operations=("header", "strings"),
        arg_schema={"type": "object", "required": ["artifact_id"]},
        execution_classes=(ExecutionClass.STATIC,),
        required_scope={"mode": "offline_ctf"},
        limits=CapabilityLimits(timeout_seconds=60, max_output_bytes=65536, max_decode_bytes=4096),
    )
    assert desc.adapter_commit == "0123456789abcdef"
    assert canonical_digest({"b": 2, "a": 1}) == canonical_digest({"a": 1, "b": 2})


# ---------------------------------------------------------------------------
# 2. EvidencePage Schema & Runtime Semantic Invariants
# ---------------------------------------------------------------------------


def test_synthetic_evidence_page_matches_schema_and_contract() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    sample = json.loads(SYNTHETIC_PAGE_PATH.read_text(encoding="utf-8"))

    validator = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())
    validator.validate(sample)

    page = EvidencePage.model_validate(sample)
    assert page.view_sha256 == sha256_bytes(page.content.encode("utf-8"))
    assert page.view_bytes == 44


def test_evidence_page_semantic_rejections() -> None:
    base = {
        "schema_version": "evidence-page/1",
        "run_id": "r1",
        "evidence_id": "e1",
        "view_sha256": "a" * 64,
        "view_revision": "v1",
        "encoding": "utf-8",
        "offset_bytes": 0,
        "next_offset_bytes": 5,
        "view_bytes": 10,
        "content": "hello",
        "capture_complete": True,
        "omission_reason": None,
        "next_cursor": "cursor-1",
    }
    EvidencePage.model_validate(base)

    # Empty view terminal page is allowed
    EvidencePage.model_validate(
        {
            **base,
            "offset_bytes": 0,
            "next_offset_bytes": 0,
            "view_bytes": 0,
            "content": "",
            "next_cursor": None,
        }
    )

    # Base64 page byte span matches decoded bytes
    raw = b"\x00\x01\x02\x03"
    EvidencePage.model_validate(
        {
            **base,
            "encoding": PageEncoding.BASE64,
            "offset_bytes": 0,
            "next_offset_bytes": len(raw),
            "view_bytes": len(raw),
            "content": base64.b64encode(raw).decode("ascii"),
            "next_cursor": None,
        }
    )

    # Incomplete capture requires omission_reason
    with pytest.raises(ValidationError):
        EvidencePage.model_validate({**base, "capture_complete": False, "omission_reason": None})

    # Complete capture forbids omission_reason
    with pytest.raises(ValidationError):
        EvidencePage.model_validate({**base, "capture_complete": True, "omission_reason": "x"})

    # Non-terminal page with zero progress must fail
    with pytest.raises(ValidationError):
        EvidencePage.model_validate({**base, "next_offset_bytes": 0, "content": ""})

    # Byte span mismatch fails
    with pytest.raises(ValidationError):
        EvidencePage.model_validate({**base, "content": "hello!"})

    # Oversized >4000 chars fails
    with pytest.raises(ValidationError):
        EvidencePage.model_validate(
            {
                **base,
                "offset_bytes": 0,
                "next_offset_bytes": 4001,
                "view_bytes": 4001,
                "content": "x" * 4001,
                "next_cursor": None,
            }
        )


# ---------------------------------------------------------------------------
# 3. Configuration Fail-Closed Guards
# ---------------------------------------------------------------------------


def test_config_rejects_non_executable_example_and_unsafe_flags(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="executable"):
        load_config_file(EXAMPLE_CONFIG_PATH)

    valid_data = json.loads(EXAMPLE_CONFIG_PATH.read_text(encoding="utf-8"))
    valid_data["executable"] = True
    good_cfg_path = tmp_path / "good.json"
    good_cfg_path.write_text(json.dumps(valid_data), encoding="utf-8")
    loaded = load_config_file(good_cfg_path)
    assert loaded.executable is True
    assert loaded.profile == RunMode.OFFLINE_CTF

    # arbitrary_shell=True must be rejected
    bad_shell = dict(valid_data)
    bad_shell["execution"] = {**valid_data["execution"], "arbitrary_shell": True}
    bad_cfg_path = tmp_path / "bad_shell.json"
    bad_cfg_path.write_text(json.dumps(bad_shell), encoding="utf-8")
    with pytest.raises(ConfigurationError):
        load_config_file(bad_cfg_path)


def test_cursor_hmac_key_and_runtime_settings() -> None:
    with pytest.raises(ConfigurationError):
        get_cursor_hmac_key({})

    with pytest.raises(ConfigurationError):
        get_cursor_hmac_key({"CTF_MCP_CURSOR_HMAC_KEY": "CHANGE_ME_SECRET"})

    with pytest.raises(ConfigurationError):
        get_cursor_hmac_key({"CTF_MCP_CURSOR_HMAC_KEY": "short-key"})

    key_hex = "0123456789abcdef" * 2
    assert len(get_cursor_hmac_key({"CTF_MCP_CURSOR_HMAC_KEY": key_hex})) == 16
    assert len(get_cursor_hmac_key({}, allow_ephemeral_dev_key=True)) == 32

    stdio_settings = load_runtime_settings({})
    assert stdio_settings.transport == TransportMode.STDIO

    with pytest.raises(ConfigurationError):
        load_runtime_settings({"CTF_MCP_TRANSPORT": "streamable-http"})

    http_settings = load_runtime_settings(
        {"CTF_MCP_TRANSPORT": "streamable-http", "CTF_MCP_AUTH_TOKEN": "real-local-secret-token"}
    )
    assert http_settings.transport == TransportMode.STREAMABLE_HTTP


# ---------------------------------------------------------------------------
# 4. Storage SQLite WAL, Constraints & Atomic Transactions
# ---------------------------------------------------------------------------


def test_storage_wal_tables_fencing_and_idempotency_unique_constraint(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError):
        Storage(":memory:")

    db_path = tmp_path / "state" / "harness.db"
    storage = Storage(db_path)
    storage.initialize()

    assert storage.journal_mode() == "wal"
    assert REQUIRED_TABLES.issubset(storage.table_names())

    with storage.transaction() as conn:
        t1 = storage.next_fencing_token(conn, "guest-1")
        t2 = storage.next_fencing_token(conn, "guest-1")
        assert (t1, t2) == (1, 2)

        conn.execute(
            """
            INSERT INTO runs (
                run_id, owner_principal_id, task_id, mode, scope_revision,
                manifest_json, budget_spec_json, remaining_ms, remaining_bytes,
                remaining_calls, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            ("run-1", "alice", "task-1", "offline_ctf", "s1", "{}", "{}", 1000, 1000, 10, "2026-11-13T00:00:00Z"),
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
                "act-1", "alice", "run-1", "req-1", 1,
                "artifact.inspect", "header", "rev1", "a" * 64,
                "{}", "s1", "reserved", 100, 100,
                "2026-11-13T00:00:00Z", "2026-11-13T00:00:00Z",
            ),
        )

    # Duplicate (principal_id, run_id, request_id) must fail at DB layer
    with pytest.raises(sqlite3.IntegrityError):
        with storage.transaction() as conn:
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
                    "act-2", "alice", "run-1", "req-1", 1,
                    "artifact.inspect", "header", "rev1", "b" * 64,
                    "{}", "s1", "reserved", 100, 100,
                    "2026-11-13T00:00:00Z", "2026-11-13T00:00:00Z",
                ),
            )

    # Exception inside transaction rolls back cleanly
    with pytest.raises(RuntimeError):
        with storage.transaction() as conn:
            storage.next_fencing_token(conn, "guest-1")
            raise RuntimeError("simulated crash")

    with storage.transaction() as conn:
        t3 = storage.next_fencing_token(conn, "guest-1")
        assert t3 == 3


# ---------------------------------------------------------------------------
# 5. Filesystem Guard (Path Traversal, Symlink/Reparse Point, Bounds)
# ---------------------------------------------------------------------------


def test_fs_guard_safe_rw_traversal_and_bounds(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()
    outside = tmp_path / "secret.txt"
    outside.write_bytes(b"TOP_SECRET")

    written = safe_write_atomic(ws, "sub/data.bin", b"hello-world", max_bytes=64)
    assert written == ws / "sub" / "data.bin"

    # overwrite=False blocks overwrite
    with pytest.raises(PathSecurityError):
        safe_write_atomic(ws, "sub/data.bin", b"new", overwrite=False)

    safe_write_atomic(ws, "sub/data.bin", b"0123456789", overwrite=True)

    with safe_open_read(ws, "sub/data.bin", max_bytes=10) as fh:
        assert fh.read() == b"0123456789"

    with pytest.raises(BoundsExceededError):
        safe_read_bounded(ws, "sub/data.bin", max_bytes=5, allow_truncate=False)

    trunc = safe_read_bounded(ws, "sub/data.bin", max_bytes=5, allow_truncate=True)
    assert trunc.data == b"01234"
    assert trunc.truncated is True

    for unsafe in (
        "../secret.txt",
        "..\\secret.txt",
        "/etc/passwd",
        "C:\\secret.txt",
        "a:stream",
        "a\x00b",
        "CON",
        "sub/NUL.txt",
        "sub/bad.",
    ):
        with pytest.raises(PathSecurityError):
            safe_open_read(ws, unsafe)


def test_fs_guard_blocks_symlinks_and_windows_junctions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()
    outside_dir = tmp_path / "outside_dir"
    outside_dir.mkdir()
    outside_file = outside_dir / "leak.txt"
    outside_file.write_bytes(b"SECRET")

    if sys.platform == "win32":
        import _winapi

        junction = ws / "junc"
        _winapi.CreateJunction(str(outside_dir), str(junction))
        with pytest.raises(PathSecurityError):
            safe_open_read(ws, "junc/leak.txt")
        with pytest.raises(PathSecurityError):
            safe_write_atomic(ws, "junc/pwn.txt", b"x")

    link_path = ws / "sym.txt"
    try:
        os.symlink(outside_file, link_path)
    except (OSError, NotImplementedError):
        pass
    else:
        with pytest.raises(PathSecurityError):
            safe_open_read(ws, "sym.txt")

    # Also verify symlink/reparse detection deterministically via lstat simulation
    safe_write_atomic(ws, "normal.txt", b"ok")
    real_lstat = os.lstat

    def fake_lstat(path: str | os.PathLike[str]) -> os.stat_result | SimpleNamespace:
        res = real_lstat(path)
        if Path(path).name == "normal.txt":
            return SimpleNamespace(
                st_mode=stat.S_IFLNK | 0o777,
                st_dev=res.st_dev,
                st_ino=res.st_ino,
                st_file_attributes=getattr(res, "st_file_attributes", 0),
            )
        return res

    monkeypatch.setattr(os, "lstat", fake_lstat)
    with pytest.raises(PathSecurityError):
        safe_open_read(ws, "normal.txt")


def test_pyproject_dependencies_and_no_forbidden_exec_patterns() -> None:
    data = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    deps = data["project"]["dependencies"]
    assert "fastmcp==4.1.8" in deps
    assert "mcp==2.3.0" in deps
    assert "pydantic==2.14.3" in deps
    assert "jsonschema[format-nongpl]==4.26.0" in deps
    assert not any("jsonschema[format]" in d for d in deps)
    assert data["project"]["optional-dependencies"]["dev"] == ["pytest==9.2.0"]

    import fastmcp  # noqa: F401
    import mcp  # noqa: F401

    for py_file in (REPO_ROOT / "src" / "ctf_mcp").rglob("*.py"):
        source = py_file.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(py_file))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
                    raise AssertionError(f"Forbidden call {node.func.id} in {py_file}")
                if (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr == "system"
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "os"
                ):
                    raise AssertionError(f"Forbidden os.system call in {py_file}")
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        raise AssertionError(f"Forbidden shell=True in {py_file}")
