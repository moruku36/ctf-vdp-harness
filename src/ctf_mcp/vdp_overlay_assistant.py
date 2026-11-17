"""Assisted overlay scanning, selector-role mapping, and fail-closed registration.

Provides non-destructive dry-run preview (default) and explicit opt-in
registration for synthetic read-only VDP test overlays while preserving
SHA-256 pinning, ``network_mode="none"`` container isolation, bounded
resource caps, and immutability of existing overlay bundles, selector roles,
runs, and evidence.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import stat
import sys
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ctf_mcp.adapters.runner import SubprocessRunner
from ctf_mcp.adapters.vdp_product_test import (
    DEFAULT_VDP_TEST_MAX_CPUS,
    DEFAULT_VDP_TEST_MAX_MEMORY_MB,
    DEFAULT_VDP_TEST_MAX_OUTPUT_BYTES,
    DEFAULT_VDP_TEST_TIMEOUT_SECONDS,
    VALID_SELECTOR_ROLES,
    VdpOverlaySpec,
    VdpTargetProfile,
    compute_vdp_profile_digest,
    load_registered_vdp_profiles,
    run_vdp_environment_check,
    save_registered_vdp_profile,
    validate_vdp_profile_registration,
    validate_vdp_selector_format,
)
from ctf_mcp.config import load_runtime_settings
from ctf_mcp.contracts import (
    ConfigurationError,
    ContractViolationError,
    PathSecurityError,
    ScopeDeniedError,
)
from ctf_mcp.fs_guard import _is_reparse_or_symlink

OVERLAY_ASSISTANT_COMMAND = "register-vdp-overlay"
DEFAULT_OVERLAY_CONTAINER_TARGET = "/src/vdp-test-overlay"
_MAX_OVERLAY_FILE_BYTES = 256 * 1024
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")
_REV_SUFFIX_RE = re.compile(r"^(?P<prefix>.*?)(?:^|-)r(?P<num>\d+)$")
_SENSITIVE_MARKER_RE = re.compile(
    r"(?:SYNTHETIC_SECRET_[A-Za-z0-9_=-]*|CTF_SENSITIVE_MARKER[A-Za-z0-9_=-]*|"
    r"(?:flag|ctf)\{[^}\r\n]*\}|-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----)",
    re.IGNORECASE,
)

SELECTOR_ROLE_PREFIXES: tuple[tuple[str, str], ...] = (
    ("test_positive_", "positive_control"),
    ("test_defense_", "defense_check"),
    ("test_anomaly_", "anomaly_repro"),
    ("test_env_", "env_check"),
)

ALLOWED_CONFIG_DIFF_KEYS: frozenset[str] = frozenset(
    {
        "image_ref",
        "expected_image_digest",
        "expected_source_commit",
        "checkout_dir",
        "expires_at",
        "profile_revision",
        "max_cpus",
        "max_memory_mb",
        "max_timeout_seconds",
        "max_output_bytes",
        "network_mode",
        "notes",
    }
)

_INT_CONFIG_KEYS: frozenset[str] = frozenset(
    {"max_cpus", "max_memory_mb", "max_timeout_seconds", "max_output_bytes"}
)


def _next_profile_revision(base_revision: str | None) -> str:
    if not base_revision:
        return "r1"
    match = _REV_SUFFIX_RE.match(base_revision.strip())
    if match:
        prefix = match.group("prefix")
        next_num = int(match.group("num")) + 1
        return f"{prefix}-r{next_num}" if prefix else f"r{next_num}"
    return f"{base_revision.strip()}-r2"


def _parse_iso_datetime(value: datetime | str | None) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    cleaned = str(value).strip()
    if not cleaned:
        return None
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"
    dt = datetime.fromisoformat(cleaned)
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)


def _validate_identifier(value: str, *, label: str) -> str:
    cleaned = str(value).strip()
    if not _NAME_RE.fullmatch(cleaned):
        raise ContractViolationError(
            f"Invalid {label} {value!r}: expected ^[a-z0-9][a-z0-9._-]{{1,63}}$."
        )
    return cleaned


def _validate_int_cap(
    value: Any,
    *,
    name: str,
    minimum: int,
    maximum: int,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ContractViolationError(f"{name} must be an integer, got {value!r}.")
    if value < minimum or value > maximum:
        raise ContractViolationError(
            f"{name} must be between {minimum} and {maximum} to preserve resource caps, got {value}."
        )
    return value


def _validate_overlay_dir_path(overlay_dir: str | Path) -> Path:
    raw = os.fspath(overlay_dir)
    if not isinstance(raw, str) or not raw.strip():
        raise PathSecurityError("overlay_dir must be a non-empty directory path.")
    if "\x00" in raw:
        raise PathSecurityError("overlay_dir contains a null byte.")
    path = Path(raw)
    if ".." in path.parts:
        raise PathSecurityError(f"Path traversal '..' is forbidden in overlay_dir {raw!r}.")
    try:
        st = os.lstat(path)
    except FileNotFoundError as exc:
        raise ContractViolationError(f"Overlay directory {raw!r} does not exist.") from exc
    except OSError as exc:
        raise PathSecurityError(f"Unable to inspect overlay directory {raw!r}: {exc}") from exc

    if _is_reparse_or_symlink(st) or not stat.S_ISDIR(st.st_mode):
        raise PathSecurityError(
            f"Overlay directory {raw!r} must be a regular non-symlink directory."
        )

    real_dir = Path(os.path.realpath(path, strict=True))
    real_st = os.lstat(real_dir)
    if _is_reparse_or_symlink(real_st) or not stat.S_ISDIR(real_st.st_mode):
        raise PathSecurityError(f"Resolved overlay directory {real_dir!s} must not be a symlink.")
    return real_dir


def _ensure_not_vault_protected_dir(overlay_real_dir: Path, vault_root: str | Path | None) -> None:
    if vault_root is None:
        return
    vault_path = Path(vault_root)
    if vault_path.exists():
        vault_st = os.lstat(vault_path)
        if _is_reparse_or_symlink(vault_st) or not stat.S_ISDIR(vault_st.st_mode):
            raise PathSecurityError(f"vault_root {vault_root!s} must be a non-symlink directory.")
        vault_real = Path(os.path.realpath(vault_path, strict=True))
    else:
        vault_real = vault_path.resolve()

    for sub in ("_vdp", "blobs", "_exports", "artifacts"):
        protected = vault_real / sub
        if overlay_real_dir == protected or protected in overlay_real_dir.parents:
            raise PathSecurityError(
                f"Overlay directory cannot reside inside protected vault path {protected!s}."
            )


def _discover_pytest_selectors_in_source(
    source: str,
    *,
    filename: str,
    container_target: str,
) -> list[tuple[str, str]]:
    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError as exc:
        raise ContractViolationError(
            f"Failed to parse overlay test file {filename!r}: {exc.msg} (line {exc.lineno})."
        ) from exc

    discovered: list[tuple[str, str]] = []
    seen: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
            sel = validate_vdp_selector_format(f"{container_target}/{filename}::{node.name}")
            if sel not in seen:
                seen.add(sel)
                discovered.append((sel, node.name))
        elif isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
            for member in node.body:
                if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)) and member.name.startswith("test_"):
                    sel = validate_vdp_selector_format(
                        f"{container_target}/{filename}::{node.name}::{member.name}"
                    )
                    if sel not in seen:
                        seen.add(sel)
                        discovered.append((sel, member.name))
    return discovered


def scan_overlay_directory(
    overlay_dir: str | Path,
    *,
    container_target: str = DEFAULT_OVERLAY_CONTAINER_TARGET,
) -> dict[str, Any]:
    """Scan an overlay directory cleanly, computing SHA-256s and AST-discovered pytest selectors.

    Rejects symlinks, Windows reparse points, subdirectories/non-regular entries,
    traversal filenames, oversized files (>256 KiB), sensitive marker patterns,
    and unparseable ``test_*.py`` files.
    """
    if container_target != DEFAULT_OVERLAY_CONTAINER_TARGET:
        raise ContractViolationError(
            f"Overlay container_target must be {DEFAULT_OVERLAY_CONTAINER_TARGET!r}, got {container_target!r}."
        )
    real_dir = _validate_overlay_dir_path(overlay_dir)

    allowed_files: dict[str, str] = {}
    discovered_items: list[dict[str, str]] = []
    test_files: list[str] = []

    entries = sorted(os.scandir(real_dir), key=lambda e: e.name)
    for entry in entries:
        fname = entry.name
        if not fname or "/" in fname or "\\" in fname or ".." in fname or "\x00" in fname:
            raise PathSecurityError(f"Unsafe overlay filename {fname!r}.")
        entry_path = real_dir / fname
        est = os.lstat(entry_path)
        if _is_reparse_or_symlink(est):
            raise ScopeDeniedError(
                f"Overlay entry {fname!r} cannot be a symlink or reparse point.",
                code="overlay_integrity_failed",
            )
        if not stat.S_ISREG(est.st_mode):
            raise ScopeDeniedError(
                f"Overlay entry {fname!r} must be a regular file (subdirectories/special files are forbidden).",
                code="overlay_integrity_failed",
            )

        digest = hashlib.sha256()
        chunks: list[bytes] = []
        total = 0
        with open(entry_path, "rb") as handle:
            while chunk := handle.read(65_536):
                total += len(chunk)
                if total > _MAX_OVERLAY_FILE_BYTES:
                    raise ScopeDeniedError(
                        f"Overlay file {fname!r} exceeds bounded overlay size ({_MAX_OVERLAY_FILE_BYTES} bytes).",
                        code="overlay_integrity_failed",
                    )
                digest.update(chunk)
                chunks.append(chunk)

        raw_bytes = b"".join(chunks)
        text_preview = raw_bytes.decode("utf-8", errors="replace")
        if _SENSITIVE_MARKER_RE.search(text_preview):
            raise ScopeDeniedError(
                f"Overlay file {fname!r} contains forbidden sensitive markers.",
                code="overlay_integrity_failed",
            )
        allowed_files[fname] = digest.hexdigest()

        if fname.startswith("test_") and fname.endswith(".py"):
            try:
                source_text = raw_bytes.decode("utf-8", errors="strict")
            except UnicodeDecodeError as exc:
                raise ContractViolationError(
                    f"Overlay test file {fname!r} must be valid UTF-8: {exc}"
                ) from exc
            test_files.append(fname)
            for sel, func_name in _discover_pytest_selectors_in_source(
                source_text,
                filename=fname,
                container_target=container_target,
            ):
                discovered_items.append(
                    {
                        "selector": sel,
                        "function_name": func_name,
                        "file": fname,
                    }
                )

    if not allowed_files:
        raise ContractViolationError("Overlay directory contains no regular files.")
    if not discovered_items:
        raise ContractViolationError(
            "No pytest test selectors (test_*.py with TestClass::test_* or top-level test_*) "
            f"discovered in overlay directory {real_dir!s}."
        )

    return {
        "host_dir": real_dir,
        "container_target": container_target,
        "allowed_files": allowed_files,
        "test_files": test_files,
        "discovered_items": discovered_items,
        "discovered_selectors": [item["selector"] for item in discovered_items],
    }


def infer_selector_role(
    selector: str,
    *,
    explicit_roles: Mapping[str, str] | None = None,
) -> str:
    """Resolve a selector's canonical role via explicit mapping or naming prefix heuristic.

    Fails closed with ``ContractViolationError`` when no explicit override exists
    and the test function name does not match a recognized prefix.
    """
    cleaned_sel = validate_vdp_selector_format(selector)
    if explicit_roles and cleaned_sel in explicit_roles:
        role = str(explicit_roles[cleaned_sel]).strip()
        if role not in VALID_SELECTOR_ROLES:
            raise ContractViolationError(
                f"Invalid selector role {role!r} for {cleaned_sel!r}; expected one of {VALID_SELECTOR_ROLES}."
            )
        return role

    func_name = cleaned_sel.rsplit("::", 1)[-1]
    for prefix, mapped_role in SELECTOR_ROLE_PREFIXES:
        if func_name.startswith(prefix):
            return mapped_role

    raise ContractViolationError(
        f"Cannot determine selector role for {cleaned_sel!r}: function {func_name!r} does not start "
        "with a recognized role prefix (test_positive_*, test_defense_*, test_anomaly_*, test_env_*) "
        "and no explicit role override was provided."
    )


def _normalize_config_diffs(
    config_diffs: Mapping[str, Any] | None,
    *,
    explicit_values: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Validate requested config_diffs, enforcing network_mode='none' and resource caps."""
    requested: dict[str, Any] = {}
    if config_diffs is not None:
        if not isinstance(config_diffs, Mapping):
            raise ContractViolationError("config_diffs must be a mapping.")
        for raw_key, raw_val in config_diffs.items():
            key = str(raw_key).strip()
            if key not in ALLOWED_CONFIG_DIFF_KEYS:
                raise ContractViolationError(
                    f"Unsupported or unsafe config_diffs key {raw_key!r}; "
                    f"allowed keys: {sorted(ALLOWED_CONFIG_DIFF_KEYS)}."
                )
            if key == "network_mode":
                if str(raw_val).strip() != "none":
                    raise ContractViolationError(
                        f"network_mode must remain 'none' for isolated VDP tests, got {raw_val!r}."
                    )
                requested["network_mode"] = "none"
            elif key in _INT_CONFIG_KEYS:
                requested[key] = raw_val
            elif key == "checkout_dir":
                requested[key] = Path(raw_val) if raw_val is not None else None
            elif key == "expires_at":
                requested[key] = _parse_iso_datetime(raw_val)
            elif key == "notes":
                requested[key] = str(raw_val).strip() if raw_val is not None else None
            else:
                requested[key] = str(raw_val).strip() if raw_val is not None else None

    merged: dict[str, Any] = dict(requested)
    for key, val in explicit_values.items():
        if val is None:
            continue
        if key in merged and merged[key] != val:
            raise ContractViolationError(
                f"Conflicting values supplied for {key!r} between explicit argument and config_diffs."
            )
        merged[key] = val

    if merged.get("network_mode", "none") != "none":
        raise ContractViolationError("network_mode must remain 'none'.")

    return merged, requested


def _compute_registration_diff(
    reference: VdpTargetProfile | None,
    candidate: VdpTargetProfile,
    *,
    requested_config_diffs: Mapping[str, Any],
) -> dict[str, Any]:
    """Compute pre-registration diff and detect any overwrite/modification conflicts."""
    cand_roles = candidate.resolve_selector_roles()

    if reference is None:
        added_selectors = [
            {"selector": sel, "role": cand_roles.get(sel, "unassigned")}
            for sel in candidate.allowed_test_selectors
        ]
        removed_selectors: list[dict[str, str]] = []
        role_changes: list[dict[str, str]] = []
        added_overlays = {
            k: {
                "container_target": v.container_target,
                "allowed_files": dict(v.allowed_files),
            }
            for k, v in sorted(candidate.allowed_overlays.items())
        }
        updated_overlays: dict[str, Any] = {}
        removed_overlays: dict[str, Any] = {}
        changed_fields: dict[str, Any] = {
            "image_ref": {"before": None, "after": candidate.image_ref},
            "expected_image_digest": {"before": None, "after": candidate.expected_image_digest},
            "expected_source_commit": {"before": None, "after": candidate.expected_source_commit},
        }
    else:
        ref_set = set(reference.allowed_test_selectors)
        cand_set = set(candidate.allowed_test_selectors)
        ref_roles = reference.resolve_selector_roles()

        added_selectors = [
            {"selector": s, "role": cand_roles.get(s, "unassigned")}
            for s in candidate.allowed_test_selectors
            if s not in ref_set
        ]
        removed_selectors = [
            {"selector": s, "role": ref_roles.get(s, "unassigned")}
            for s in reference.allowed_test_selectors
            if s not in cand_set
        ]
        role_changes = [
            {
                "selector": s,
                "from": ref_roles.get(s, "unassigned"),
                "to": cand_roles.get(s, "unassigned"),
            }
            for s in candidate.allowed_test_selectors
            if s in ref_set and ref_roles.get(s, "unassigned") != cand_roles.get(s, "unassigned")
        ]

        added_overlays = {}
        updated_overlays = {}
        for bname, spec in sorted(candidate.allowed_overlays.items()):
            old = reference.allowed_overlays.get(bname)
            if old is None:
                added_overlays[bname] = {
                    "container_target": spec.container_target,
                    "allowed_files": dict(spec.allowed_files),
                }
            elif old.allowed_files != spec.allowed_files or old.host_dir != spec.host_dir:
                updated_overlays[bname] = {
                    "before_files": dict(old.allowed_files),
                    "after_files": dict(spec.allowed_files),
                }
        removed_overlays = {
            bname: {
                "container_target": spec.container_target,
                "allowed_files": dict(spec.allowed_files),
            }
            for bname, spec in sorted(reference.allowed_overlays.items())
            if bname not in candidate.allowed_overlays
        }

        changed_fields = {}
        for field_name in (
            "image_ref",
            "expected_image_digest",
            "expected_source_commit",
            "max_cpus",
            "max_memory_mb",
            "max_timeout_seconds",
            "max_output_bytes",
        ):
            before_val = getattr(reference, field_name)
            after_val = getattr(candidate, field_name)
            if before_val != after_val:
                changed_fields[field_name] = {"before": before_val, "after": after_val}
        before_checkout = str(reference.checkout_dir) if reference.checkout_dir else None
        after_checkout = str(candidate.checkout_dir) if candidate.checkout_dir else None
        if before_checkout != after_checkout:
            changed_fields["checkout_dir"] = {"before": before_checkout, "after": after_checkout}
        before_exp = reference.expires_at.isoformat() if reference.expires_at else None
        after_exp = candidate.expires_at.isoformat() if candidate.expires_at else None
        if before_exp != after_exp:
            changed_fields["expires_at"] = {"before": before_exp, "after": after_exp}

    serialized_requested: dict[str, Any] = {}
    for k, v in sorted(requested_config_diffs.items()):
        if isinstance(v, datetime):
            serialized_requested[k] = v.isoformat()
        elif isinstance(v, Path):
            serialized_requested[k] = str(v)
        else:
            serialized_requested[k] = v

    config_diffs_summary: dict[str, Any] = {
        "network_mode": "none",
        "resource_caps": {
            "max_cpus": candidate.max_cpus,
            "max_memory_mb": candidate.max_memory_mb,
            "max_timeout_seconds": candidate.max_timeout_seconds,
            "max_output_bytes": candidate.max_output_bytes,
            "within_harness_limits": True,
        },
        "changed_fields": changed_fields,
        "requested_overrides": serialized_requested,
    }
    if "notes" in requested_config_diffs and requested_config_diffs["notes"] is not None:
        config_diffs_summary["notes"] = requested_config_diffs["notes"]

    return {
        "is_new_profile": reference is None,
        "base_revision": reference.profile_revision if reference is not None else None,
        "new_revision": candidate.profile_revision,
        "added_overlays": added_overlays,
        "updated_overlays": updated_overlays,
        "removed_overlays": removed_overlays,
        "added_selectors": added_selectors,
        "removed_selectors": removed_selectors,
        "role_changes": role_changes,
        "selector_roles": cand_roles,
        "config_diffs": config_diffs_summary,
    }


def _collect_apply_conflicts(
    *,
    overlay_bundle: str,
    candidate: VdpTargetProfile,
    reference: VdpTargetProfile | None,
    existing_target: VdpTargetProfile | None,
    requested_base_name: str | None,
    diff: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Identify any overwrite, cross-base drop, or mutation conflict that must block apply."""
    conflicts: list[dict[str, Any]] = []
    if (
        existing_target is not None
        and requested_base_name is not None
        and requested_base_name != existing_target.profile_name
    ):
        conflicts.append(
            {
                "code": "cross_base_profile_existing_target_denied",
                "profile_name": existing_target.profile_name,
                "base_profile": requested_base_name,
                "message": (
                    f"Target profile {existing_target.profile_name!r} already exists in profiles.json; "
                    f"cannot re-base it onto different profile {requested_base_name!r}. "
                    f"Omit --base-profile or pass --base-profile {existing_target.profile_name} "
                    "to stack onto the existing target profile."
                ),
            }
        )
    if diff.get("removed_overlays"):
        removed_names = sorted(diff["removed_overlays"].keys())
        conflicts.append(
            {
                "code": "would_remove_existing_target_overlays",
                "removed": removed_names,
                "message": (
                    f"Candidate would drop existing overlay bundle(s) {removed_names}; "
                    "refusing modification."
                ),
            }
        )
    if reference is not None and overlay_bundle in reference.allowed_overlays:
        conflicts.append(
            {
                "code": "existing_overlay_bundle_conflict",
                "bundle": overlay_bundle,
                "message": (
                    f"Overlay bundle {overlay_bundle!r} already exists in profile "
                    f"{reference.profile_name!r}; refusing to overwrite or modify an existing overlay bundle."
                ),
            }
        )
    if existing_target is not None and overlay_bundle in existing_target.allowed_overlays and existing_target is not reference:
        conflicts.append(
            {
                "code": "existing_overlay_bundle_conflict",
                "bundle": overlay_bundle,
                "message": (
                    f"Overlay bundle {overlay_bundle!r} already exists in registered profile "
                    f"{existing_target.profile_name!r}."
                ),
            }
        )
    if diff.get("updated_overlays"):
        conflicts.append(
            {
                "code": "existing_overlay_bundle_modified",
                "bundles": sorted(diff["updated_overlays"].keys()),
                "message": "Candidate would modify an existing overlay bundle; refusing overwrite.",
            }
        )
    if diff.get("role_changes"):
        conflicts.append(
            {
                "code": "existing_selector_role_conflict",
                "changes": list(diff["role_changes"]),
                "message": "Candidate would alter the role of an existing selector; refusing modification.",
            }
        )
    if diff.get("removed_selectors"):
        conflicts.append(
            {
                "code": "would_remove_existing_target_selectors",
                "removed": list(diff["removed_selectors"]),
                "message": "Candidate would remove existing allowlisted selectors; refusing modification.",
            }
        )
    if existing_target is not None and candidate.profile_revision == existing_target.profile_revision:
        conflicts.append(
            {
                "code": "existing_revision_conflict",
                "revision": candidate.profile_revision,
                "message": (
                    f"Candidate revision {candidate.profile_revision!r} collides with existing registered revision."
                ),
            }
        )
    return conflicts


def generate_overlay_registration_plan(
    overlay_dir: str | Path,
    profile_name: str,
    overlay_bundle: str,
    *,
    base_profile: str | VdpTargetProfile | None = None,
    vault_root: str | Path | None = None,
    role_overrides: Mapping[str, str] | None = None,
    config_diffs: Mapping[str, Any] | None = None,
    image_ref: str | None = None,
    expected_image_digest: str | None = None,
    expected_source_commit: str | None = None,
    checkout_dir: str | Path | None = None,
    profile_revision: str | None = None,
    expires_at: datetime | str | None = None,
    max_cpus: int | None = None,
    max_memory_mb: int | None = None,
    max_timeout_seconds: int | None = None,
    max_output_bytes: int | None = None,
) -> dict[str, Any]:
    """Scan an overlay directory, infer/validate selector roles, and build a candidate VDP profile plan.

    Does NOT mutate ``profiles.json``, runs, or evidence.
    """
    clean_profile_name = _validate_identifier(profile_name, label="profile_name")
    clean_bundle_name = _validate_identifier(overlay_bundle, label="overlay_bundle")

    scan_result = scan_overlay_directory(overlay_dir)
    _ensure_not_vault_protected_dir(scan_result["host_dir"], vault_root)

    registered: dict[str, VdpTargetProfile] = {}
    if vault_root is not None:
        registered = load_registered_vdp_profiles(vault_root)

    existing_target = registered.get(clean_profile_name)
    base: VdpTargetProfile | None = None
    requested_base_name: str | None = None
    if isinstance(base_profile, VdpTargetProfile):
        requested_base_name = base_profile.profile_name
        base = base_profile
    elif isinstance(base_profile, str) and base_profile.strip():
        base_name = base_profile.strip()
        requested_base_name = base_name
        if base_name in registered:
            base = registered[base_name]
        else:
            raise ContractViolationError(f"Unknown base VDP profile {base_name!r}.")
    else:
        base = existing_target

    discovered_selectors: list[str] = list(scan_result["discovered_selectors"])
    discovered_set = set(discovered_selectors)
    base_set = set(base.allowed_test_selectors) if base is not None else set()

    normalized_overrides: dict[str, str] = {}
    if role_overrides:
        for raw_sel, raw_role in role_overrides.items():
            sel = validate_vdp_selector_format(raw_sel)
            role = str(raw_role).strip()
            if role not in VALID_SELECTOR_ROLES:
                raise ContractViolationError(
                    f"Invalid selector role {raw_role!r} for {sel!r}; expected one of {VALID_SELECTOR_ROLES}."
                )
            if sel not in discovered_set and sel not in base_set:
                raise ContractViolationError(
                    f"role_overrides selector {sel!r} was not discovered in overlay and is not in base profile."
                )
            normalized_overrides[sel] = role

    new_selector_roles: dict[str, str] = {}
    for sel in discovered_selectors:
        new_selector_roles[sel] = infer_selector_role(sel, explicit_roles=normalized_overrides)

    explicit_config_values = {
        "image_ref": image_ref,
        "expected_image_digest": expected_image_digest,
        "expected_source_commit": expected_source_commit,
        "checkout_dir": Path(checkout_dir) if checkout_dir is not None else None,
        "profile_revision": profile_revision,
        "expires_at": _parse_iso_datetime(expires_at),
        "max_cpus": max_cpus,
        "max_memory_mb": max_memory_mb,
        "max_timeout_seconds": max_timeout_seconds,
        "max_output_bytes": max_output_bytes,
    }
    merged_cfg, requested_cfg = _normalize_config_diffs(
        config_diffs,
        explicit_values=explicit_config_values,
    )

    eff_image_ref = merged_cfg.get("image_ref") or (base.image_ref if base is not None else None)
    if not eff_image_ref:
        raise ContractViolationError("image_ref is required when registering a new VDP profile.")
    eff_image_digest = merged_cfg.get("expected_image_digest") or (
        base.expected_image_digest if base is not None else None
    )
    if not eff_image_digest:
        raise ContractViolationError(
            "expected_image_digest is required when registering a new VDP profile."
        )
    eff_source_commit = merged_cfg.get("expected_source_commit") or (
        base.expected_source_commit if base is not None else None
    )
    if not eff_source_commit:
        raise ContractViolationError(
            "expected_source_commit is required when registering a new VDP profile."
        )

    eff_checkout_dir = (
        merged_cfg["checkout_dir"]
        if "checkout_dir" in merged_cfg
        else (base.checkout_dir if base is not None else None)
    )
    eff_expires_at = (
        merged_cfg["expires_at"]
        if "expires_at" in merged_cfg
        else (base.expires_at if base is not None else None)
    )

    eff_max_cpus = _validate_int_cap(
        merged_cfg.get("max_cpus", base.max_cpus if base is not None else DEFAULT_VDP_TEST_MAX_CPUS),
        name="max_cpus",
        minimum=1,
        maximum=DEFAULT_VDP_TEST_MAX_CPUS,
    )
    eff_max_memory_mb = _validate_int_cap(
        merged_cfg.get(
            "max_memory_mb",
            base.max_memory_mb if base is not None else DEFAULT_VDP_TEST_MAX_MEMORY_MB,
        ),
        name="max_memory_mb",
        minimum=512,
        maximum=DEFAULT_VDP_TEST_MAX_MEMORY_MB,
    )
    eff_max_timeout_seconds = _validate_int_cap(
        merged_cfg.get(
            "max_timeout_seconds",
            base.max_timeout_seconds if base is not None else DEFAULT_VDP_TEST_TIMEOUT_SECONDS,
        ),
        name="max_timeout_seconds",
        minimum=5,
        maximum=DEFAULT_VDP_TEST_TIMEOUT_SECONDS,
    )
    eff_max_output_bytes = _validate_int_cap(
        merged_cfg.get(
            "max_output_bytes",
            base.max_output_bytes if base is not None else DEFAULT_VDP_TEST_MAX_OUTPUT_BYTES,
        ),
        name="max_output_bytes",
        minimum=1024,
        maximum=DEFAULT_VDP_TEST_MAX_OUTPUT_BYTES,
    )

    allowed_selectors = tuple(
        dict.fromkeys(
            [
                *(base.allowed_test_selectors if base is not None else ()),
                *discovered_selectors,
            ]
        )
    )

    # Preserve existing selector roles from base unless explicitly overridden (conflicts caught below).
    combined_roles: dict[str, str] = dict(base.resolve_selector_roles()) if base is not None else {}
    for sel, role in normalized_overrides.items():
        combined_roles[sel] = role
    combined_roles.update(new_selector_roles)

    override_set = set(normalized_overrides.keys()) | set(new_selector_roles.keys())
    pos_selectors = tuple(
        dict.fromkeys(
            [
                *(s for s in (base.positive_selectors if base is not None else ()) if s not in override_set),
                *(s for s, r in combined_roles.items() if r == "positive_control"),
            ]
        )
    )
    neg_selectors = tuple(
        dict.fromkeys(
            [
                *(s for s in (base.negative_selectors if base is not None else ()) if s not in override_set),
                *(s for s, r in combined_roles.items() if r == "defense_check"),
            ]
        )
    )
    anom_selectors = tuple(
        dict.fromkeys(
            [
                *(s for s in (base.anomaly_repro_selectors if base is not None else ()) if s not in override_set),
                *(s for s, r in combined_roles.items() if r == "anomaly_repro"),
            ]
        )
    )
    env_selectors = tuple(
        dict.fromkeys(
            [
                *(s for s in (base.env_check_selectors if base is not None else ()) if s not in override_set),
                *(s for s, r in combined_roles.items() if r == "env_check"),
            ]
        )
    )

    overlays = dict(base.allowed_overlays) if base is not None else {}
    overlays[clean_bundle_name] = VdpOverlaySpec(
        bundle_name=clean_bundle_name,
        host_dir=scan_result["host_dir"],
        container_target=DEFAULT_OVERLAY_CONTAINER_TARGET,
        allowed_files=dict(scan_result["allowed_files"]),
    )

    reference = existing_target or base
    explicit_rev = merged_cfg.get("profile_revision")
    if reference is not None:
        if explicit_rev is None:
            eff_revision = _next_profile_revision(reference.profile_revision)
        elif explicit_rev == reference.profile_revision:
            raise ContractViolationError(
                f"profile_revision {explicit_rev!r} matches existing revision; provide a new revision "
                "or omit profile_revision to auto-increment."
            )
        else:
            eff_revision = explicit_rev
    else:
        eff_revision = explicit_rev or "r1"

    candidate = validate_vdp_profile_registration(
        VdpTargetProfile(
            profile_name=clean_profile_name,
            profile_revision=eff_revision,
            image_ref=str(eff_image_ref).strip(),
            expected_image_digest=str(eff_image_digest).strip().lower(),
            expected_source_commit=str(eff_source_commit).strip().lower(),
            checkout_dir=eff_checkout_dir,
            allowed_test_selectors=allowed_selectors,
            positive_selectors=pos_selectors,
            negative_selectors=neg_selectors,
            anomaly_repro_selectors=anom_selectors,
            env_check_selectors=env_selectors,
            selector_roles=combined_roles,
            allowed_overlays=overlays,
            max_cpus=eff_max_cpus,
            max_memory_mb=eff_max_memory_mb,
            max_timeout_seconds=eff_max_timeout_seconds,
            max_output_bytes=eff_max_output_bytes,
            expires_at=eff_expires_at,
        )
    )

    diff = _compute_registration_diff(
        reference,
        candidate,
        requested_config_diffs=requested_cfg,
    )
    apply_conflicts = _collect_apply_conflicts(
        overlay_bundle=clean_bundle_name,
        candidate=candidate,
        reference=reference,
        existing_target=existing_target,
        requested_base_name=requested_base_name,
        diff=diff,
    )

    target_revision_before = (
        existing_target.profile_revision if existing_target is not None else None
    )
    target_digest_before = (
        compute_vdp_profile_digest(existing_target) if existing_target is not None else None
    )

    return {
        "schema": "vdp-overlay-registration-plan/1",
        "profile_name": candidate.profile_name,
        "profile_revision": candidate.profile_revision,
        "base_profile": base.profile_name if base is not None else None,
        "previous_revision": reference.profile_revision if reference is not None else None,
        "target_revision_before": target_revision_before,
        "target_digest_before": target_digest_before,
        "overlay_bundle": clean_bundle_name,
        "discovered_files": dict(scan_result["allowed_files"]),
        "test_files": list(scan_result["test_files"]),
        "discovered_selectors": discovered_selectors,
        "new_selector_roles": new_selector_roles,
        "selector_roles": diff["selector_roles"],
        "added_overlays": diff["added_overlays"],
        "updated_overlays": diff["updated_overlays"],
        "removed_overlays": diff["removed_overlays"],
        "added_selectors": diff["added_selectors"],
        "removed_selectors": diff["removed_selectors"],
        "role_changes": diff["role_changes"],
        "config_diffs": diff["config_diffs"],
        "apply_conflicts": apply_conflicts,
        "can_apply": len(apply_conflicts) == 0,
        "candidate_profile_summary": candidate.to_public_summary(),
        "candidate_profile": candidate.model_dump(mode="json"),
    }


def preview_and_register_overlay(
    overlay_dir: str | Path,
    profile_name: str,
    overlay_bundle: str,
    *,
    base_profile: str | VdpTargetProfile | None = None,
    vault_root: str | Path | None = None,
    role_overrides: Mapping[str, str] | None = None,
    config_diffs: Mapping[str, Any] | None = None,
    image_ref: str | None = None,
    expected_image_digest: str | None = None,
    expected_source_commit: str | None = None,
    checkout_dir: str | Path | None = None,
    profile_revision: str | None = None,
    expires_at: datetime | str | None = None,
    max_cpus: int | None = None,
    max_memory_mb: int | None = None,
    max_timeout_seconds: int | None = None,
    max_output_bytes: int | None = None,
    apply: bool = False,
    confirm_apply: bool = False,
    require_healthy_env: bool = True,
    runner: SubprocessRunner | None = None,
    docker_bin: str | None = None,
    git_bin: str | None = None,
    include_host_paths: bool = False,
    clock: Callable[[], datetime] | None = None,
) -> dict[str, Any]:
    """Run dry-run registration validation + environment check, and optionally persist with confirmation.

    By default (``apply=False``), produces a full pre-registration diff and
    ``run_vdp_environment_check`` report without mutating ``profiles.json``.
    Setting ``apply=True`` requires ``confirm_apply=True``, ``vault_root``,
    zero overwrite/cross-base/role/revision conflicts, and a healthy environment
    by default (``require_healthy_env=True``); otherwise it fails closed.
    """
    plan = generate_overlay_registration_plan(
        overlay_dir=overlay_dir,
        profile_name=profile_name,
        overlay_bundle=overlay_bundle,
        base_profile=base_profile,
        vault_root=vault_root,
        role_overrides=role_overrides,
        config_diffs=config_diffs,
        image_ref=image_ref,
        expected_image_digest=expected_image_digest,
        expected_source_commit=expected_source_commit,
        checkout_dir=checkout_dir,
        profile_revision=profile_revision,
        expires_at=expires_at,
        max_cpus=max_cpus,
        max_memory_mb=max_memory_mb,
        max_timeout_seconds=max_timeout_seconds,
        max_output_bytes=max_output_bytes,
    )
    candidate = VdpTargetProfile.model_validate(plan["candidate_profile"])

    env_health = run_vdp_environment_check(
        candidate,
        runner=runner,
        docker_bin=docker_bin,
        git_bin=git_bin,
        overlay_bundle=plan["overlay_bundle"],
        include_host_paths=include_host_paths,
        clock=clock,
    )

    apply_conflicts = list(plan["apply_conflicts"])
    if require_healthy_env and not env_health["healthy"]:
        apply_conflicts.append(
            {
                "code": "env_check_failed",
                "issues": list(env_health["issues"]),
                "message": (
                    "Environment health check failed; refusing to persist profile revision "
                    "unless require_healthy_env=False (--allow-unhealthy-env)."
                ),
            }
        )
    can_apply = len(apply_conflicts) == 0

    result: dict[str, Any] = {
        "schema": "vdp-overlay-assistant/1",
        "status": "dry_run_preview",
        "dry_run": not apply,
        "applied": False,
        "profile_name": candidate.profile_name,
        "profile_revision": candidate.profile_revision,
        "previous_revision": plan["previous_revision"],
        "overlay_bundle": plan["overlay_bundle"],
        "added_overlays": plan["added_overlays"],
        "updated_overlays": plan["updated_overlays"],
        "removed_overlays": plan["removed_overlays"],
        "added_selectors": plan["added_selectors"],
        "removed_selectors": plan["removed_selectors"],
        "role_changes": plan["role_changes"],
        "selector_roles": plan["selector_roles"],
        "new_selector_roles": plan["new_selector_roles"],
        "config_diffs": plan["config_diffs"],
        "env_health": env_health,
        "apply_conflicts": apply_conflicts,
        "can_apply": can_apply,
        "existing_runs_and_evidence_untouched": True,
        "profile_summary": plan["candidate_profile_summary"],
    }

    if not apply:
        return result

    if not confirm_apply:
        raise ContractViolationError(
            "Persisting profile changes requires explicit confirmation (confirm_apply=True / --confirm-apply).",
            code="confirmation_required",
        )
    if vault_root is None:
        raise ConfigurationError(
            "Vault root (--vault-root or CTF_MCP_VAULT_ROOT) must be specified when apply=True."
        )
    if plan["apply_conflicts"]:
        first_msg = plan["apply_conflicts"][0]["message"]
        raise ContractViolationError(
            first_msg,
            code="registration_overwrite_refused",
            details={"conflicts": apply_conflicts},
        )
    if require_healthy_env and not env_health["healthy"]:
        raise ContractViolationError(
            "Environment health check failed; refusing to persist profile revision.",
            code="env_check_failed",
            details={"issues": env_health["issues"]},
        )

    # Atomic locked read-check-write + CAS against concurrent overwrites/lost updates.
    saved_path = save_registered_vdp_profile(
        vault_root,
        candidate,
        expected_profile_revision=plan["target_revision_before"],
        expected_profile_digest=plan["target_digest_before"],
        disallow_existing_bundles=(plan["overlay_bundle"],),
    )
    result["status"] = "registered"
    result["dry_run"] = False
    result["applied"] = True
    result["profiles_file"] = str(saved_path)
    return result


def _parse_selector_role_args(items: Sequence[str] | None) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for raw in items or ():
        sel_raw, sep, role_raw = str(raw).partition("=")
        sel_s = sel_raw.strip()
        role_s = role_raw.strip()
        if not sep or not sel_s or role_s not in VALID_SELECTOR_ROLES:
            raise ContractViolationError(
                f"--selector-role must be SELECTOR=ROLE with ROLE in {VALID_SELECTOR_ROLES}, got {raw!r}."
            )
        parsed[sel_s] = role_s
    return parsed


def _parse_config_diff_args(items: Sequence[str] | None) -> dict[str, Any]:
    parsed: dict[str, Any] = {}
    for raw in items or ():
        key_raw, sep, val_raw = str(raw).partition("=")
        key = key_raw.strip()
        val_s = val_raw.strip()
        if not sep or not key:
            raise ContractViolationError(
                f"--config-diff must be KEY=VALUE, got {raw!r}."
            )
        if key not in ALLOWED_CONFIG_DIFF_KEYS:
            raise ContractViolationError(
                f"Unsupported or unsafe --config-diff key {key!r}; allowed: {sorted(ALLOWED_CONFIG_DIFF_KEYS)}."
            )
        if key in _INT_CONFIG_KEYS:
            try:
                parsed[key] = int(val_s)
            except ValueError as exc:
                raise ContractViolationError(
                    f"--config-diff {key} requires an integer value, got {val_s!r}."
                ) from exc
        else:
            parsed[key] = val_s
    return parsed


def _add_fallback_common_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--db-path", type=Path, default=argparse.SUPPRESS)
    parser.add_argument("--vault-root", type=Path, default=argparse.SUPPRESS)
    parser.add_argument("--config", type=Path, default=argparse.SUPPRESS)
    parser.add_argument("--principal-id", default=argparse.SUPPRESS)
    parser.add_argument("--client-kind", default=argparse.SUPPRESS)
    parser.add_argument("--model-label", default=argparse.SUPPRESS)


def register_overlay_assistant_subparser(
    subparsers: Any,
    *,
    add_common_flags: Callable[[argparse.ArgumentParser], None] | None = None,
    command_name: str = OVERLAY_ASSISTANT_COMMAND,
) -> argparse.ArgumentParser:
    """Register the ``register-vdp-overlay`` assistant subparser for ``ctf-mcp-admin``."""
    subparser = subparsers.add_parser(
        command_name,
        help=(
            "Scan an overlay directory, infer selector roles, preview diff + env checks "
            "(dry-run by default), and persist with explicit --apply --confirm-apply."
        ),
    )
    if add_common_flags is not None:
        add_common_flags(subparser)
    else:
        _add_fallback_common_flags(subparser)

    subparser.add_argument("--overlay-dir", type=Path, required=True, help="Host overlay directory to scan.")
    subparser.add_argument("--profile-name", required=True, help="Target VDP profile name.")
    subparser.add_argument("--overlay-bundle", required=True, help="New overlay bundle identifier.")
    subparser.add_argument("--base-profile", default=None, help="Optional existing base profile name.")
    subparser.add_argument("--profile-revision", default=None, help="Optional explicit new profile revision.")
    subparser.add_argument("--image-ref", default=None, help="Pinned container image reference.")
    subparser.add_argument("--image-digest", default=None, help="Pinned sha256:<64hex> image digest.")
    subparser.add_argument("--source-commit", default=None, help="Pinned 40-hex source commit.")
    subparser.add_argument("--checkout-dir", type=Path, default=None, help="Optional pinned checkout directory.")
    subparser.add_argument("--expires-at", default=None, help="Optional ISO-8601 expiry timestamp.")
    subparser.add_argument(
        "--selector-role",
        action="append",
        default=None,
        help="Explicit role override as SELECTOR=ROLE (positive_control|defense_check|anomaly_repro|env_check).",
    )
    subparser.add_argument(
        "--config-diff",
        action="append",
        default=None,
        help="Optional configuration diff entry as KEY=VALUE (preserves network_mode=none and resource caps).",
    )
    subparser.add_argument("--max-cpus", type=int, default=None)
    subparser.add_argument("--max-memory-mb", type=int, default=None)
    subparser.add_argument("--max-timeout-seconds", type=int, default=None)
    subparser.add_argument("--max-output-bytes", type=int, default=None)
    subparser.add_argument("--docker-bin", default=None, help="Docker CLI binary for environment check.")
    subparser.add_argument("--git-bin", default=None, help="Git CLI binary for checkout check.")
    env_group = subparser.add_mutually_exclusive_group()
    env_group.add_argument(
        "--require-healthy-env",
        dest="require_healthy_env",
        action="store_true",
        help="Refuse --apply unless environment verification passes (default).",
    )
    env_group.add_argument(
        "--allow-unhealthy-env",
        dest="require_healthy_env",
        action="store_false",
        help="Explicitly allow --apply even when environment verification fails.",
    )
    subparser.set_defaults(require_healthy_env=True)
    subparser.add_argument(
        "--apply",
        action="store_true",
        default=False,
        help="Persist new profile revision (dry-run preview only when omitted).",
    )
    subparser.add_argument(
        "--confirm-apply",
        action="store_true",
        default=False,
        help="Explicit operator confirmation required alongside --apply.",
    )
    subparser.set_defaults(_handler=handle_overlay_assistant)
    return subparser


def handle_overlay_assistant(
    args: argparse.Namespace,
    env: Mapping[str, str] | None = None,
) -> int:
    """CLI handler for ``register-vdp-overlay``."""
    eff_env = dict(env if env is not None else os.environ)
    vault_arg = getattr(args, "vault_root", None)
    if vault_arg is not None:
        eff_env["CTF_MCP_VAULT_ROOT"] = str(vault_arg)
    settings = load_runtime_settings(eff_env)

    role_overrides = _parse_selector_role_args(getattr(args, "selector_role", None))
    config_diffs = _parse_config_diff_args(getattr(args, "config_diff", None))

    result = preview_and_register_overlay(
        overlay_dir=args.overlay_dir,
        profile_name=args.profile_name,
        overlay_bundle=args.overlay_bundle,
        base_profile=getattr(args, "base_profile", None),
        vault_root=settings.vault_root,
        role_overrides=role_overrides or None,
        config_diffs=config_diffs or None,
        image_ref=getattr(args, "image_ref", None),
        expected_image_digest=getattr(args, "image_digest", None),
        expected_source_commit=getattr(args, "source_commit", None),
        checkout_dir=getattr(args, "checkout_dir", None),
        profile_revision=getattr(args, "profile_revision", None),
        expires_at=getattr(args, "expires_at", None),
        max_cpus=getattr(args, "max_cpus", None),
        max_memory_mb=getattr(args, "max_memory_mb", None),
        max_timeout_seconds=getattr(args, "max_timeout_seconds", None),
        max_output_bytes=getattr(args, "max_output_bytes", None),
        apply=bool(getattr(args, "apply", False)),
        confirm_apply=bool(getattr(args, "confirm_apply", False)),
        require_healthy_env=bool(getattr(args, "require_healthy_env", True)),
        docker_bin=getattr(args, "docker_bin", None),
        git_bin=getattr(args, "git_bin", None),
        include_host_paths=True,
    )
    sys.stdout.write(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
    return 0


__all__ = [
    "ALLOWED_CONFIG_DIFF_KEYS",
    "DEFAULT_OVERLAY_CONTAINER_TARGET",
    "OVERLAY_ASSISTANT_COMMAND",
    "SELECTOR_ROLE_PREFIXES",
    "generate_overlay_registration_plan",
    "handle_overlay_assistant",
    "infer_selector_role",
    "preview_and_register_overlay",
    "register_overlay_assistant_subparser",
    "scan_overlay_directory",
]
