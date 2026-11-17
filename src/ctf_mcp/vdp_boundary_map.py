"""Static AST-based Auth Boundary Diff Map (Feature 1) for VDP analysis.

Inspects a target Python source tree (and optional test directory) across four
entrypoint kinds (``ui``, ``api``, ``webhook``, ``async``) for a specified
feature, extracting per-path boundary controls and exact ``file:line``
locations:

- Entrypoint name / route
- Permission and authentication checks
- Input validation and normalization/sanitization steps
- Target selection and tenant/owner scoping logic
- State-mutating update sinks

All cross-path differences and test-coverage gaps are emitted strictly with
``status="investigation_candidate"`` and never claim confirmed vulnerabilities.
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import stat
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, model_validator

from ctf_mcp.contracts import (
    ContractViolationError,
    PathSecurityError,
    StrictModel,
)

# ---------------------------------------------------------------------------
# Constants & Public Contracts
# ---------------------------------------------------------------------------

BOUNDARY_MAP_SUBCOMMAND = "vdp-boundary-map"
DEFAULT_MAX_FILE_BYTES = 1024 * 1024
INVESTIGATION_CANDIDATE_STATUS: Literal["investigation_candidate"] = (
    "investigation_candidate"
)
VALID_ENTRYPOINT_KINDS: tuple[str, ...] = ("ui", "api", "webhook", "async")

_IGNORED_DIR_NAMES: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "node_modules",
        "build",
        "dist",
    }
)

_HTTP_DECORATOR_METHODS: frozenset[str] = frozenset(
    {"get", "post", "put", "patch", "delete", "head", "options", "route", "api_route"}
)

_API_CLASS_BASES: frozenset[str] = frozenset(
    {
        "apiview",
        "genericapiview",
        "viewset",
        "modelviewset",
        "readonlymodelviewset",
        "genericviewset",
        "resource",
        "restcontroller",
        "apiendpoint",
    }
)

_UI_CLASS_BASES: frozenset[str] = frozenset(
    {
        "view",
        "templateview",
        "formview",
        "updateview",
        "createview",
        "deleteview",
        "detailview",
        "listview",
    }
)

_TASK_DECORATOR_TOKENS: tuple[str, ...] = (
    "shared_task",
    "celery.task",
    "app.task",
    "task",
    "job",
    "actor",
    "background",
    "worker",
    "dramatiq.actor",
    "huey.task",
    "rq.job",
)

_PERMISSION_DECORATOR_TOKENS: tuple[str, ...] = (
    "login_required",
    "permission_required",
    "require_permission",
    "has_perm",
    "has_permission",
    "require_role",
    "roles_required",
    "auth_required",
    "jwt_required",
    "require_auth",
    "staff_member_required",
    "superuser_required",
    "admin_required",
    "verify_signature",
    "verify_webhook_signature",
    "hmac_required",
    "require_signature",
    "authenticated",
    "scopes",
)

_SIGNATURE_CHECK_TOKENS: tuple[str, ...] = (
    "signature",
    "hmac",
    "compare_digest",
    "verify_webhook",
    "webhook_secret",
)

_PERMISSION_CALL_TOKENS: tuple[str, ...] = (
    "has_perm",
    "has_permission",
    "has_object_permission",
    "check_permission",
    "check_permissions",
    "check_object_permissions",
    "require_permission",
    "require_role",
    "require_auth",
    "authorize",
    "is_authorized",
    "verify_signature",
    "verify_webhook_signature",
    "verify_hmac",
    "compare_digest",
    "check_access",
    "assert_owner",
    "ensure_member",
    "ensure_authorized",
    "check_token",
    "validate_token",
    "authenticate",
    "abort_if_unauthorized",
)

_AUTH_ATTR_TOKENS: tuple[str, ...] = (
    "is_authenticated",
    "is_superuser",
    "is_staff",
    "is_admin",
)

_SCOPE_PREDICATE_KEYS: frozenset[str] = frozenset(
    {
        "owner",
        "owner_id",
        "user",
        "user_id",
        "tenant",
        "tenant_id",
        "org",
        "org_id",
        "organization",
        "organization_id",
        "workspace",
        "workspace_id",
        "account",
        "account_id",
        "team",
        "team_id",
        "member",
        "member_id",
        "created_by",
        "created_by_id",
        "actor",
        "actor_id",
    }
)

_ORM_LOOKUP_CALLS: frozenset[str] = frozenset(
    {
        "filter",
        "filter_by",
        "get",
        "get_or_404",
        "get_object_or_404",
        "get_list_or_404",
        "first",
        "one",
        "one_or_none",
        "scalar_one",
        "scalar_one_or_none",
        "find_one",
        "find",
        "where",
        "exclude",
        "select_related",
        "prefetch_related",
        "get_object",
        "get_queryset",
    }
)

_FUZZY_LOOKUP_SUFFIXES: tuple[str, ...] = (
    "__endswith",
    "__iendswith",
    "__startswith",
    "__istartswith",
    "__contains",
    "__icontains",
    "__regex",
    "__iregex",
)

_VALIDATION_CALL_PREFIXES: tuple[str, ...] = (
    "validate_",
    "clean_",
    "normalize_",
    "sanitize_",
    "parse_",
    "verify_",
)

_ORM_MUTATION_METHODS: frozenset[str] = frozenset(
    {
        "save",
        "update",
        "bulk_update",
        "bulk_create",
        "create",
        "get_or_create",
        "update_or_create",
        "delete",
        "commit",
        "flush",
        "execute",
        "executemany",
        "perform_update",
        "perform_create",
        "perform_destroy",
    }
)

_ASYNC_DISPATCH_METHODS: frozenset[str] = frozenset(
    {"delay", "apply_async", "enqueue", "send", "create_task"}
)

_MUTATING_CALL_PREFIXES: tuple[str, ...] = (
    "update_",
    "save_",
    "write_",
    "set_",
    "create_",
    "delete_",
    "remove_",
    "apply_",
    "sync_",
    "trigger_",
    "dispatch_",
    "enqueue_",
    "mutate_",
    "patch_",
    "persist_",
)

_TEST_AUTH_HINTS: tuple[str, ...] = (
    "401",
    "403",
    "unauthorized",
    "unauthenticated",
    "forbidden",
    "permissiondenied",
    "permission_denied",
    "not_authorized",
    "access_denied",
    "invalid_signature",
    "bad_signature",
    "signature",
    "anonymous",
)

_TEST_SCOPE_HINTS: tuple[str, ...] = (
    "other_user",
    "other_tenant",
    "other_org",
    "other_owner",
    "foreign",
    "cross_tenant",
    "cross_org",
    "cross_user",
    "wrong_tenant",
    "wrong_owner",
    "404",
    "notfound",
    "not_found",
    "tenant",
    "scope",
)

_TEST_VALIDATION_HINTS: tuple[str, ...] = (
    "400",
    "422",
    "bad_request",
    "validationerror",
    "validation_error",
    "valueerror",
    "invalid",
    "malformed",
    "normalize",
    "sanitiz",
    "reject",
)

_STOP_TOKENS: frozenset[str] = frozenset(
    {"the", "and", "for", "with", "from", "into", "handler", "view", "api", "task"}
)


class EntrypointKind(StrEnum):
    """Supported application boundary entrypoint categories."""

    UI = "ui"
    API = "api"
    WEBHOOK = "webhook"
    ASYNC = "async"


class BoundaryItemCategory(StrEnum):
    """Extracted boundary aspect category for a single source location."""

    PERMISSION_CHECK = "permission_check"
    INPUT_VALIDATION = "input_validation"
    TARGET_SCOPING = "target_scoping"
    UPDATE_SINK = "update_sink"


class DiffCategory(StrEnum):
    """Cross-path boundary difference categories."""

    MISSING_PERMISSION_CHECK = "missing_permission_check"
    PERMISSION_MODEL_MISMATCH = "permission_model_mismatch"
    MISSING_TARGET_SCOPING = "missing_target_scoping"
    SCOPING_MISMATCH = "scoping_mismatch"
    MISSING_INPUT_VALIDATION = "missing_input_validation"
    INPUT_NORMALIZATION_MISMATCH = "input_normalization_mismatch"
    UPDATE_SINK_ASYMMETRY = "update_sink_asymmetry"


class CoverageGapType(StrEnum):
    """Test-coverage gap categories for boundary entrypoints."""

    NO_TEST_REFERENCE = "no_test_reference"
    MISSING_PERMISSION_TEST_ASSERTION = "missing_permission_test_assertion"
    MISSING_SCOPING_TEST_ASSERTION = "missing_scoping_test_assertion"
    MISSING_VALIDATION_TEST_ASSERTION = "missing_validation_test_assertion"


class SourceEvidenceItem(StrictModel):
    """One extracted boundary control, filter, validation, or sink with location."""

    category: BoundaryItemCategory
    name: str = Field(min_length=1)
    detail: str = Field(min_length=1)
    file: str = Field(min_length=1)
    line: int = Field(ge=1)
    location: str = Field(min_length=1)
    tags: tuple[str, ...] = ()


class EntrypointBoundaryRecord(StrictModel):
    """Extracted boundary profile for one feature-related entrypoint."""

    entrypoint_id: str = Field(min_length=1)
    kind: EntrypointKind
    name: str = Field(min_length=1)
    qualified_name: str = Field(min_length=1)
    route: str | None = None
    file: str = Field(min_length=1)
    line: int = Field(ge=1)
    location: str = Field(min_length=1)
    matched_feature_reasons: tuple[str, ...] = ()
    parameters: tuple[str, ...] = ()
    permission_checks: tuple[SourceEvidenceItem, ...] = ()
    input_validations: tuple[SourceEvidenceItem, ...] = ()
    target_scopings: tuple[SourceEvidenceItem, ...] = ()
    update_sinks: tuple[SourceEvidenceItem, ...] = ()
    callees_followed: tuple[str, ...] = ()
    test_references: tuple[str, ...] = ()


class BoundaryDiffFinding(StrictModel):
    """Cross-path difference marked strictly as an investigation candidate."""

    finding_id: str = Field(min_length=1)
    status: Literal["investigation_candidate"] = INVESTIGATION_CANDIDATE_STATUS
    category: DiffCategory
    baseline_entrypoint_id: str | None = None
    compared_entrypoint_id: str = Field(min_length=1)
    baseline_kind: EntrypointKind | None = None
    compared_kind: EntrypointKind
    summary: str = Field(min_length=1)
    evidence_locations: tuple[str, ...] = Field(min_length=1)
    details: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _validate_candidate_status(self) -> BoundaryDiffFinding:
        if self.status != INVESTIGATION_CANDIDATE_STATUS:
            raise ContractViolationError(
                "BoundaryDiffFinding status must remain 'investigation_candidate'."
            )
        return self


class TestCoverageGap(StrictModel):
    """Untested boundary path or assertion gap marked as investigation candidate."""

    gap_id: str = Field(min_length=1)
    status: Literal["investigation_candidate"] = INVESTIGATION_CANDIDATE_STATUS
    entrypoint_id: str = Field(min_length=1)
    kind: EntrypointKind
    entrypoint_location: str = Field(min_length=1)
    gap_type: CoverageGapType
    untested_items: tuple[str, ...] = ()
    evidence_locations: tuple[str, ...] = Field(min_length=1)
    summary: str = Field(min_length=1)

    @model_validator(mode="after")
    def _validate_candidate_status(self) -> TestCoverageGap:
        if self.status != INVESTIGATION_CANDIDATE_STATUS:
            raise ContractViolationError(
                "TestCoverageGap status must remain 'investigation_candidate'."
            )
        return self


class BoundaryDiffMap(StrictModel):
    """Complete Auth Boundary Diff Map report for one feature."""

    schema_version: Literal["1"] = "1"
    status_policy: Literal["investigation_candidate_only"] = (
        "investigation_candidate_only"
    )
    feature: str = Field(min_length=1)
    source_root: str = Field(min_length=1)
    test_root: str | None = None
    baseline_entrypoint_id: str | None = None
    analyzed_files: tuple[str, ...] = ()
    analyzed_test_files: tuple[str, ...] = ()
    skipped_files: tuple[str, ...] = ()
    entrypoints: tuple[EntrypointBoundaryRecord, ...] = ()
    entrypoints_by_kind: dict[str, int] = Field(default_factory=dict)
    cross_path_diffs: tuple[BoundaryDiffFinding, ...] = ()
    test_coverage_gaps: tuple[TestCoverageGap, ...] = ()
    total_investigation_candidates: int = Field(ge=0)
    disclaimer: str = (
        "All items carry status='investigation_candidate' from static AST inspection; "
        "manual code and runtime verification is required before drawing conclusions."
    )


# ---------------------------------------------------------------------------
# Internal AST Indexing Structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _IndexedClass:
    file_rel: str
    module_name: str
    name: str
    qualified_name: str
    line: int
    bases: tuple[str, ...]
    decorators: tuple[ast.expr, ...]
    class_body: tuple[ast.stmt, ...]


@dataclass(frozen=True)
class _IndexedFunction:
    file_rel: str
    module_name: str
    name: str
    qualified_name: str
    line: int
    end_line: int
    is_async: bool
    node: ast.FunctionDef | ast.AsyncFunctionDef
    class_info: _IndexedClass | None
    imports_map: dict[str, str]


@dataclass(frozen=True)
class _IndexedTestCase:
    selector: str
    file_rel: str
    line: int
    name: str
    referenced_names: frozenset[str]
    string_literals: tuple[str, ...]
    lowered_tokens: frozenset[str]


# ---------------------------------------------------------------------------
# Filesystem Walking & Safe AST Loading
# ---------------------------------------------------------------------------


def _is_reparse_or_symlink(path: Path) -> bool:
    try:
        st = os.lstat(path)
    except OSError:
        return True
    if stat.S_ISLNK(st.st_mode):
        return True
    file_attrs = getattr(st, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(file_attrs & reparse_flag)


def _validate_root_dir(raw_dir: str | Path, *, label: str) -> Path:
    path = Path(raw_dir)
    if "\x00" in str(raw_dir):
        raise PathSecurityError(f"{label} contains null byte.")
    if not path.exists():
        raise ContractViolationError(f"{label} does not exist: {path}")
    if _is_reparse_or_symlink(path):
        raise PathSecurityError(f"{label} must not be a symlink or reparse point: {path}")
    if not path.is_dir():
        raise ContractViolationError(f"{label} must be a directory: {path}")
    return path.resolve()


def _iter_python_files(
    root: Path,
    *,
    exclude_tests: bool = False,
    only_tests: bool = False,
) -> list[tuple[Path, str]]:
    """Safely walk ``root`` for ``.py`` files, skipping symlinks and build/cache dirs."""
    discovered: list[tuple[Path, str]] = []

    def _walk(current: Path) -> None:
        try:
            entries = sorted(current.iterdir(), key=lambda p: p.name)
        except OSError:
            return
        for entry in entries:
            if _is_reparse_or_symlink(entry):
                continue
            try:
                resolved = entry.resolve()
                if not resolved.is_relative_to(root):
                    continue
            except OSError:
                continue
            if entry.is_dir():
                if entry.name in _IGNORED_DIR_NAMES:
                    continue
                if exclude_tests and entry.name in {"tests", "test"}:
                    continue
                _walk(entry)
            elif entry.is_file() and entry.suffix == ".py":
                rel = resolved.relative_to(root).as_posix()
                is_test_name = entry.name.startswith("test_") or entry.name.endswith(
                    "_test.py"
                )
                if exclude_tests and is_test_name:
                    continue
                if only_tests and not is_test_name:
                    continue
                discovered.append((resolved, rel))

    _walk(root)
    return discovered


def _read_python_ast(
    path: Path,
    rel_posix: str,
    *,
    max_file_bytes: int,
) -> ast.Module | None:
    if max_file_bytes <= 0:
        raise ContractViolationError("max_file_bytes must be positive.")
    try:
        size = path.stat().st_size
        if size > max_file_bytes:
            return None
        source = path.read_text(encoding="utf-8")
        return ast.parse(source, filename=rel_posix)
    except (OSError, UnicodeDecodeError, SyntaxError):
        return None


# ---------------------------------------------------------------------------
# AST Formatting & Token Helpers
# ---------------------------------------------------------------------------


def _format_expr(node: ast.AST | None, *, max_parts: int = 5) -> str:
    if node is None:
        return ""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _format_expr(node.value, max_parts=max_parts - 1)
        if not prefix:
            return node.attr
        parts = f"{prefix}.{node.attr}".split(".")
        if len(parts) > max_parts:
            parts = parts[-max_parts:]
        return ".".join(parts)
    if isinstance(node, ast.Call):
        return _format_expr(node.func, max_parts=max_parts)
    if isinstance(node, ast.Subscript):
        return _format_expr(node.value, max_parts=max_parts)
    if isinstance(node, ast.Constant):
        if isinstance(node.value, str):
            return node.value
        return repr(node.value)
    return type(node).__name__


def _extract_str_constant(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _tokenize_identifier(text: str) -> tuple[str, ...]:
    camel_split = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", text)
    raw_parts = re.split(r"[^a-zA-Z0-9]+", camel_split.lower())
    tokens: list[str] = []
    for part in raw_parts:
        if len(part) >= 2 and part not in _STOP_TOKENS and part not in tokens:
            tokens.append(part)
    return tuple(tokens)


def _normalize_slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", text.lower())


def _collect_imports(tree: ast.Module, module_name: str) -> dict[str, str]:
    imports: dict[str, str] = {}
    pkg_parts = module_name.split(".")[:-1]
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".")[0]
                imports[local] = alias.name
        elif isinstance(node, ast.ImportFrom):
            base_mod = node.module or ""
            if node.level > 0:
                keep = max(0, len(pkg_parts) - (node.level - 1))
                prefix = ".".join(pkg_parts[:keep])
                base_mod = f"{prefix}.{base_mod}".strip(".") if prefix else base_mod
            for alias in node.names:
                if alias.name == "*":
                    continue
                local = alias.asname or alias.name
                target = f"{base_mod}.{alias.name}" if base_mod else alias.name
                imports[local] = target
    return imports


def _extract_route_table(
    tree: ast.Module,
    module_name: str,
    imports_map: dict[str, str],
) -> dict[str, str]:
    """Extract URL/route strings mapped to handler names from module-level routing calls."""
    routes: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func_name = _format_expr(node.func).lower()
        tail = func_name.rsplit(".", 1)[-1]
        if tail not in {"path", "re_path", "url", "add_url_rule", "add_api_route", "register"}:
            continue
        route_str: str | None = None
        target_name: str | None = None
        if node.args:
            route_str = _extract_str_constant(node.args[0])
        if route_str is None:
            for kw in node.keywords:
                if kw.arg in {"route", "rule", "path", "prefix"}:
                    route_str = _extract_str_constant(kw.value)
                    if route_str:
                        break
        for arg in node.args[1:]:
            if isinstance(arg, ast.Call) and _format_expr(arg.func).endswith(".as_view"):
                target_name = _format_expr(arg.func.value if isinstance(arg.func, ast.Attribute) else None)
                break
            if isinstance(arg, (ast.Name, ast.Attribute)):
                target_name = _format_expr(arg)
                break
        if target_name is None:
            for kw in node.keywords:
                if kw.arg in {"view", "view_func", "endpoint", "viewset"}:
                    if isinstance(kw.value, ast.Call) and _format_expr(kw.value.func).endswith(".as_view"):
                        target_name = _format_expr(
                            kw.value.func.value if isinstance(kw.value.func, ast.Attribute) else None
                        )
                    else:
                        target_name = _format_expr(kw.value)
                    break
        if route_str is None or not target_name:
            continue
        normalized_route = route_str if route_str.startswith("/") else f"/{route_str}"
        short_target = target_name.rsplit(".", 1)[-1]
        routes[target_name] = normalized_route
        routes[short_target] = normalized_route
        first_part = target_name.split(".", 1)[0]
        if first_part in imports_map:
            resolved = imports_map[first_part]
            if "." in target_name:
                resolved = f"{resolved}.{target_name.split('.', 1)[1]}"
            routes[resolved] = normalized_route
    return routes


# ---------------------------------------------------------------------------
# Indexing Source Tree & Resolving Callees
# ---------------------------------------------------------------------------


def _index_source_tree(
    source_root: Path,
    *,
    exclude_tests: bool,
    max_file_bytes: int,
) -> tuple[
    list[str],
    list[str],
    list[_IndexedFunction],
    dict[str, _IndexedFunction],
    dict[str, str],
]:
    py_files = _iter_python_files(source_root, exclude_tests=exclude_tests)
    analyzed_files: list[str] = []
    skipped_files: list[str] = []
    functions: list[_IndexedFunction] = []
    by_qname: dict[str, _IndexedFunction] = {}
    route_table: dict[str, str] = {}

    for abs_path, rel_posix in py_files:
        tree = _read_python_ast(abs_path, rel_posix, max_file_bytes=max_file_bytes)
        if tree is None:
            skipped_files.append(rel_posix)
            continue
        analyzed_files.append(rel_posix)
        mod_parts = list(Path(rel_posix).with_suffix("").parts)
        if mod_parts and mod_parts[-1] == "__init__":
            mod_parts = mod_parts[:-1]
        module_name = ".".join(mod_parts) or Path(rel_posix).stem
        imports_map = _collect_imports(tree, module_name)
        route_table.update(_extract_route_table(tree, module_name, imports_map))

        for stmt in tree.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qname = f"{module_name}.{stmt.name}"
                fn = _IndexedFunction(
                    file_rel=rel_posix,
                    module_name=module_name,
                    name=stmt.name,
                    qualified_name=qname,
                    line=stmt.lineno,
                    end_line=getattr(stmt, "end_lineno", stmt.lineno),
                    is_async=isinstance(stmt, ast.AsyncFunctionDef),
                    node=stmt,
                    class_info=None,
                    imports_map=imports_map,
                )
                functions.append(fn)
                by_qname[qname] = fn
            elif isinstance(stmt, ast.ClassDef):
                cls_qname = f"{module_name}.{stmt.name}"
                bases = tuple(_format_expr(b) for b in stmt.bases)
                cls_info = _IndexedClass(
                    file_rel=rel_posix,
                    module_name=module_name,
                    name=stmt.name,
                    qualified_name=cls_qname,
                    line=stmt.lineno,
                    bases=bases,
                    decorators=tuple(stmt.decorator_list),
                    class_body=tuple(stmt.body),
                )
                for member in stmt.body:
                    if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        qname = f"{cls_qname}.{member.name}"
                        fn = _IndexedFunction(
                            file_rel=rel_posix,
                            module_name=module_name,
                            name=member.name,
                            qualified_name=qname,
                            line=member.lineno,
                            end_line=getattr(member, "end_lineno", member.lineno),
                            is_async=isinstance(member, ast.AsyncFunctionDef),
                            node=member,
                            class_info=cls_info,
                            imports_map=imports_map,
                        )
                        functions.append(fn)
                        by_qname[qname] = fn

    return analyzed_files, skipped_files, functions, by_qname, route_table


_GENERIC_METHOD_NAMES: frozenset[str] = frozenset(
    {
        "get",
        "post",
        "put",
        "patch",
        "delete",
        "head",
        "options",
        "filter",
        "filter_by",
        "save",
        "update",
        "create",
        "strip",
        "lstrip",
        "rstrip",
        "lower",
        "upper",
        "items",
        "keys",
        "values",
        "append",
        "extend",
        "first",
        "all",
        "count",
        "exists",
        "dispatch",
    }
)


def _resolve_callee(
    call_name: str,
    caller: _IndexedFunction,
    by_qname: dict[str, _IndexedFunction],
    by_short_name: dict[str, list[_IndexedFunction]],
) -> _IndexedFunction | None:
    if not call_name:
        return None
    if call_name.startswith("self.") and caller.class_info is not None:
        method_name = call_name.split(".", 1)[1]
        cand = by_qname.get(f"{caller.class_info.qualified_name}.{method_name}")
        if cand is not None:
            return cand
    if "." not in call_name:
        same_mod = by_qname.get(f"{caller.module_name}.{call_name}")
        if same_mod is not None:
            return same_mod
        imported = caller.imports_map.get(call_name)
        if imported and imported in by_qname:
            return by_qname[imported]
        top_matches = [
            m for m in by_short_name.get(call_name, []) if m.class_info is None
        ]
        if len(top_matches) == 1:
            return top_matches[0]
        return None

    head, tail = call_name.split(".", 1)
    if head in caller.imports_map:
        resolved = f"{caller.imports_map[head]}.{tail}"
        if resolved in by_qname:
            return by_qname[resolved]
    short_tail = call_name.rsplit(".", 1)[-1]
    if short_tail.lower() in _GENERIC_METHOD_NAMES:
        return None
    matches = by_short_name.get(short_tail, [])
    if len(matches) == 1:
        return matches[0]
    return None


# ---------------------------------------------------------------------------
# Entrypoint Classification & Feature Matching
# ---------------------------------------------------------------------------


def _extract_decorator_route(decorator: ast.expr) -> str | None:
    if not isinstance(decorator, ast.Call):
        return None
    dec_name = _format_expr(decorator.func).lower()
    tail = dec_name.rsplit(".", 1)[-1]
    if tail not in _HTTP_DECORATOR_METHODS and "task" not in tail and "job" not in tail:
        return None
    if decorator.args:
        arg0 = _extract_str_constant(decorator.args[0])
        if arg0:
            return arg0
    for kw in decorator.keywords:
        if kw.arg in {"path", "rule", "route", "name"}:
            val = _extract_str_constant(kw.value)
            if val:
                return val
    return None


def _is_http_decorator(decorator: ast.expr) -> bool:
    dec_name = _format_expr(decorator).lower()
    tail = dec_name.rsplit(".", 1)[-1]
    return tail in _HTTP_DECORATOR_METHODS or tail in {
        "api_view",
        "require_post",
        "require_get",
        "require_http_methods",
        "csrf_exempt",
        "csrf_protect",
    }


def _is_task_decorator(decorator: ast.expr) -> bool:
    dec_name = _format_expr(decorator).lower()
    return any(
        dec_name == tok or dec_name.endswith(f".{tok}") for tok in _TASK_DECORATOR_TOKENS
    )


def _lookup_route_for_function(
    fn: _IndexedFunction,
    route_table: dict[str, str],
) -> str | None:
    for dec in fn.node.decorator_list:
        route = _extract_decorator_route(dec)
        if route:
            return route
    if fn.class_info is not None:
        for dec in fn.class_info.decorators:
            route = _extract_decorator_route(dec)
            if route:
                return route
        for key in (fn.class_info.qualified_name, fn.class_info.name):
            if key in route_table:
                return route_table[key]
    for key in (fn.qualified_name, fn.name):
        if key in route_table:
            return route_table[key]
    return None


def _classify_entrypoint(
    fn: _IndexedFunction,
    route: str | None,
) -> EntrypointKind | None:
    """Determine if ``fn`` is a boundary entrypoint and return its EntrypointKind."""
    if fn.name.startswith("_"):
        return None

    file_lower = fn.file_rel.lower()
    name_lower = fn.name.lower()
    route_lower = (route or "").lower()
    class_name_lower = fn.class_info.name.lower() if fn.class_info else ""
    base_names_lower = (
        {b.rsplit(".", 1)[-1].lower() for b in fn.class_info.bases}
        if fn.class_info
        else set()
    )
    decorators = list(fn.node.decorator_list)
    if fn.class_info is not None:
        decorators.extend(fn.class_info.decorators)

    has_task_dec = any(_is_task_decorator(d) for d in decorators)
    has_http_dec = any(_is_http_decorator(d) for d in decorators)
    has_auth_dec = any(
        any(tok in _format_expr(d).lower() for tok in _PERMISSION_DECORATOR_TOKENS)
        for d in decorators
    )
    arg_names = [a.arg for a in fn.node.args.args]
    takes_request = any(arg in {"request", "req"} for arg in arg_names[:2])

    is_api_class = bool(base_names_lower & _API_CLASS_BASES) or class_name_lower.endswith(
        ("apiview", "viewset", "apicontroller")
    )
    is_ui_class = (
        bool(base_names_lower & _UI_CLASS_BASES)
        or (class_name_lower.endswith("view") and not is_api_class)
    )
    http_method_names = {
        "get",
        "post",
        "put",
        "patch",
        "delete",
        "create",
        "update",
        "partial_update",
        "destroy",
        "dispatch",
        "form_valid",
    }

    # Check entrypoint eligibility first so internal helpers aren't misclassified.
    is_entrypoint = (
        has_task_dec
        or has_http_dec
        or route is not None
        or (is_api_class and name_lower in http_method_names)
        or (is_ui_class and name_lower in http_method_names)
        or (
            takes_request
            and any(
                seg in file_lower
                for seg in ("view", "api", "web", "ui", "webhook", "hook", "route", "endpoint")
            )
        )
        or (
            any(seg in file_lower for seg in ("task", "worker", "job", "async"))
            and (
                fn.is_async
                or name_lower.endswith(("_task", "_job", "_worker"))
                or name_lower.startswith(("run_", "process_", "sync_", "handle_"))
            )
        )
        or (
            any(seg in file_lower for seg in ("webhook", "hook"))
            and (takes_request or "webhook" in name_lower or "hook" in name_lower)
        )
    )
    if not is_entrypoint and has_auth_dec and takes_request:
        is_entrypoint = True
    if not is_entrypoint:
        return None

    # Precedence: webhook > async (non-HTTP) > api > ui
    if (
        "webhook" in route_lower
        or "/hooks/" in route_lower
        or "webhook" in name_lower
        or "webhook" in class_name_lower
        or "webhook" in file_lower
    ):
        return EntrypointKind.WEBHOOK

    if has_task_dec or (
        not has_http_dec
        and route is None
        and not takes_request
        and not is_api_class
        and not is_ui_class
        and (
            any(seg in file_lower for seg in ("task", "worker", "job", "async"))
            or name_lower.endswith(("_task", "_job", "_worker"))
            or "task" in base_names_lower
            or "worker" in base_names_lower
        )
    ):
        return EntrypointKind.ASYNC

    if (
        is_api_class
        or "/api/" in route_lower
        or route_lower.startswith("/api")
        or "/v1/" in route_lower
        or "/v2/" in route_lower
        or "/graphql" in route_lower
        or any("api_view" in _format_expr(d).lower() for d in decorators)
        or "api" in file_lower.split("/")
        or file_lower.endswith("api.py")
        or name_lower.startswith("api_")
    ):
        return EntrypointKind.API

    return EntrypointKind.UI


def _collect_feature_terms(
    feature: str,
    aliases: Sequence[str],
) -> tuple[list[str], list[tuple[str, ...]]]:
    slugs: list[str] = []
    token_groups: list[tuple[str, ...]] = []
    for raw in (feature, *aliases):
        cleaned = raw.strip()
        if not cleaned:
            continue
        slug = _normalize_slug(cleaned)
        if slug and slug not in slugs:
            slugs.append(slug)
        toks = _tokenize_identifier(cleaned)
        if toks and toks not in token_groups:
            token_groups.append(toks)
    return slugs, token_groups


def _function_surface_text(fn: _IndexedFunction, route: str | None) -> tuple[str, str]:
    header_parts = [fn.qualified_name, fn.file_rel, route or ""]
    doc = ast.get_docstring(fn.node) or ""
    if doc:
        header_parts.append(doc)
    for dec in fn.node.decorator_list:
        header_parts.append(_format_expr(dec))
        if isinstance(dec, ast.Call):
            for arg in dec.args:
                s = _extract_str_constant(arg)
                if s:
                    header_parts.append(s)

    body_parts: list[str] = []
    for node in ast.walk(fn.node):
        if isinstance(node, ast.Name):
            body_parts.append(node.id)
        elif isinstance(node, ast.Attribute):
            body_parts.append(node.attr)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            if len(node.value) <= 120:
                body_parts.append(node.value)
    return " ".join(header_parts), " ".join(body_parts)


def _match_feature_reasons(
    fn: _IndexedFunction,
    route: str | None,
    callee_names: Sequence[str],
    slugs: Sequence[str],
    token_groups: Sequence[tuple[str, ...]],
) -> tuple[str, ...]:
    reasons: list[str] = []
    header_text, body_text = _function_surface_text(fn, route)
    header_slug = _normalize_slug(header_text)
    body_slug = _normalize_slug(body_text)
    callee_slug = _normalize_slug(" ".join(callee_names))

    header_tokens = set(_tokenize_identifier(header_text))
    body_tokens = set(_tokenize_identifier(body_text))
    callee_tokens = set(_tokenize_identifier(" ".join(callee_names)))

    name_slug = _normalize_slug(fn.name)
    route_slug = _normalize_slug(route or "")

    for slug in slugs:
        if slug in name_slug:
            reasons.append("name_match")
        elif route_slug and slug in route_slug:
            reasons.append("route_match")
        elif slug in header_slug:
            reasons.append("symbol_or_file_match")
        elif slug in callee_slug:
            reasons.append("callee_match")
        elif slug in body_slug:
            reasons.append("body_symbol_match")

    if not reasons:
        for toks in token_groups:
            tok_set = set(toks)
            if tok_set.issubset(header_tokens):
                reasons.append("header_tokens_match")
            elif tok_set.issubset(header_tokens | callee_tokens):
                reasons.append("callee_tokens_match")
            elif tok_set.issubset(header_tokens | body_tokens):
                reasons.append("body_tokens_match")

    return tuple(dict.fromkeys(reasons))


# ---------------------------------------------------------------------------
# Per-Function Boundary Extraction (AST)
# ---------------------------------------------------------------------------


def _call_kwargs_summary(call: ast.Call) -> list[str]:
    parts: list[str] = []
    for arg in call.args:
        parts.append(_format_expr(arg))
    for kw in call.keywords:
        val = _format_expr(kw.value)
        if kw.arg is not None:
            parts.append(f"{kw.arg}={val}")
        else:
            parts.append(f"**{val}")
    return parts


def _walk_without_nested_if(stmts: Sequence[ast.stmt]) -> list[ast.AST]:
    """Walk statements without descending into nested ``ast.If`` blocks."""
    nodes: list[ast.AST] = []
    stack: list[ast.AST] = list(stmts)
    while stack:
        cur = stack.pop()
        nodes.append(cur)
        if isinstance(cur, ast.If):
            continue
        stack.extend(ast.iter_child_nodes(cur))
    return nodes


def _is_forbidden_response_node(if_node: ast.If) -> bool:
    for sub in _walk_without_nested_if([*if_node.body, *if_node.orelse]):
        if isinstance(sub, ast.Raise) and sub.exc is not None:
            exc_name = _format_expr(sub.exc).lower()
            if any(
                tok in exc_name
                for tok in ("permissiondenied", "forbidden", "unauthorized", "httpexception", "abort")
            ):
                return True
        if isinstance(sub, ast.Call):
            cname = _format_expr(sub.func).lower()
            if any(tok in cname for tok in ("forbidden", "unauthorized", "abort")):
                return True
        if isinstance(sub, ast.Constant) and sub.value in (401, 403):
            return True
    return False


def _is_validation_error_node(if_node: ast.If) -> bool:
    for sub in _walk_without_nested_if([*if_node.body, *if_node.orelse]):
        if isinstance(sub, ast.Raise) and sub.exc is not None:
            exc_name = _format_expr(sub.exc).lower()
            if any(
                tok in exc_name
                for tok in ("valueerror", "validationerror", "badrequest", "httpexception")
            ):
                return True
        if isinstance(sub, ast.Constant) and sub.value in (400, 422):
            return True
    return False


def _extract_class_level_items(
    cls_info: _IndexedClass,
    items: list[SourceEvidenceItem],
) -> None:
    """Inspect class decorators and attributes like ``permission_classes`` / ``serializer_class``."""
    for dec in cls_info.decorators:
        dec_name = _format_expr(dec)
        dec_lower = dec_name.lower()
        if any(tok in dec_lower for tok in _PERMISSION_DECORATOR_TOKENS):
            items.append(
                SourceEvidenceItem(
                    category=BoundaryItemCategory.PERMISSION_CHECK,
                    name=dec_name,
                    detail=f"class decorator @{dec_name}",
                    file=cls_info.file_rel,
                    line=dec.lineno,
                    location=f"{cls_info.file_rel}:{dec.lineno}",
                    tags=("auth_decorator",),
                )
            )

    for stmt in cls_info.class_body:
        if not isinstance(stmt, ast.Assign):
            continue
        target_names = [
            _format_expr(t) for t in stmt.targets if isinstance(t, (ast.Name, ast.Attribute))
        ]
        for tname in target_names:
            if tname in {"permission_classes", "authentication_classes"}:
                items.append(
                    SourceEvidenceItem(
                        category=BoundaryItemCategory.PERMISSION_CHECK,
                        name=f"{cls_info.name}.{tname}",
                        detail=f"class attribute {tname}={ast.unparse(stmt.value) if hasattr(ast, 'unparse') else '...'}",
                        file=cls_info.file_rel,
                        line=stmt.lineno,
                        location=f"{cls_info.file_rel}:{stmt.lineno}",
                        tags=("drf_permission_classes",),
                    )
                )
            elif tname in {"serializer_class", "form_class", "schema_class"}:
                val_name = _format_expr(stmt.value)
                items.append(
                    SourceEvidenceItem(
                        category=BoundaryItemCategory.INPUT_VALIDATION,
                        name=val_name or tname,
                        detail=f"class attribute {tname}={val_name}",
                        file=cls_info.file_rel,
                        line=stmt.lineno,
                        location=f"{cls_info.file_rel}:{stmt.lineno}",
                        tags=("schema_validation",),
                    )
                )


def _extract_function_boundary_items(fn: _IndexedFunction) -> list[SourceEvidenceItem]:
    """Extract permission, validation, scoping, and sink items directly from ``fn``."""
    items: list[SourceEvidenceItem] = []

    if fn.class_info is not None:
        _extract_class_level_items(fn.class_info, items)
        for base in fn.class_info.bases:
            b_lower = base.rsplit(".", 1)[-1].lower()
            if b_lower in {"loginrequiredmixin", "permissionrequiredmixin", "userpassestestmixin"}:
                items.append(
                    SourceEvidenceItem(
                        category=BoundaryItemCategory.PERMISSION_CHECK,
                        name=base,
                        detail=f"class mixin {base}",
                        file=fn.class_info.file_rel,
                        line=fn.class_info.line,
                        location=f"{fn.class_info.file_rel}:{fn.class_info.line}",
                        tags=("auth_mixin",),
                    )
                )

    # 1. Function decorators
    for dec in fn.node.decorator_list:
        dec_name = _format_expr(dec)
        dec_lower = dec_name.lower()
        if any(tok in dec_lower for tok in _PERMISSION_DECORATOR_TOKENS):
            tags = ["auth_decorator"]
            if "permission" in dec_lower or "role" in dec_lower or "scope" in dec_lower:
                tags.append("permission_decorator")
            if any(tok in dec_lower for tok in _SIGNATURE_CHECK_TOKENS):
                tags.append("signature_verification")
            items.append(
                SourceEvidenceItem(
                    category=BoundaryItemCategory.PERMISSION_CHECK,
                    name=dec_name,
                    detail=f"decorator @{dec_name}",
                    file=fn.file_rel,
                    line=dec.lineno,
                    location=f"{fn.file_rel}:{dec.lineno}",
                    tags=tuple(tags),
                )
            )

    # 2. Typed schema / FastAPI Body/Query annotations on parameters
    all_args = list(fn.node.args.posonlyargs) + list(fn.node.args.args) + list(fn.node.args.kwonlyargs)
    for arg in all_args:
        if arg.annotation is None:
            continue
        ann_text = _format_expr(arg.annotation)
        ann_lower = ann_text.lower()
        if any(tok in ann_lower for tok in ("schema", "payload", "input", "request", "form", "model")) and ann_lower not in {"httprequest", "request"}:
            items.append(
                SourceEvidenceItem(
                    category=BoundaryItemCategory.INPUT_VALIDATION,
                    name=ann_text,
                    detail=f"typed parameter {arg.arg}: {ann_text}",
                    file=fn.file_rel,
                    line=arg.lineno,
                    location=f"{fn.file_rel}:{arg.lineno}",
                    tags=("schema_validation",),
                )
            )
    for default in fn.node.args.defaults:
        if isinstance(default, ast.Call):
            cname = _format_expr(default.func)
            if cname.rsplit(".", 1)[-1] in {"Body", "Query", "Path", "Header", "Form"}:
                items.append(
                    SourceEvidenceItem(
                        category=BoundaryItemCategory.INPUT_VALIDATION,
                        name=cname,
                        detail=f"parameter validator {cname}(...)",
                        file=fn.file_rel,
                        line=default.lineno,
                        location=f"{fn.file_rel}:{default.lineno}",
                        tags=("schema_validation",),
                    )
                )

    # 3. Walk statements & expressions inside function body
    for node in ast.walk(fn.node):
        if isinstance(node, ast.If):
            test_text = ast.unparse(node.test) if hasattr(ast, "unparse") else _format_expr(node.test)
            test_lower = test_text.lower()
            has_forbid = _is_forbidden_response_node(node)
            if any(tok in test_lower for tok in _AUTH_ATTR_TOKENS) or (
                has_forbid and any(tok in test_lower for tok in ("perm", "auth", "role", "signature", "hmac", "token", "admin", "staff"))
            ):
                tags = ["inline_auth_check"]
                if any(tok in test_lower for tok in _SIGNATURE_CHECK_TOKENS):
                    tags.append("signature_verification")
                if any(tok in test_lower for tok in ("perm", "role")):
                    tags.append("permission_check_guard")
                items.append(
                    SourceEvidenceItem(
                        category=BoundaryItemCategory.PERMISSION_CHECK,
                        name="inline_auth_guard",
                        detail=f"if {test_text}",
                        file=fn.file_rel,
                        line=node.lineno,
                        location=f"{fn.file_rel}:{node.lineno}",
                        tags=tuple(tags),
                    )
                )
            elif any(tok in test_lower for tok in ("owner", "tenant", "org", "member", "workspace")) and (
                has_forbid or "404" in test_lower or any(isinstance(s, ast.Raise) for s in node.body)
            ):
                items.append(
                    SourceEvidenceItem(
                        category=BoundaryItemCategory.TARGET_SCOPING,
                        name="post_lookup_scope_guard",
                        detail=f"if {test_text}",
                        file=fn.file_rel,
                        line=node.lineno,
                        location=f"{fn.file_rel}:{node.lineno}",
                        tags=("post_lookup_scope_check",),
                    )
                )
            elif _is_validation_error_node(node):
                items.append(
                    SourceEvidenceItem(
                        category=BoundaryItemCategory.INPUT_VALIDATION,
                        name="inline_validation_guard",
                        detail=f"if {test_text}",
                        file=fn.file_rel,
                        line=node.lineno,
                        location=f"{fn.file_rel}:{node.lineno}",
                        tags=("explicit_guard",),
                    )
                )

        if not isinstance(node, ast.Call):
            continue

        call_name = _format_expr(node.func)
        call_lower = call_name.lower()
        tail = call_lower.rsplit(".", 1)[-1]
        args_summary = _call_kwargs_summary(node)
        args_joined = ", ".join(args_summary)
        args_lower = args_joined.lower()

        # A. Permission calls
        if any(
            tail == tok or tok in call_lower
            for tok in _PERMISSION_CALL_TOKENS
        ):
            tags = ["inline_permission_call"]
            if any(tok in call_lower or tok in args_lower for tok in _SIGNATURE_CHECK_TOKENS):
                tags.append("signature_verification")
            if "perm" in call_lower or "role" in call_lower or "owner" in call_lower or "member" in call_lower:
                tags.append("object_or_role_permission")
            items.append(
                SourceEvidenceItem(
                    category=BoundaryItemCategory.PERMISSION_CHECK,
                    name=call_name,
                    detail=f"call {call_name}({args_joined})",
                    file=fn.file_rel,
                    line=node.lineno,
                    location=f"{fn.file_rel}:{node.lineno}",
                    tags=tuple(tags),
                )
            )
            continue

        # B. Input validation / normalization calls
        val_tags: list[str] = []
        if tail in {"strip", "lstrip", "rstrip"}:
            val_tags.append("strip")
        elif tail in {"lower", "upper", "casefold"}:
            val_tags.append("case_normalize")
        elif call_lower.endswith("unicodedata.normalize") or tail == "normalize":
            val_tags.append("unicode_normalize")
        elif tail in {"urlparse", "urlsplit"} or "urlvalidator" in call_lower:
            val_tags.append("url_parse")
        elif tail in {"normpath", "resolve"}:
            val_tags.append("path_normalize")
        elif call_lower in {"re.match", "re.fullmatch", "re.search", "re.sub"}:
            val_tags.append("regex_check")
        elif tail in {"is_valid", "model_validate", "model_validate_json", "full_clean"} or (
            any(tok in call_lower for tok in ("serializer", "schema", "form"))
            and tail not in {"get", "filter", "save", "update"}
        ):
            val_tags.append("schema_validation")
        elif tail in {"escape", "bleach.clean", "strip_tags"} or call_lower == "bleach.clean":
            val_tags.append("html_escape")
        elif tail.startswith(_VALIDATION_CALL_PREFIXES):
            val_tags.append("custom_validator")

        if val_tags:
            items.append(
                SourceEvidenceItem(
                    category=BoundaryItemCategory.INPUT_VALIDATION,
                    name=call_name,
                    detail=f"call {call_name}({args_joined})",
                    file=fn.file_rel,
                    line=node.lineno,
                    location=f"{fn.file_rel}:{node.lineno}",
                    tags=tuple(val_tags),
                )
            )

        # C. Target selection / scoping lookups
        is_chained_call = isinstance(node.func, ast.Attribute) and isinstance(
            node.func.value, ast.Call
        )
        has_lookup_args = bool(node.args or node.keywords)
        is_orm_lookup = (
            tail in _ORM_LOOKUP_CALLS
            and (has_lookup_args or not is_chained_call)
            and not (is_chained_call and tail in {"first", "one", "one_or_none", "scalar_one", "scalar_one_or_none"})
            and (
                ".objects." in call_lower
                or "queryset" in call_lower
                or "session." in call_lower
                or ".query." in call_lower
                or tail in {"get_object_or_404", "get_list_or_404", "filter_by", "get_object", "get_queryset"}
                or (tail in {"filter", "where"} and len(node.keywords) > 0)
            )
        )
        if is_orm_lookup:
            kw_names = {kw.arg.lower() for kw in node.keywords if kw.arg}
            has_scope_kw = bool(kw_names & _SCOPE_PREDICATE_KEYS) or any(
                any(k in kw for k in _SCOPE_PREDICATE_KEYS) for kw in kw_names
            )
            has_actor_ref = any(
                tok in args_lower for tok in ("request.user", "current_user", "actor", "tenant")
            )
            scope_tags: list[str] = []
            if has_scope_kw or has_actor_ref:
                scope_tags.append("tenant_or_owner_scoped")
            else:
                scope_tags.append("unscoped_lookup")
            if any(any(sfx in kw for sfx in _FUZZY_LOOKUP_SUFFIXES) for kw in kw_names):
                scope_tags.append("fuzzy_or_suffix_lookup")
            items.append(
                SourceEvidenceItem(
                    category=BoundaryItemCategory.TARGET_SCOPING,
                    name=call_name,
                    detail=f"lookup {call_name}({args_joined}) [{', '.join(scope_tags)}]",
                    file=fn.file_rel,
                    line=node.lineno,
                    location=f"{fn.file_rel}:{node.lineno}",
                    tags=tuple(scope_tags),
                )
            )
            continue

        # D. Update sinks
        sink_tags: list[str] = []
        if tail in _ORM_MUTATION_METHODS:
            sink_tags.append("db_write")
        elif tail in _ASYNC_DISPATCH_METHODS:
            sink_tags.append("async_dispatch")
        elif tail.startswith(_MUTATING_CALL_PREFIXES):
            sink_tags.append("state_mutation")
        elif call_lower in {"subprocess.run", "subprocess.popen", "os.system"}:
            sink_tags.append("subprocess_exec")
        elif tail in {"write_text", "write_bytes"}:
            sink_tags.append("file_write")
        elif call_lower.startswith(("requests.", "httpx.")) and tail in {"post", "put", "patch", "delete"}:
            sink_tags.append("outbound_http")

        if sink_tags:
            items.append(
                SourceEvidenceItem(
                    category=BoundaryItemCategory.UPDATE_SINK,
                    name=call_name,
                    detail=f"sink {call_name}({args_joined})",
                    file=fn.file_rel,
                    line=node.lineno,
                    location=f"{fn.file_rel}:{node.lineno}",
                    tags=tuple(sink_tags),
                )
            )

    return items


def _collect_entrypoint_boundaries(
    fn: _IndexedFunction,
    *,
    by_qname: dict[str, _IndexedFunction],
    by_short_name: dict[str, list[_IndexedFunction]],
    max_call_depth: int,
) -> tuple[
    tuple[SourceEvidenceItem, ...],
    tuple[SourceEvidenceItem, ...],
    tuple[SourceEvidenceItem, ...],
    tuple[SourceEvidenceItem, ...],
    tuple[str, ...],
]:
    """Collect boundary items across ``fn`` and bounded internal callees."""
    visited: set[str] = set()
    callees_followed: list[str] = []
    all_items: list[SourceEvidenceItem] = []

    def _visit(current: _IndexedFunction, depth: int) -> None:
        if current.qualified_name in visited:
            return
        visited.add(current.qualified_name)
        if depth > 0:
            callees_followed.append(f"{current.qualified_name} ({current.file_rel}:{current.line})")
        all_items.extend(_extract_function_boundary_items(current))
        if depth >= max_call_depth:
            return
        for stmt in current.node.body:
            for node in ast.walk(stmt):
                if not isinstance(node, ast.Call):
                    continue
                call_name = _format_expr(node.func)
                callee = _resolve_callee(call_name, current, by_qname, by_short_name)
                if callee is not None and callee.qualified_name not in visited:
                    _visit(callee, depth + 1)

    _visit(fn, 0)

    deduped: dict[tuple[str, str, str], SourceEvidenceItem] = {}
    for item in all_items:
        key = (item.category.value, item.name, item.location)
        if key not in deduped:
            deduped[key] = item

    sorted_items = sorted(deduped.values(), key=lambda i: (i.file, i.line, i.name))
    perms = tuple(i for i in sorted_items if i.category == BoundaryItemCategory.PERMISSION_CHECK)
    vals = tuple(i for i in sorted_items if i.category == BoundaryItemCategory.INPUT_VALIDATION)
    scopes = tuple(i for i in sorted_items if i.category == BoundaryItemCategory.TARGET_SCOPING)
    sinks = tuple(i for i in sorted_items if i.category == BoundaryItemCategory.UPDATE_SINK)
    return perms, vals, scopes, sinks, tuple(callees_followed)


# ---------------------------------------------------------------------------
# Cross-Path Diff Engine
# ---------------------------------------------------------------------------


def _score_baseline(ep: EntrypointBoundaryRecord) -> tuple[int, int, str]:
    kind_priority = {
        EntrypointKind.API: 4,
        EntrypointKind.UI: 3,
        EntrypointKind.WEBHOOK: 2,
        EntrypointKind.ASYNC: 1,
    }
    has_scoped = int(
        any(
            "tenant_or_owner_scoped" in s.tags or "post_lookup_scope_check" in s.tags
            for s in ep.target_scopings
        )
    )
    control_score = (
        len(ep.permission_checks) * 3
        + has_scoped * 3
        + len(ep.input_validations) * 2
        + len(ep.update_sinks)
    )
    return (control_score, kind_priority.get(ep.kind, 0), ep.entrypoint_id)


def _select_baseline(
    entrypoints: Sequence[EntrypointBoundaryRecord],
    *,
    baseline_kind: str | None,
    baseline_entrypoint: str | None,
) -> EntrypointBoundaryRecord | None:
    if not entrypoints:
        return None
    if baseline_entrypoint:
        for ep in entrypoints:
            if baseline_entrypoint in {ep.entrypoint_id, ep.name, ep.qualified_name}:
                return ep
        raise ContractViolationError(
            f"Requested baseline entrypoint {baseline_entrypoint!r} was not found among matched entrypoints."
        )
    if baseline_kind:
        if baseline_kind not in VALID_ENTRYPOINT_KINDS:
            raise ContractViolationError(
                f"baseline_kind must be one of {VALID_ENTRYPOINT_KINDS}, got {baseline_kind!r}."
            )
        matching = [ep for ep in entrypoints if ep.kind.value == baseline_kind]
        if not matching:
            raise ContractViolationError(
                f"No matched entrypoints of baseline_kind={baseline_kind!r} were found."
            )
        return max(matching, key=_score_baseline)
    return max(entrypoints, key=_score_baseline)


def _has_scoped_check(ep: EntrypointBoundaryRecord) -> bool:
    return any(
        "tenant_or_owner_scoped" in s.tags or "post_lookup_scope_check" in s.tags
        for s in ep.target_scopings
    )


def _has_unscoped_lookup(ep: EntrypointBoundaryRecord) -> bool:
    return any("unscoped_lookup" in s.tags for s in ep.target_scopings)


def _has_fuzzy_lookup(ep: EntrypointBoundaryRecord) -> bool:
    return any("fuzzy_or_suffix_lookup" in s.tags for s in ep.target_scopings)


def _validation_tags(ep: EntrypointBoundaryRecord) -> set[str]:
    tags: set[str] = set()
    for item in ep.input_validations:
        tags.update(item.tags)
    return tags


def _permission_tags(ep: EntrypointBoundaryRecord) -> set[str]:
    tags: set[str] = set()
    for item in ep.permission_checks:
        tags.update(item.tags)
    return tags


def _collect_locations(*groups: Sequence[SourceEvidenceItem], fallback: str) -> tuple[str, ...]:
    locs: list[str] = []
    for grp in groups:
        for item in grp:
            if item.location not in locs:
                locs.append(item.location)
    if fallback and fallback not in locs:
        locs.append(fallback)
    return tuple(locs)


def _compute_cross_path_diffs(
    entrypoints: Sequence[EntrypointBoundaryRecord],
    baseline: EntrypointBoundaryRecord | None,
) -> tuple[BoundaryDiffFinding, ...]:
    if baseline is None or len(entrypoints) < 2:
        return ()

    findings: list[BoundaryDiffFinding] = []
    counter = 1

    def _next_id() -> str:
        nonlocal counter
        fid = f"diff-{counter:03d}"
        counter += 1
        return fid

    base_perm_tags = _permission_tags(baseline)
    base_val_tags = _validation_tags(baseline)
    base_scoped = _has_scoped_check(baseline)
    base_fuzzy = _has_fuzzy_lookup(baseline)

    for ep in entrypoints:
        if ep.entrypoint_id == baseline.entrypoint_id:
            continue

        ep_perm_tags = _permission_tags(ep)
        ep_val_tags = _validation_tags(ep)
        ep_scoped = _has_scoped_check(ep)
        ep_unscoped = _has_unscoped_lookup(ep)
        ep_fuzzy = _has_fuzzy_lookup(ep)

        # 1. Permission boundary diffs
        if baseline.permission_checks and not ep.permission_checks:
            locs = _collect_locations(
                baseline.permission_checks, ep.update_sinks, fallback=ep.location
            )
            locs = tuple(dict.fromkeys((ep.location, *locs)))
            findings.append(
                BoundaryDiffFinding(
                    finding_id=_next_id(),
                    category=DiffCategory.MISSING_PERMISSION_CHECK,
                    baseline_entrypoint_id=baseline.entrypoint_id,
                    compared_entrypoint_id=ep.entrypoint_id,
                    baseline_kind=baseline.kind,
                    compared_kind=ep.kind,
                    summary=(
                        f"{ep.kind.value.upper()} entrypoint '{ep.name}' has no observed permission check "
                        f"(unlike baseline {baseline.kind.value.upper()} entrypoint '{baseline.name}')."
                    ),
                    evidence_locations=locs,
                    details={
                        "baseline_permission_checks": [p.name for p in baseline.permission_checks],
                        "compared_permission_checks": [],
                        "compared_update_sinks": [s.name for s in ep.update_sinks],
                    },
                )
            )
        elif ep.permission_checks and not baseline.permission_checks:
            locs = _collect_locations(
                ep.permission_checks, baseline.update_sinks, fallback=baseline.location
            )
            locs = tuple(dict.fromkeys((baseline.location, *locs)))
            findings.append(
                BoundaryDiffFinding(
                    finding_id=_next_id(),
                    category=DiffCategory.MISSING_PERMISSION_CHECK,
                    baseline_entrypoint_id=ep.entrypoint_id,
                    compared_entrypoint_id=baseline.entrypoint_id,
                    baseline_kind=ep.kind,
                    compared_kind=baseline.kind,
                    summary=(
                        f"Baseline {baseline.kind.value.upper()} entrypoint '{baseline.name}' has no observed "
                        f"permission check compared to {ep.kind.value.upper()} entrypoint '{ep.name}'."
                    ),
                    evidence_locations=locs,
                    details={
                        "baseline_permission_checks": [p.name for p in ep.permission_checks],
                        "compared_permission_checks": [],
                    },
                )
            )
        elif baseline.permission_checks and ep.permission_checks:
            base_rbac = bool(
                base_perm_tags
                & {"permission_decorator", "drf_permission_classes", "object_or_role_permission", "permission_check_guard"}
            )
            ep_rbac = bool(
                ep_perm_tags
                & {"permission_decorator", "drf_permission_classes", "object_or_role_permission", "permission_check_guard"}
            )
            if base_rbac != ep_rbac or (
                ("signature_verification" in base_perm_tags)
                != ("signature_verification" in ep_perm_tags)
            ):
                locs = _collect_locations(
                    baseline.permission_checks, ep.permission_checks, fallback=ep.location
                )
                findings.append(
                    BoundaryDiffFinding(
                        finding_id=_next_id(),
                        category=DiffCategory.PERMISSION_MODEL_MISMATCH,
                        baseline_entrypoint_id=baseline.entrypoint_id,
                        compared_entrypoint_id=ep.entrypoint_id,
                        baseline_kind=baseline.kind,
                        compared_kind=ep.kind,
                        summary=(
                            f"Permission model differs between baseline '{baseline.name}' ({sorted(base_perm_tags)}) "
                            f"and '{ep.name}' ({sorted(ep_perm_tags)})."
                        ),
                        evidence_locations=locs,
                        details={
                            "baseline_permission_tags": sorted(base_perm_tags),
                            "compared_permission_tags": sorted(ep_perm_tags),
                        },
                    )
                )

        # 2. Target selection & scoping diffs
        if base_scoped and not ep_scoped and (ep_unscoped or ep.update_sinks):
            locs = _collect_locations(
                baseline.target_scopings,
                ep.target_scopings,
                ep.update_sinks,
                fallback=ep.location,
            )
            locs = tuple(dict.fromkeys((ep.location, *locs)))
            findings.append(
                BoundaryDiffFinding(
                    finding_id=_next_id(),
                    category=DiffCategory.MISSING_TARGET_SCOPING,
                    baseline_entrypoint_id=baseline.entrypoint_id,
                    compared_entrypoint_id=ep.entrypoint_id,
                    baseline_kind=baseline.kind,
                    compared_kind=ep.kind,
                    summary=(
                        f"{ep.kind.value.upper()} entrypoint '{ep.name}' lacks tenant/owner scoping filter "
                        f"(unscoped_lookup={ep_unscoped}) present on baseline '{baseline.name}'."
                    ),
                    evidence_locations=locs,
                    details={
                        "baseline_scopings": [s.detail for s in baseline.target_scopings],
                        "compared_scopings": [s.detail for s in ep.target_scopings],
                    },
                )
            )
        elif ep_scoped and not base_scoped and (_has_unscoped_lookup(baseline) or baseline.update_sinks):
            locs = _collect_locations(
                ep.target_scopings,
                baseline.target_scopings,
                baseline.update_sinks,
                fallback=baseline.location,
            )
            findings.append(
                BoundaryDiffFinding(
                    finding_id=_next_id(),
                    category=DiffCategory.MISSING_TARGET_SCOPING,
                    baseline_entrypoint_id=ep.entrypoint_id,
                    compared_entrypoint_id=baseline.entrypoint_id,
                    baseline_kind=ep.kind,
                    compared_kind=baseline.kind,
                    summary=(
                        f"Baseline {baseline.kind.value.upper()} entrypoint '{baseline.name}' lacks tenant/owner "
                        f"scoping filter observed on '{ep.name}'."
                    ),
                    evidence_locations=locs,
                    details={
                        "baseline_scopings": [s.detail for s in ep.target_scopings],
                        "compared_scopings": [s.detail for s in baseline.target_scopings],
                    },
                )
            )
        elif base_fuzzy != ep_fuzzy:
            locs = _collect_locations(
                baseline.target_scopings, ep.target_scopings, fallback=ep.location
            )
            findings.append(
                BoundaryDiffFinding(
                    finding_id=_next_id(),
                    category=DiffCategory.SCOPING_MISMATCH,
                    baseline_entrypoint_id=baseline.entrypoint_id,
                    compared_entrypoint_id=ep.entrypoint_id,
                    baseline_kind=baseline.kind,
                    compared_kind=ep.kind,
                    summary=(
                        f"Target lookup predicate precision differs between '{baseline.name}' and '{ep.name}' "
                        f"(fuzzy/suffix lookup mismatch)."
                    ),
                    evidence_locations=locs,
                    details={
                        "baseline_fuzzy_lookup": base_fuzzy,
                        "compared_fuzzy_lookup": ep_fuzzy,
                    },
                )
            )

        # 3. Input validation & normalization diffs
        if baseline.input_validations and not ep.input_validations:
            locs = _collect_locations(
                baseline.input_validations, ep.update_sinks, fallback=ep.location
            )
            locs = tuple(dict.fromkeys((ep.location, *locs)))
            findings.append(
                BoundaryDiffFinding(
                    finding_id=_next_id(),
                    category=DiffCategory.MISSING_INPUT_VALIDATION,
                    baseline_entrypoint_id=baseline.entrypoint_id,
                    compared_entrypoint_id=ep.entrypoint_id,
                    baseline_kind=baseline.kind,
                    compared_kind=ep.kind,
                    summary=(
                        f"{ep.kind.value.upper()} entrypoint '{ep.name}' has no observed input validation or "
                        f"normalization (baseline '{baseline.name}' uses {sorted(base_val_tags)})."
                    ),
                    evidence_locations=locs,
                    details={
                        "baseline_validation_tags": sorted(base_val_tags),
                        "compared_validation_tags": [],
                    },
                )
            )
        elif ep.input_validations and not baseline.input_validations:
            locs = _collect_locations(
                ep.input_validations, baseline.update_sinks, fallback=baseline.location
            )
            findings.append(
                BoundaryDiffFinding(
                    finding_id=_next_id(),
                    category=DiffCategory.MISSING_INPUT_VALIDATION,
                    baseline_entrypoint_id=ep.entrypoint_id,
                    compared_entrypoint_id=baseline.entrypoint_id,
                    baseline_kind=ep.kind,
                    compared_kind=baseline.kind,
                    summary=(
                        f"Baseline {baseline.kind.value.upper()} entrypoint '{baseline.name}' lacks input validation "
                        f"observed on '{ep.name}' ({sorted(ep_val_tags)})."
                    ),
                    evidence_locations=locs,
                    details={
                        "baseline_validation_tags": sorted(ep_val_tags),
                        "compared_validation_tags": [],
                    },
                )
            )
        elif base_val_tags != ep_val_tags:
            missing_on_ep = sorted(base_val_tags - ep_val_tags)
            extra_on_ep = sorted(ep_val_tags - base_val_tags)
            locs = _collect_locations(
                baseline.input_validations, ep.input_validations, fallback=ep.location
            )
            findings.append(
                BoundaryDiffFinding(
                    finding_id=_next_id(),
                    category=DiffCategory.INPUT_NORMALIZATION_MISMATCH,
                    baseline_entrypoint_id=baseline.entrypoint_id,
                    compared_entrypoint_id=ep.entrypoint_id,
                    baseline_kind=baseline.kind,
                    compared_kind=ep.kind,
                    summary=(
                        f"Input validation/normalization differs between '{baseline.name}' and '{ep.name}' "
                        f"(missing={missing_on_ep}, distinct={extra_on_ep})."
                    ),
                    evidence_locations=locs,
                    details={
                        "baseline_validation_tags": sorted(base_val_tags),
                        "compared_validation_tags": sorted(ep_val_tags),
                        "missing_on_compared": missing_on_ep,
                        "only_on_compared": extra_on_ep,
                    },
                )
            )

        # 4. Update sink asymmetry
        base_sink_tags = {t for s in baseline.update_sinks for t in s.tags}
        ep_sink_tags = {t for s in ep.update_sinks for t in s.tags}
        base_sink_names = {s.name.rsplit(".", 1)[-1] for s in baseline.update_sinks}
        ep_sink_names = {s.name.rsplit(".", 1)[-1] for s in ep.update_sinks}
        if (baseline.update_sinks or ep.update_sinks) and (
            base_sink_tags != ep_sink_tags or base_sink_names != ep_sink_names
        ):
            locs = _collect_locations(
                baseline.update_sinks, ep.update_sinks, fallback=ep.location
            )
            findings.append(
                BoundaryDiffFinding(
                    finding_id=_next_id(),
                    category=DiffCategory.UPDATE_SINK_ASYMMETRY,
                    baseline_entrypoint_id=baseline.entrypoint_id,
                    compared_entrypoint_id=ep.entrypoint_id,
                    baseline_kind=baseline.kind,
                    compared_kind=ep.kind,
                    summary=(
                        f"Update sink behavior differs between '{baseline.name}' ({sorted(base_sink_names)}) "
                        f"and '{ep.name}' ({sorted(ep_sink_names)})."
                    ),
                    evidence_locations=locs,
                    details={
                        "baseline_sinks": [s.name for s in baseline.update_sinks],
                        "compared_sinks": [s.name for s in ep.update_sinks],
                        "baseline_sink_tags": sorted(base_sink_tags),
                        "compared_sink_tags": sorted(ep_sink_tags),
                    },
                )
            )

    return tuple(findings)


# ---------------------------------------------------------------------------
# Test Coverage Gap Scanner
# ---------------------------------------------------------------------------


def _scan_test_cases(
    test_root: Path,
    *,
    max_file_bytes: int,
) -> tuple[list[str], list[str], list[_IndexedTestCase]]:
    test_files = _iter_python_files(test_root, only_tests=True)
    analyzed_test_files: list[str] = []
    skipped: list[str] = []
    cases: list[_IndexedTestCase] = []

    def _extract_case(
        fn_node: ast.FunctionDef | ast.AsyncFunctionDef,
        rel_posix: str,
        class_name: str | None,
    ) -> _IndexedTestCase:
        selector = (
            f"{rel_posix}::{class_name}::{fn_node.name}"
            if class_name
            else f"{rel_posix}::{fn_node.name}"
        )
        names: set[str] = {fn_node.name.lower()}
        strings: list[str] = []
        tokens: set[str] = {fn_node.name.lower(), *_tokenize_identifier(fn_node.name)}
        for sub in ast.walk(fn_node):
            if isinstance(sub, ast.Name):
                names.add(sub.id.lower())
                tokens.add(sub.id.lower())
                tokens.update(_tokenize_identifier(sub.id))
            elif isinstance(sub, ast.Attribute):
                names.add(sub.attr.lower())
                tokens.add(sub.attr.lower())
                tokens.update(_tokenize_identifier(sub.attr))
            elif isinstance(sub, ast.Constant):
                if isinstance(sub.value, str) and len(sub.value) <= 200:
                    val_lower = sub.value.lower()
                    strings.append(val_lower)
                    tokens.add(val_lower)
                    tokens.update(_tokenize_identifier(sub.value))
                elif isinstance(sub.value, int) and sub.value in (400, 401, 403, 404, 422):
                    tokens.add(str(sub.value))
        return _IndexedTestCase(
            selector=selector,
            file_rel=rel_posix,
            line=fn_node.lineno,
            name=fn_node.name,
            referenced_names=frozenset(names),
            string_literals=tuple(strings),
            lowered_tokens=frozenset(tokens),
        )

    for abs_path, rel_posix in test_files:
        tree = _read_python_ast(abs_path, rel_posix, max_file_bytes=max_file_bytes)
        if tree is None:
            skipped.append(rel_posix)
            continue
        analyzed_test_files.append(rel_posix)
        for stmt in tree.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)) and stmt.name.startswith("test_"):
                cases.append(_extract_case(stmt, rel_posix, None))
            elif isinstance(stmt, ast.ClassDef) and stmt.name.startswith("Test"):
                for member in stmt.body:
                    if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)) and member.name.startswith("test_"):
                        cases.append(_extract_case(member, rel_posix, stmt.name))

    return analyzed_test_files, skipped, cases


def _match_tests_for_entrypoint(
    ep: EntrypointBoundaryRecord,
    cases: Sequence[_IndexedTestCase],
) -> list[_IndexedTestCase]:
    matched: list[_IndexedTestCase] = []
    ep_name_lower = ep.name.lower()
    class_name_lower = ""
    parts = ep.qualified_name.split(".")
    if len(parts) >= 2 and parts[-2][:1].isupper():
        class_name_lower = parts[-2].lower()
    route_lower = (ep.route or "").lower().rstrip("/")
    route_variants = set()
    if route_lower:
        route_variants.add(route_lower)
        route_variants.add(route_lower.split("<")[0].rstrip("/"))
        route_variants = {r for r in route_variants if len(r) >= 4}

    for case in cases:
        hit = ep_name_lower in case.referenced_names or (
            class_name_lower and class_name_lower in case.referenced_names
        )
        if not hit and route_variants:
            hit = any(
                rv in s for rv in route_variants for s in case.string_literals
            )
        if not hit:
            # Match by test name explicitly containing entrypoint name
            hit = ep_name_lower in case.name.lower()
        if hit:
            matched.append(case)
    return matched


def _compute_test_coverage_gaps(
    entrypoints: Sequence[EntrypointBoundaryRecord],
    cases: Sequence[_IndexedTestCase],
) -> tuple[dict[str, tuple[str, ...]], tuple[TestCoverageGap, ...]]:
    refs_by_ep: dict[str, tuple[str, ...]] = {}
    gaps: list[TestCoverageGap] = []
    counter = 1

    def _next_gap_id() -> str:
        nonlocal counter
        gid = f"gap-{counter:03d}"
        counter += 1
        return gid

    for ep in entrypoints:
        matched = _match_tests_for_entrypoint(ep, cases)
        refs_by_ep[ep.entrypoint_id] = tuple(c.selector for c in matched)

        if not matched:
            untested = tuple(
                dict.fromkeys(
                    [ep.name]
                    + [s.name for s in ep.update_sinks]
                    + [s.name for s in ep.target_scopings]
                )
            )
            locs = _collect_locations(
                ep.update_sinks, ep.target_scopings, fallback=ep.location
            )
            locs = tuple(dict.fromkeys((ep.location, *locs)))
            gaps.append(
                TestCoverageGap(
                    gap_id=_next_gap_id(),
                    entrypoint_id=ep.entrypoint_id,
                    kind=ep.kind,
                    entrypoint_location=ep.location,
                    gap_type=CoverageGapType.NO_TEST_REFERENCE,
                    untested_items=untested,
                    evidence_locations=locs,
                    summary=(
                        f"{ep.kind.value.upper()} entrypoint '{ep.name}' has no matching test selector "
                        f"in the inspected test directory."
                    ),
                )
            )
            continue

        combined_tokens = set().union(*(c.lowered_tokens for c in matched))
        combined_strings = " ".join(s for c in matched for s in c.string_literals)
        combined_surface = combined_tokens | set(_tokenize_identifier(combined_strings))

        def _has_any_hint(hints: tuple[str, ...]) -> bool:
            for hint in hints:
                if hint in combined_surface or any(hint in tok for tok in combined_surface):
                    return True
            return False

        test_locs = tuple(f"{c.file_rel}:{c.line}" for c in matched)

        if not _has_any_hint(_TEST_AUTH_HINTS):
            gaps.append(
                TestCoverageGap(
                    gap_id=_next_gap_id(),
                    entrypoint_id=ep.entrypoint_id,
                    kind=ep.kind,
                    entrypoint_location=ep.location,
                    gap_type=CoverageGapType.MISSING_PERMISSION_TEST_ASSERTION,
                    untested_items=tuple(p.name for p in ep.permission_checks) or ("authorization_rejection",),
                    evidence_locations=tuple(dict.fromkeys((ep.location, *test_locs))),
                    summary=(
                        f"Tests referencing '{ep.name}' do not appear to assert unauthorized/forbidden "
                        f"(401/403/signature) rejection behavior."
                    ),
                )
            )

        if (ep.target_scopings or ep.update_sinks) and not _has_any_hint(_TEST_SCOPE_HINTS):
            gaps.append(
                TestCoverageGap(
                    gap_id=_next_gap_id(),
                    entrypoint_id=ep.entrypoint_id,
                    kind=ep.kind,
                    entrypoint_location=ep.location,
                    gap_type=CoverageGapType.MISSING_SCOPING_TEST_ASSERTION,
                    untested_items=tuple(s.name for s in ep.target_scopings) or ("cross_tenant_isolation",),
                    evidence_locations=tuple(dict.fromkeys((ep.location, *test_locs))),
                    summary=(
                        f"Tests referencing '{ep.name}' do not appear to exercise cross-owner or "
                        f"cross-tenant target scoping boundaries."
                    ),
                )
            )

        if (ep.input_validations or ep.update_sinks) and not _has_any_hint(_TEST_VALIDATION_HINTS):
            gaps.append(
                TestCoverageGap(
                    gap_id=_next_gap_id(),
                    entrypoint_id=ep.entrypoint_id,
                    kind=ep.kind,
                    entrypoint_location=ep.location,
                    gap_type=CoverageGapType.MISSING_VALIDATION_TEST_ASSERTION,
                    untested_items=tuple(v.name for v in ep.input_validations) or ("invalid_input_rejection",),
                    evidence_locations=tuple(dict.fromkeys((ep.location, *test_locs))),
                    summary=(
                        f"Tests referencing '{ep.name}' do not appear to exercise invalid or "
                        f"non-normalized input rejection."
                    ),
                )
            )

    return refs_by_ep, tuple(gaps)


# ---------------------------------------------------------------------------
# Public Builder, Formatter, and CLI Registration Helpers
# ---------------------------------------------------------------------------


def build_boundary_diff_map(
    feature: str,
    source_dir: str | Path,
    *,
    test_dir: str | Path | None = None,
    baseline_kind: str | None = None,
    baseline_entrypoint: str | None = None,
    feature_aliases: Sequence[str] = (),
    include_unmatched_entrypoints: bool = False,
    max_call_depth: int = 3,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
) -> BoundaryDiffMap:
    """Build a static Auth Boundary Diff Map for ``feature`` under ``source_dir``.

    Args:
        feature: Target feature identifier or keyword (e.g. ``"catalog_sync"``).
        source_dir: Root directory containing Python application source code.
        test_dir: Optional directory containing pytest test files to inspect.
        baseline_kind: Optional entrypoint kind (``ui``, ``api``, ``webhook``, ``async``)
            to use as the comparison baseline.
        baseline_entrypoint: Optional entrypoint ID/name to force as baseline.
        feature_aliases: Optional extra alias strings for matching the feature.
        include_unmatched_entrypoints: When True, include all detected entrypoints even
            if they do not match ``feature``.
        max_call_depth: Maximum depth for following internal helper calls.
        max_file_bytes: Maximum Python file size in bytes to parse.

    Returns:
        A validated ``BoundaryDiffMap`` containing per-entrypoint boundary records,
        cross-path diffs, and test-coverage gaps, all marked ``investigation_candidate``.
    """
    cleaned_feature = feature.strip()
    if not cleaned_feature:
        raise ContractViolationError("feature must be a non-empty string.")
    if max_call_depth < 0 or max_call_depth > 10:
        raise ContractViolationError("max_call_depth must be between 0 and 10.")

    src_root = _validate_root_dir(source_dir, label="source_dir")
    tst_root = (
        _validate_root_dir(test_dir, label="test_dir") if test_dir is not None else None
    )

    analyzed_files, skipped_files, functions, by_qname, route_table = _index_source_tree(
        src_root,
        exclude_tests=True,
        max_file_bytes=max_file_bytes,
    )
    by_short_name: dict[str, list[_IndexedFunction]] = {}
    for fn in functions:
        by_short_name.setdefault(fn.name, []).append(fn)

    slugs, token_groups = _collect_feature_terms(cleaned_feature, feature_aliases)

    records: list[EntrypointBoundaryRecord] = []
    for fn in functions:
        route = _lookup_route_for_function(fn, route_table)
        kind = _classify_entrypoint(fn, route)
        if kind is None:
            continue

        direct_calls = [
            _format_expr(node.func)
            for node in ast.walk(fn.node)
            if isinstance(node, ast.Call)
        ]
        reasons = _match_feature_reasons(fn, route, direct_calls, slugs, token_groups)
        if not reasons:
            if include_unmatched_entrypoints:
                reasons = ("unmatched_included",)
            else:
                continue

        perms, vals, scopes, sinks, callees = _collect_entrypoint_boundaries(
            fn,
            by_qname=by_qname,
            by_short_name=by_short_name,
            max_call_depth=max_call_depth,
        )
        ep_id = f"{kind.value}:{fn.qualified_name}"
        params = tuple(
            a.arg
            for a in (list(fn.node.args.posonlyargs) + list(fn.node.args.args) + list(fn.node.args.kwonlyargs))
            if a.arg not in {"self", "cls"}
        )
        records.append(
            EntrypointBoundaryRecord(
                entrypoint_id=ep_id,
                kind=kind,
                name=fn.name,
                qualified_name=fn.qualified_name,
                route=route,
                file=fn.file_rel,
                line=fn.line,
                location=f"{fn.file_rel}:{fn.line}",
                matched_feature_reasons=reasons,
                parameters=params,
                permission_checks=perms,
                input_validations=vals,
                target_scopings=scopes,
                update_sinks=sinks,
                callees_followed=callees,
            )
        )

    records.sort(key=lambda r: (VALID_ENTRYPOINT_KINDS.index(r.kind.value), r.file, r.line, r.name))

    analyzed_test_files: list[str] = []
    coverage_gaps: tuple[TestCoverageGap, ...] = ()
    if tst_root is not None:
        analyzed_test_files, test_skipped, cases = _scan_test_cases(
            tst_root, max_file_bytes=max_file_bytes
        )
        skipped_files.extend(f"test:{item}" for item in test_skipped)
        refs_by_ep, coverage_gaps = _compute_test_coverage_gaps(records, cases)
        records = [
            ep.model_copy(update={"test_references": refs_by_ep.get(ep.entrypoint_id, ())})
            for ep in records
        ]

    baseline = _select_baseline(
        records,
        baseline_kind=baseline_kind,
        baseline_entrypoint=baseline_entrypoint,
    )
    cross_diffs = _compute_cross_path_diffs(records, baseline)

    counts: dict[str, int] = {k: 0 for k in VALID_ENTRYPOINT_KINDS}
    for ep in records:
        counts[ep.kind.value] = counts.get(ep.kind.value, 0) + 1

    return BoundaryDiffMap(
        feature=cleaned_feature,
        source_root=str(src_root),
        test_root=str(tst_root) if tst_root is not None else None,
        baseline_entrypoint_id=baseline.entrypoint_id if baseline is not None else None,
        analyzed_files=tuple(analyzed_files),
        analyzed_test_files=tuple(analyzed_test_files),
        skipped_files=tuple(skipped_files),
        entrypoints=tuple(records),
        entrypoints_by_kind=counts,
        cross_path_diffs=cross_diffs,
        test_coverage_gaps=coverage_gaps,
        total_investigation_candidates=len(cross_diffs) + len(coverage_gaps),
    )


def format_boundary_diff_map(
    diff_map: BoundaryDiffMap,
    *,
    output_format: Literal["markdown", "text", "json"] = "markdown",
) -> str:
    """Render a ``BoundaryDiffMap`` as JSON, Markdown, or plain text."""
    if output_format == "json":
        return json.dumps(
            diff_map.model_dump(mode="json"),
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )

    if output_format not in {"markdown", "text"}:
        raise ContractViolationError(
            f"Unsupported output_format {output_format!r}; expected 'json', 'markdown', or 'text'."
        )

    lines: list[str] = []
    if output_format == "markdown":
        lines.append(f"# Auth Boundary Diff Map: `{diff_map.feature}`")
        lines.append("")
        lines.append(
            f"- **Policy**: `{diff_map.status_policy}` ({diff_map.total_investigation_candidates} investigation candidate(s))"
        )
        lines.append(f"- **Baseline**: `{diff_map.baseline_entrypoint_id or 'none'}`")
        lines.append(
            "- **Entrypoints by kind**: "
            + ", ".join(f"`{k}={v}`" for k, v in diff_map.entrypoints_by_kind.items())
        )
        lines.append("")
        lines.append("## Entrypoints")
        if not diff_map.entrypoints:
            lines.append("_No matching entrypoints found._")
        else:
            lines.append(
                "| Kind | Entrypoint | Route | Location | Perm | Validation | Scoping | Sinks | Tests |"
            )
            lines.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
            for ep in diff_map.entrypoints:
                lines.append(
                    f"| `{ep.kind.value}` | `{ep.name}` | `{ep.route or '-'}` | "
                    f"`{ep.location}` | {len(ep.permission_checks)} | "
                    f"{len(ep.input_validations)} | {len(ep.target_scopings)} | "
                    f"{len(ep.update_sinks)} | {len(ep.test_references)} |"
                )
        lines.append("")
        lines.append("## Cross-Path Differences (Investigation Candidates)")
        if not diff_map.cross_path_diffs:
            lines.append("_No cross-path boundary differences detected._")
        else:
            for item in diff_map.cross_path_diffs:
                locs = ", ".join(f"`{loc}`" for loc in item.evidence_locations)
                lines.append(
                    f"- **[{item.status}] {item.finding_id} ({item.category.value})**: "
                    f"{item.summary} Locations: {locs}"
                )
        lines.append("")
        lines.append("## Test Coverage Gaps (Investigation Candidates)")
        if not diff_map.test_coverage_gaps:
            lines.append("_No test coverage gaps detected._")
        else:
            for gap in diff_map.test_coverage_gaps:
                locs = ", ".join(f"`{loc}`" for loc in gap.evidence_locations)
                lines.append(
                    f"- **[{gap.status}] {gap.gap_id} ({gap.gap_type.value})**: "
                    f"{gap.summary} Locations: {locs}"
                )
        lines.append("")
        lines.append(f"> {diff_map.disclaimer}")
        return "\n".join(lines)

    # Plain text format
    lines.append(f"Auth Boundary Diff Map: {diff_map.feature}")
    lines.append(f"Baseline: {diff_map.baseline_entrypoint_id or 'none'}")
    lines.append(
        "Entrypoints: "
        + ", ".join(f"{k}={v}" for k, v in diff_map.entrypoints_by_kind.items())
    )
    for ep in diff_map.entrypoints:
        lines.append(
            f"  [{ep.kind.value}] {ep.name} ({ep.location}) route={ep.route or '-'} "
            f"perm={len(ep.permission_checks)} val={len(ep.input_validations)} "
            f"scope={len(ep.target_scopings)} sink={len(ep.update_sinks)} tests={len(ep.test_references)}"
        )
    lines.append("Cross-Path Differences (investigation_candidate):")
    for item in diff_map.cross_path_diffs:
        lines.append(
            f"  - [{item.status}] {item.finding_id} {item.category.value}: {item.summary} "
            f"@ {', '.join(item.evidence_locations)}"
        )
    lines.append("Test Coverage Gaps (investigation_candidate):")
    for gap in diff_map.test_coverage_gaps:
        lines.append(
            f"  - [{gap.status}] {gap.gap_id} {gap.gap_type.value}: {gap.summary} "
            f"@ {', '.join(gap.evidence_locations)}"
        )
    return "\n".join(lines)


def handle_boundary_map_cli(
    args: argparse.Namespace,
    env: Mapping[str, str] | None = None,
) -> int:
    """CLI handler for ``vdp-boundary-map`` subcommand."""
    _ = env  # Unused; kept for uniform cli.py handler signature (args, env) -> int.
    diff_map = build_boundary_diff_map(
        feature=args.feature,
        source_dir=args.source_dir,
        test_dir=getattr(args, "test_dir", None),
        baseline_kind=getattr(args, "baseline_kind", None),
        baseline_entrypoint=getattr(args, "baseline_entrypoint", None),
        feature_aliases=getattr(args, "feature_aliases", None) or (),
        include_unmatched_entrypoints=bool(getattr(args, "include_unmatched", False)),
        max_call_depth=getattr(args, "max_call_depth", 3),
    )
    output_format = getattr(args, "output_format", "json")
    rendered = format_boundary_diff_map(diff_map, output_format=output_format)
    sys.stdout.write(rendered + "\n")
    return 0


def register_boundary_map_subparser(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
    *,
    command_name: str = BOUNDARY_MAP_SUBCOMMAND,
    parents: Sequence[argparse.ArgumentParser] = (),
) -> argparse.ArgumentParser:
    """Register the ``vdp-boundary-map`` subcommand on an argparse subparsers action."""
    parser = subparsers.add_parser(
        command_name,
        parents=list(parents),
        help=(
            "Analyze UI/API/Webhook/Async entrypoints for one feature and emit a static "
            "Auth Boundary Diff Map (investigation_candidate items only)."
        ),
    )
    parser.add_argument(
        "--feature",
        required=True,
        help="Feature name or keyword to trace across entrypoints.",
    )
    parser.add_argument(
        "--source-dir",
        type=Path,
        required=True,
        help="Root Python source directory to inspect.",
    )
    parser.add_argument(
        "--test-dir",
        type=Path,
        default=None,
        help="Optional test directory to scan for boundary coverage gaps.",
    )
    parser.add_argument(
        "--baseline-kind",
        choices=list(VALID_ENTRYPOINT_KINDS),
        default=None,
        help="Optional baseline entrypoint kind (ui, api, webhook, async).",
    )
    parser.add_argument(
        "--baseline-entrypoint",
        default=None,
        help="Optional explicit baseline entrypoint ID or function name.",
    )
    parser.add_argument(
        "--alias",
        action="append",
        default=None,
        dest="feature_aliases",
        help="Optional additional alias string for matching the feature.",
    )
    parser.add_argument(
        "--include-unmatched",
        action="store_true",
        default=False,
        help="Include detected entrypoints even if they do not match --feature.",
    )
    parser.add_argument(
        "--max-call-depth",
        type=int,
        default=3,
        help="Maximum helper call depth to follow during AST extraction (default: 3).",
    )
    parser.add_argument(
        "--format",
        choices=["json", "markdown", "text"],
        default="json",
        dest="output_format",
        help="Output format (default: json).",
    )
    parser.set_defaults(handler=handle_boundary_map_cli)
    return parser


__all__ = [
    "BOUNDARY_MAP_SUBCOMMAND",
    "BoundaryDiffFinding",
    "BoundaryDiffMap",
    "BoundaryItemCategory",
    "CoverageGapType",
    "DEFAULT_MAX_FILE_BYTES",
    "DiffCategory",
    "EntrypointBoundaryRecord",
    "EntrypointKind",
    "INVESTIGATION_CANDIDATE_STATUS",
    "SourceEvidenceItem",
    "TestCoverageGap",
    "VALID_ENTRYPOINT_KINDS",
    "build_boundary_diff_map",
    "format_boundary_diff_map",
    "handle_boundary_map_cli",
    "register_boundary_map_subparser",
]
