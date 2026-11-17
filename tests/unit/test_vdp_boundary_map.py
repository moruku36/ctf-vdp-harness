"""Unit and acceptance tests for the Auth Boundary Diff Map (Feature 1)."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

import pytest

from ctf_mcp.contracts import ContractViolationError, PathSecurityError
from ctf_mcp.vdp_boundary_map import (
    BOUNDARY_MAP_SUBCOMMAND,
    BoundaryDiffMap,
    BoundaryItemCategory,
    CoverageGapType,
    DiffCategory,
    EntrypointKind,
    INVESTIGATION_CANDIDATE_STATUS,
    PermissionStatus,
    ScopingStatus,
    UpdateSinkStatus,
    ValidationStatus,
    build_boundary_diff_map,
    format_boundary_diff_map,
    handle_boundary_map_cli,
    register_boundary_map_subparser,
)


def _write_synthetic_app(root: Path) -> tuple[Path, Path]:
    """Create an ephemeral synthetic multi-entrypoint app (UI+API+Webhook+Async) and partial tests."""
    src_dir = root / "app"
    test_dir = root / "tests"
    src_dir.mkdir(parents=True)
    test_dir.mkdir(parents=True)

    (src_dir / "__init__.py").write_text("", encoding="utf-8")

    (src_dir / "services.py").write_text(
        "\n".join(
            [
                "from urllib.parse import urlparse",
                "",
                "def normalize_feed_url(raw_url: str) -> str:",
                "    cleaned = raw_url.strip().lower()",
                "    parsed = urlparse(cleaned)",
                "    if parsed.scheme not in ('https', 'http'):",
                "        raise ValueError('Invalid feed URL scheme')",
                "    return cleaned.rstrip('/')",
                "",
                "def apply_catalog_sync_config(source, normalized_url: str) -> None:",
                "    source.feed_url = normalized_url",
                "    source.save()",
                "",
                "def trigger_catalog_sync(source) -> None:",
                "    source.save()",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    (src_dir / "views.py").write_text(
        "\n".join(
            [
                "from app.services import apply_catalog_sync_config, normalize_feed_url",
                "",
                "@login_required",
                "@permission_required('catalog.manage')",
                "def ui_catalog_sync_settings(request, source_id: int):",
                "    form = CatalogSyncForm(request.POST)",
                "    if not form.is_valid():",
                "        raise ValueError('Invalid form payload')",
                "    normalized = normalize_feed_url(form.cleaned_data['feed_url'])",
                "    source = CatalogSource.objects.get(pk=source_id, tenant=request.user.tenant)",
                "    apply_catalog_sync_config(source, normalized)",
                "    return {'status': 'ok'}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    (src_dir / "api.py").write_text(
        "\n".join(
            [
                "from app.services import apply_catalog_sync_config, normalize_feed_url",
                "",
                "class CatalogSyncApiView(APIView):",
                "    permission_classes = [IsAuthenticated, CanManageCatalog]",
                "    serializer_class = CatalogSyncSerializer",
                "",
                "    def post(self, request, source_id: int):",
                "        serializer = self.serializer_class(data=request.data)",
                "        serializer.is_valid(raise_exception=True)",
                "        normalized = normalize_feed_url(serializer.validated_data['feed_url'])",
                "        source = CatalogSource.objects.filter(id=source_id, tenant_id=request.user.tenant_id).first()",
                "        apply_catalog_sync_config(source, normalized)",
                "        return {'updated': True}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    (src_dir / "webhooks.py").write_text(
        "\n".join(
            [
                "from app.services import trigger_catalog_sync",
                "",
                "@app.post('/webhooks/catalog-sync')",
                "def catalog_sync_webhook(payload: dict):",
                "    raw_url = payload.get('feed_url', '').rstrip('/')",
                "    source = CatalogSource.objects.filter(feed_url__endswith=raw_url).first()",
                "    if source is not None:",
                "        trigger_catalog_sync(source)",
                "    return {'accepted': True}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    (src_dir / "tasks.py").write_text(
        "\n".join(
            [
                "from app.services import trigger_catalog_sync",
                "",
                "@shared_task",
                "def run_catalog_sync_task(source_id: int, feed_url: str):",
                "    source = CatalogSource.objects.get(pk=source_id)",
                "    source.feed_url = feed_url",
                "    trigger_catalog_sync(source)",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    (src_dir / "urls.py").write_text(
        "\n".join(
            [
                "from app.api import CatalogSyncApiView",
                "from app.views import ui_catalog_sync_settings",
                "",
                "urlpatterns = [",
                "    path('ui/catalog-sync/<int:source_id>/', ui_catalog_sync_settings),",
                "    path('api/v1/catalog-sync/<int:source_id>/', CatalogSyncApiView.as_view()),",
                "]",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    # Partial test suite:
    # - UI and API tests include auth (403), cross-tenant scope (other_tenant), and invalid input (400)
    # - Webhook test only exercises happy path (missing auth/scope/validation assertions)
    # - Async task has no test at all
    (test_dir / "test_catalog_sync_paths.py").write_text(
        "\n".join(
            [
                "def test_ui_catalog_sync_settings_enforces_auth_and_tenant():",
                "    # Exercises ui_catalog_sync_settings across 403 unauthorized, other_tenant 404, and invalid 400",
                "    path = '/ui/catalog-sync/1/'",
                "    expected = (403, 404, 400, 'other_tenant', 'invalid')",
                "    assert path and expected",
                "",
                "def test_api_catalog_sync_enforces_permission_and_validation():",
                "    endpoint = '/api/v1/catalog-sync/1/'",
                "    checks = ('CatalogSyncApiView', 'unauthorized', 403, 'other_tenant', 400, 'invalid')",
                "    assert endpoint and checks",
                "",
                "def test_catalog_sync_webhook_happy_path():",
                "    url = '/webhooks/catalog-sync'",
                "    assert url.endswith('catalog-sync')",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    return src_dir, test_dir


def test_boundary_diff_map_synthetic_multi_entrypoint_app(tmp_path: Path) -> None:
    src_dir, test_dir = _write_synthetic_app(tmp_path)

    diff_map = build_boundary_diff_map(
        "catalog_sync",
        src_dir,
        test_dir=test_dir,
    )

    assert isinstance(diff_map, BoundaryDiffMap)
    assert diff_map.status_policy == "investigation_candidate_only"
    assert diff_map.entrypoints_by_kind == {
        "ui": 1,
        "api": 1,
        "webhook": 1,
        "async": 1,
    }

    by_kind = {ep.kind: ep for ep in diff_map.entrypoints}
    assert set(by_kind) == {
        EntrypointKind.UI,
        EntrypointKind.API,
        EntrypointKind.WEBHOOK,
        EntrypointKind.ASYNC,
    }

    # Verify extracted routes and exact file:line locations
    ui_ep = by_kind[EntrypointKind.UI]
    assert ui_ep.name == "ui_catalog_sync_settings"
    assert ui_ep.route == "/ui/catalog-sync/<int:source_id>/"
    assert ui_ep.location == "views.py:5"
    assert [p.location for p in ui_ep.permission_checks] == ["views.py:3", "views.py:4"]
    assert any("tenant_or_owner_scoped" in s.tags and s.location == "views.py:10" for s in ui_ep.target_scopings)
    assert any(s.location == "services.py:12" for s in ui_ep.update_sinks)

    api_ep = by_kind[EntrypointKind.API]
    assert api_ep.name == "post"
    assert api_ep.route == "/api/v1/catalog-sync/<int:source_id>/"
    assert api_ep.location == "api.py:7"
    assert any(p.location == "api.py:4" for p in api_ep.permission_checks)
    assert any("tenant_or_owner_scoped" in s.tags and s.location == "api.py:11" for s in api_ep.target_scopings)
    assert any("url_parse" in v.tags and v.location == "services.py:5" for v in api_ep.input_validations)

    webhook_ep = by_kind[EntrypointKind.WEBHOOK]
    assert webhook_ep.name == "catalog_sync_webhook"
    assert webhook_ep.route == "/webhooks/catalog-sync"
    assert webhook_ep.location == "webhooks.py:4"
    assert webhook_ep.permission_checks == ()
    assert any("unscoped_lookup" in s.tags and "fuzzy_or_suffix_lookup" in s.tags and s.location == "webhooks.py:6" for s in webhook_ep.target_scopings)
    assert any(s.location == "services.py:15" for s in webhook_ep.update_sinks)

    async_ep = by_kind[EntrypointKind.ASYNC]
    assert async_ep.name == "run_catalog_sync_task"
    assert async_ep.location == "tasks.py:4"
    assert async_ep.permission_checks == ()
    assert async_ep.input_validations == ()
    assert any("unscoped_lookup" in s.tags and s.location == "tasks.py:5" for s in async_ep.target_scopings)

    # Verify cross-path diffs
    diff_pairs = {(d.compared_kind, d.category) for d in diff_map.cross_path_diffs}
    assert (EntrypointKind.WEBHOOK, DiffCategory.MISSING_PERMISSION_CHECK) in diff_pairs
    assert (EntrypointKind.WEBHOOK, DiffCategory.MISSING_TARGET_SCOPING) in diff_pairs
    assert (EntrypointKind.WEBHOOK, DiffCategory.INPUT_NORMALIZATION_MISMATCH) in diff_pairs
    assert (EntrypointKind.ASYNC, DiffCategory.MISSING_PERMISSION_CHECK) in diff_pairs
    assert (EntrypointKind.ASYNC, DiffCategory.MISSING_TARGET_SCOPING) in diff_pairs
    assert (EntrypointKind.ASYNC, DiffCategory.MISSING_INPUT_VALIDATION) in diff_pairs

    # Every finding MUST carry investigation_candidate status and exact file:line locations
    assert diff_map.cross_path_diffs
    for finding in diff_map.cross_path_diffs:
        assert finding.status == INVESTIGATION_CANDIDATE_STATUS
        assert finding.evidence_locations
        assert all(":" in loc for loc in finding.evidence_locations)

    # Verify test coverage gaps
    gaps_by_ep = {(g.kind, g.gap_type) for g in diff_map.test_coverage_gaps}
    assert (EntrypointKind.ASYNC, CoverageGapType.NO_TEST_REFERENCE) in gaps_by_ep
    assert (EntrypointKind.WEBHOOK, CoverageGapType.MISSING_PERMISSION_TEST_ASSERTION) in gaps_by_ep
    assert (EntrypointKind.WEBHOOK, CoverageGapType.MISSING_SCOPING_TEST_ASSERTION) in gaps_by_ep
    assert (EntrypointKind.WEBHOOK, CoverageGapType.MISSING_VALIDATION_TEST_ASSERTION) in gaps_by_ep
    # UI and API should not appear in test coverage gaps because tests cover auth, tenant scope, and validation
    assert not any(g.kind in {EntrypointKind.UI, EntrypointKind.API} for g in diff_map.test_coverage_gaps)

    for gap in diff_map.test_coverage_gaps:
        assert gap.status == INVESTIGATION_CANDIDATE_STATUS
        assert ":" in gap.entrypoint_location
        assert gap.evidence_locations

    assert diff_map.total_investigation_candidates == (
        len(diff_map.cross_path_diffs) + len(diff_map.test_coverage_gaps)
    )


def test_format_boundary_diff_map_outputs(tmp_path: Path) -> None:
    src_dir, test_dir = _write_synthetic_app(tmp_path)
    diff_map = build_boundary_diff_map("catalog_sync", src_dir, test_dir=test_dir)

    md = format_boundary_diff_map(diff_map, output_format="markdown")
    assert "# Auth Boundary Diff Map: `catalog_sync`" in md
    assert "[investigation_candidate]" in md
    assert "confirmed_vulnerability" not in md
    assert "webhooks.py:4" in md

    txt = format_boundary_diff_map(diff_map, output_format="text")
    assert "Auth Boundary Diff Map: catalog_sync" in txt
    assert "[investigation_candidate]" in txt

    raw_json = format_boundary_diff_map(diff_map, output_format="json")
    parsed = json.loads(raw_json)
    assert parsed["feature"] == "catalog_sync"
    assert parsed["status_policy"] == "investigation_candidate_only"
    assert all(
        item["status"] == "investigation_candidate"
        for item in parsed["cross_path_diffs"] + parsed["test_coverage_gaps"]
    )


def test_cli_subparser_and_handler(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    src_dir, test_dir = _write_synthetic_app(tmp_path)

    parser = argparse.ArgumentParser(prog="ctf-mcp-admin")
    subparsers = parser.add_subparsers(dest="command", required=True)
    sub = register_boundary_map_subparser(subparsers)
    assert sub is not None

    args = parser.parse_args(
        [
            BOUNDARY_MAP_SUBCOMMAND,
            "--feature",
            "catalog_sync",
            "--source-dir",
            str(src_dir),
            "--test-dir",
            str(test_dir),
            "--baseline-kind",
            "api",
            "--format",
            "json",
        ]
    )
    assert args.handler is handle_boundary_map_cli
    rc = args.handler(args, None)
    assert rc == 0

    stdout = capsys.readouterr().out
    payload = json.loads(stdout)
    assert payload["baseline_entrypoint_id"].startswith("api:")
    assert payload["entrypoints_by_kind"]["webhook"] == 1
    assert payload["total_investigation_candidates"] >= 1


def test_boundary_diff_map_rejects_invalid_inputs_and_skips_symlinks(tmp_path: Path) -> None:
    src_dir, _ = _write_synthetic_app(tmp_path)

    with pytest.raises(ContractViolationError):
        build_boundary_diff_map("   ", src_dir)

    with pytest.raises(ContractViolationError):
        build_boundary_diff_map("catalog_sync", tmp_path / "does-not-exist")

    with pytest.raises(ContractViolationError):
        build_boundary_diff_map("catalog_sync", src_dir, baseline_kind="unknown_kind")

    # Symlinked source file inside source_dir must be skipped cleanly
    outside = tmp_path / "outside.py"
    outside.write_text("def secret_webhook(request): pass\n", encoding="utf-8")
    link_path = src_dir / "linked_webhook.py"
    try:
        os.symlink(outside, link_path)
    except OSError:
        pytest.skip("Symlinks are not permitted in this environment.")

    diff_map = build_boundary_diff_map("catalog_sync", src_dir)
    assert "linked_webhook.py" not in diff_map.analyzed_files

    root_link = tmp_path / "src_link"
    os.symlink(src_dir, root_link)
    with pytest.raises(PathSecurityError):
        build_boundary_diff_map("catalog_sync", root_link)


def test_boundary_diff_map_permission_model_mismatch_aliases_and_syntax_skip(tmp_path: Path) -> None:
    src_dir = tmp_path / "svc"
    src_dir.mkdir()
    (src_dir / "broken.py").write_text("def broken(:\n    pass\n", encoding="utf-8")

    (src_dir / "api.py").write_text(
        "\n".join(
            [
                "@require_permission('billing.edit')",
                "def api_billing_profile(request, profile_id: int):",
                "    row = BillingProfile.objects.get(pk=profile_id, owner=request.user)",
                "    sync_billing_task.delay(row.id)",
                "    return {'ok': True}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    (src_dir / "webhooks.py").write_text(
        "\n".join(
            [
                "@verify_webhook_signature",
                "@app.post('/webhooks/invoice-hook')",
                "def invoice_hook_callback(payload: dict):",
                "    row = BillingProfile.objects.filter(endpoint__endswith=payload['endpoint'], owner=payload['owner']).first()",
                "    row.save()",
                "    return {'ok': True}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    diff_map = build_boundary_diff_map(
        "billing_profile",
        src_dir,
        feature_aliases=["invoice_hook"],
        baseline_entrypoint="webhook:webhooks.invoice_hook_callback",
    )
    assert "broken.py" in diff_map.skipped_files
    assert diff_map.entrypoints_by_kind["api"] == 1
    assert diff_map.entrypoints_by_kind["webhook"] == 1
    cats = {d.category for d in diff_map.cross_path_diffs}
    assert DiffCategory.PERMISSION_MODEL_MISMATCH in cats
    assert DiffCategory.SCOPING_MISMATCH in cats
    assert DiffCategory.UPDATE_SINK_ASYMMETRY in cats
    assert all(d.status == INVESTIGATION_CANDIDATE_STATUS for d in diff_map.cross_path_diffs)


def test_open_access_allow_any_and_empty_permission_classes_not_treated_as_checked(
    tmp_path: Path,
) -> None:
    """Case 1: AllowAny / [] / open decorators must classify as open_access and diff against protected paths."""
    src_dir = tmp_path / "open_app"
    src_dir.mkdir()

    (src_dir / "api.py").write_text(
        "\n".join(
            [
                "class ProtectedReportApiView(APIView):",
                "    permission_classes = [IsAuthenticated, CanExportReports]",
                "    def post(self, request, report_id: int):",
                "        row = ReportJob.objects.get(pk=report_id, tenant_id=request.user.tenant_id)",
                "        row.save()",
                "        return {'ok': True}",
                "",
                "class OpenAllowAnyReportApiView(APIView):",
                "    authentication_classes = [SessionAuthentication]",
                "    permission_classes = [AllowAny]",
                "    def post(self, request, report_id: int):",
                "        row = ReportJob.objects.get(pk=report_id, tenant_id=request.user.tenant_id)",
                "        row.save()",
                "        return {'ok': True}",
                "",
                "class OpenEmptyPermsReportApiView(APIView):",
                "    permission_classes = []",
                "    def post(self, request, report_id: int):",
                "        row = ReportJob.objects.get(pk=report_id, tenant_id=request.user.tenant_id)",
                "        row.save()",
                "        return {'ok': True}",
                "",
                "@api_view(['POST'])",
                "@permission_classes([AllowAny])",
                "def api_report_open_decorator(request, report_id: int):",
                "    row = ReportJob.objects.get(pk=report_id, tenant_id=request.user.tenant_id)",
                "    row.save()",
                "    return {'ok': True}",
                "",
                "@allow_any",
                "def api_report_allow_any_marker(request, report_id: int):",
                "    row = ReportJob.objects.get(pk=report_id, tenant_id=request.user.tenant_id)",
                "    row.save()",
                "    return {'ok': True}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    diff_map = build_boundary_diff_map(
        "report",
        src_dir,
        baseline_entrypoint="api:api.ProtectedReportApiView.post",
    )
    by_qname = {ep.qualified_name: ep for ep in diff_map.entrypoints}

    protected = by_qname["api.ProtectedReportApiView.post"]
    assert protected.permission_status == PermissionStatus.CHECKED
    assert protected.permission_checks
    assert protected.open_access_controls == ()

    open_names = [
        "api.OpenAllowAnyReportApiView.post",
        "api.OpenEmptyPermsReportApiView.post",
        "api.api_report_open_decorator",
        "api.api_report_allow_any_marker",
    ]
    for qname in open_names:
        ep = by_qname[qname]
        assert ep.permission_status == PermissionStatus.OPEN_ACCESS, qname
        assert ep.permission_checks == (), qname
        assert ep.open_access_controls, qname
        assert any("open_access" in item.tags for item in ep.open_access_controls), qname

    perm_diffs = [
        d
        for d in diff_map.cross_path_diffs
        if d.category == DiffCategory.MISSING_PERMISSION_CHECK
    ]
    diff_targets = {d.compared_entrypoint_id for d in perm_diffs}
    assert diff_targets == {f"api:{name}" for name in open_names}
    for d in perm_diffs:
        assert d.status == INVESTIGATION_CANDIDATE_STATUS
        assert d.details["compared_permission_status"] == "open_access"

    # Positive-control parity: two identically protected views produce zero diffs
    parity_dir = tmp_path / "parity_app"
    parity_dir.mkdir()
    (parity_dir / "api.py").write_text(
        "\n".join(
            [
                "class FirstReportApiView(APIView):",
                "    permission_classes = [IsAuthenticated, CanExportReports]",
                "    def post(self, request, report_id: int):",
                "        row = ReportJob.objects.get(pk=report_id, tenant_id=request.user.tenant_id)",
                "        row.save()",
                "        return {'ok': True}",
                "",
                "class SecondReportApiView(APIView):",
                "    permission_classes = [IsAuthenticated, CanExportReports]",
                "    def post(self, request, report_id: int):",
                "        row = ReportJob.objects.get(pk=report_id, tenant_id=request.user.tenant_id)",
                "        row.save()",
                "        return {'ok': True}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    parity_map = build_boundary_diff_map("report", parity_dir)
    assert parity_map.cross_path_diffs == ()


def test_untrusted_user_supplied_scoping_distinguished_from_trusted_identity_scoping(
    tmp_path: Path,
) -> None:
    """Case 2: User-supplied tenant_id inputs must not match request.user.tenant_id scoping."""
    src_dir = tmp_path / "scoping_app"
    src_dir.mkdir()

    (src_dir / "services.py").write_text(
        "\n".join(
            [
                "def save_scoped_ledger(tenant_id: int, ledger_id: int) -> None:",
                "    row = LedgerEntry.objects.filter(id=ledger_id, tenant_id=tenant_id).first()",
                "    row.save()",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    (src_dir / "api.py").write_text(
        "\n".join(
            [
                "from services import save_scoped_ledger",
                "",
                "@require_permission('ledger.write')",
                "def api_ledger_trusted_direct(request, ledger_id: int):",
                "    row = LedgerEntry.objects.get(pk=ledger_id, tenant_id=request.user.tenant_id)",
                "    row.save()",
                "    return {'ok': True}",
                "",
                "@require_permission('ledger.write')",
                "def api_ledger_trusted_helper(request, ledger_id: int):",
                "    tid = request.user.tenant_id",
                "    save_scoped_ledger(tid, ledger_id)",
                "    return {'ok': True}",
                "",
                "@require_permission('ledger.write')",
                "def api_ledger_untrusted_data(request, ledger_id: int):",
                "    row = LedgerEntry.objects.get(pk=ledger_id, tenant_id=request.data['tenant_id'])",
                "    row.save()",
                "    return {'ok': True}",
                "",
                "@require_permission('ledger.write')",
                "def api_ledger_untrusted_query_params(request, ledger_id: int):",
                "    row = LedgerEntry.objects.get(pk=ledger_id, tenant_id=request.query_params.get('tenant_id'))",
                "    row.save()",
                "    return {'ok': True}",
                "",
                "@require_permission('ledger.write')",
                "def api_ledger_untrusted_get_var(request, ledger_id: int):",
                "    tid = request.GET['tenant_id']",
                "    row = LedgerEntry.objects.get(pk=ledger_id, tenant_id=tid)",
                "    row.save()",
                "    return {'ok': True}",
                "",
                "@require_permission('ledger.write')",
                "def api_ledger_untrusted_post(request, ledger_id: int):",
                "    row = LedgerEntry.objects.get(pk=ledger_id, tenant_id=request.POST['tenant_id'])",
                "    row.save()",
                "    return {'ok': True}",
                "",
                "@require_permission('ledger.write')",
                "def api_ledger_untrusted_helper(request, ledger_id: int):",
                "    save_scoped_ledger(request.data['tenant_id'], ledger_id)",
                "    return {'ok': True}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    diff_map = build_boundary_diff_map(
        "ledger",
        src_dir,
        baseline_entrypoint="api:api.api_ledger_trusted_direct",
    )
    by_name = {ep.name: ep for ep in diff_map.entrypoints}

    # Positive controls
    for trusted_name in ("api_ledger_trusted_direct", "api_ledger_trusted_helper"):
        ep = by_name[trusted_name]
        assert ep.scoping_status == ScopingStatus.TRUSTED_SCOPED, trusted_name
        assert any("tenant_or_owner_scoped" in s.tags for s in ep.target_scopings), trusted_name
        assert not any("untrusted_scope_input" in s.tags for s in ep.target_scopings), trusted_name

    # Untrusted paths must NOT have tenant_or_owner_scoped and MUST diff against baseline
    untrusted_names = [
        "api_ledger_untrusted_data",
        "api_ledger_untrusted_query_params",
        "api_ledger_untrusted_get_var",
        "api_ledger_untrusted_post",
        "api_ledger_untrusted_helper",
    ]
    for uname in untrusted_names:
        ep = by_name[uname]
        assert ep.scoping_status == ScopingStatus.UNTRUSTED_SCOPED, uname
        assert not any("tenant_or_owner_scoped" in s.tags for s in ep.target_scopings), uname
        assert any("untrusted_scope_input" in s.tags for s in ep.target_scopings), uname

    scoping_diffs = [
        d for d in diff_map.cross_path_diffs if d.category == DiffCategory.SCOPING_MISMATCH
    ]
    assert {d.compared_entrypoint_id for d in scoping_diffs} == {
        f"api:api.{uname}" for uname in untrusted_names
    }
    assert not any(
        d.compared_entrypoint_id == "api:api.api_ledger_trusted_helper"
        and d.category in {DiffCategory.SCOPING_MISMATCH, DiffCategory.MISSING_TARGET_SCOPING}
        for d in diff_map.cross_path_diffs
    )


def test_uncalled_inner_helper_permission_check_not_counted(tmp_path: Path) -> None:
    """Case 3: Uncalled nested def/class or unreachable dead code must not count as endpoint permission."""
    src_dir = tmp_path / "inner_app"
    src_dir.mkdir()

    (src_dir / "api.py").write_text(
        "\n".join(
            [
                "def _orphan_module_guard(request):",
                "    require_permission(request, 'token.manage')",
                "",
                "def api_token_called_inner(request, token_id: int):",
                "    def _enforce():",
                "        require_permission(request, 'token.manage')",
                "    _enforce()",
                "    tok = ApiToken.objects.get(pk=token_id, tenant_id=request.user.tenant_id)",
                "    tok.save()",
                "    return {'ok': True}",
                "",
                "def api_token_uncalled_inner_def(request, token_id: int):",
                "    def _unused_guard():",
                "        require_permission(request, 'token.manage')",
                "    tok = ApiToken.objects.get(pk=token_id, tenant_id=request.user.tenant_id)",
                "    tok.save()",
                "    return {'ok': True}",
                "",
                "def api_token_uncalled_inner_async(request, token_id: int):",
                "    async def _unused_async_guard():",
                "        require_permission(request, 'token.manage')",
                "    tok = ApiToken.objects.get(pk=token_id, tenant_id=request.user.tenant_id)",
                "    tok.save()",
                "    return {'ok': True}",
                "",
                "def api_token_uncalled_inner_class(request, token_id: int):",
                "    class _UnusedGuardClass:",
                "        @permission_required('token.manage')",
                "        def check(self):",
                "            require_permission(request, 'token.manage')",
                "    tok = ApiToken.objects.get(pk=token_id, tenant_id=request.user.tenant_id)",
                "    tok.save()",
                "    return {'ok': True}",
                "",
                "def api_token_dead_code_after_return(request, token_id: int):",
                "    tok = ApiToken.objects.get(pk=token_id, tenant_id=request.user.tenant_id)",
                "    tok.save()",
                "    return {'ok': True}",
                "    require_permission(request, 'token.manage')",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    diff_map = build_boundary_diff_map(
        "token",
        src_dir,
        baseline_entrypoint="api:api.api_token_called_inner",
    )
    by_name = {ep.name: ep for ep in diff_map.entrypoints}

    # Positive control: called inner helper IS counted
    called = by_name["api_token_called_inner"]
    assert called.permission_status == PermissionStatus.CHECKED
    assert any(p.name == "require_permission" for p in called.permission_checks)

    uncalled_names = [
        "api_token_uncalled_inner_def",
        "api_token_uncalled_inner_async",
        "api_token_uncalled_inner_class",
        "api_token_dead_code_after_return",
    ]
    for uname in uncalled_names:
        ep = by_name[uname]
        assert ep.permission_status == PermissionStatus.MISSING, uname
        assert ep.permission_checks == (), uname

    missing_perm_diffs = [
        d
        for d in diff_map.cross_path_diffs
        if d.category == DiffCategory.MISSING_PERMISSION_CHECK
    ]
    assert {d.compared_entrypoint_id for d in missing_perm_diffs} == {
        f"api:api.{uname}" for uname in uncalled_names
    }


def test_indeterminable_unknown_controls_never_claim_parity_or_safe_tags(
    tmp_path: Path,
) -> None:
    """Case 4: Dynamic/conditional/unresolved controls must be marked unknown and never claim parity."""
    src_dir = tmp_path / "unknown_app"
    src_dir.mkdir()

    (src_dir / "api.py").write_text(
        "\n".join(
            [
                "@permission_required('quota.manage')",
                "def api_quota_static_baseline(request, quota_id: int):",
                "    cleaned = normalize_quota_name(request.data['name'])",
                "    row = QuotaRule.objects.get(pk=quota_id, tenant_id=request.user.tenant_id)",
                "    row.name = cleaned",
                "    row.save()",
                "    return {'ok': True}",
                "",
                "class DynamicPermQuotaApiView(APIView):",
                "    permission_classes = get_configured_permissions()",
                "    def post(self, request, quota_id: int):",
                "        cleaned = normalize_quota_name(request.data['name'])",
                "        row = QuotaRule.objects.get(pk=quota_id, tenant_id=request.user.tenant_id)",
                "        row.name = cleaned",
                "        row.save()",
                "        return {'ok': True}",
                "",
                "def api_quota_getattr_perm(request, quota_id: int):",
                "    checker = getattr(policy_registry, request.GET.get('mode', 'default'))",
                "    checker(request)",
                "    cleaned = normalize_quota_name(request.data['name'])",
                "    row = QuotaRule.objects.get(pk=quota_id, tenant_id=request.user.tenant_id)",
                "    row.save()",
                "    return {'ok': True}",
                "",
                "@DECORATORS[CURRENT_TIER]",
                "def api_quota_unresolved_decorator(request, quota_id: int):",
                "    cleaned = normalize_quota_name(request.data['name'])",
                "    row = QuotaRule.objects.get(pk=quota_id, tenant_id=request.user.tenant_id)",
                "    row.save()",
                "    return {'ok': True}",
                "",
                "def api_quota_conditional_perm(request, quota_id: int):",
                "    if feature_flags.enforce_quota_acl:",
                "        require_permission(request, 'quota.manage')",
                "    cleaned = normalize_quota_name(request.data['name'])",
                "    row = QuotaRule.objects.get(pk=quota_id, tenant_id=request.user.tenant_id)",
                "    row.save()",
                "    return {'ok': True}",
                "",
                "@permission_required('quota.manage')",
                "def api_quota_dynamic_kwargs_scope(request, quota_id: int):",
                "    cleaned = normalize_quota_name(request.data['name'])",
                "    filters = build_dynamic_scope(request)",
                "    row = QuotaRule.objects.filter(id=quota_id, **filters).first()",
                "    row.save()",
                "    return {'ok': True}",
                "",
                "@permission_required('quota.manage')",
                "def api_quota_dynamic_validator(request, quota_id: int):",
                "    cleaned = getattr(validators, 'quota_norm')(request.data['name'])",
                "    row = QuotaRule.objects.get(pk=quota_id, tenant_id=request.user.tenant_id)",
                "    row.save()",
                "    return {'ok': True}",
                "",
                "@permission_required('quota.manage')",
                "def api_quota_dynamic_sink(request, quota_id: int):",
                "    cleaned = normalize_quota_name(request.data['name'])",
                "    row = QuotaRule.objects.get(pk=quota_id, tenant_id=request.user.tenant_id)",
                "    getattr(row, request.data['action'])()",
                "    return {'ok': True}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    diff_map = build_boundary_diff_map(
        "quota",
        src_dir,
        baseline_entrypoint="api:api.api_quota_static_baseline",
    )
    by_qname = {ep.qualified_name: ep for ep in diff_map.entrypoints}

    # Dynamic permission cases -> PermissionStatus.UNKNOWN, no safe permission tags
    for perm_unknown_name in (
        "api.DynamicPermQuotaApiView.post",
        "api.api_quota_getattr_perm",
        "api.api_quota_unresolved_decorator",
        "api.api_quota_conditional_perm",
    ):
        ep = by_qname[perm_unknown_name]
        assert ep.permission_status == PermissionStatus.UNKNOWN, perm_unknown_name
        assert ep.permission_checks == (), perm_unknown_name
        assert any(
            u.category == BoundaryItemCategory.PERMISSION_CHECK and "unknown" in u.tags
            for u in ep.unknown_items
        ), perm_unknown_name

    # Dynamic scoping -> ScopingStatus.UNKNOWN, no tenant_or_owner_scoped tag
    scope_unknown = by_qname["api.api_quota_dynamic_kwargs_scope"]
    assert scope_unknown.scoping_status == ScopingStatus.UNKNOWN
    assert not any("tenant_or_owner_scoped" in s.tags for s in scope_unknown.target_scopings)
    assert any(
        u.category == BoundaryItemCategory.TARGET_SCOPING and "unknown" in u.tags
        for u in scope_unknown.unknown_items
    )

    # Dynamic validator -> ValidationStatus.UNKNOWN, no safe validation tags
    val_unknown = by_qname["api.api_quota_dynamic_validator"]
    assert val_unknown.validation_status == ValidationStatus.UNKNOWN
    assert val_unknown.input_validations == ()
    assert any(
        u.category == BoundaryItemCategory.INPUT_VALIDATION and "unknown" in u.tags
        for u in val_unknown.unknown_items
    )

    # Dynamic sink -> UpdateSinkStatus.UNKNOWN, no safe sink tags
    sink_unknown = by_qname["api.api_quota_dynamic_sink"]
    assert sink_unknown.update_sink_status == UpdateSinkStatus.UNKNOWN
    assert sink_unknown.update_sinks == ()
    assert any(
        u.category == BoundaryItemCategory.UPDATE_SINK and "unknown" in u.tags
        for u in sink_unknown.unknown_items
    )

    indeterminable_diffs = [
        d
        for d in diff_map.cross_path_diffs
        if d.category == DiffCategory.INDETERMINABLE_BOUNDARY
    ]
    assert {d.compared_entrypoint_id for d in indeterminable_diffs} == {
        f"api:{name}"
        for name in (
            "api.DynamicPermQuotaApiView.post",
            "api.api_quota_getattr_perm",
            "api.api_quota_unresolved_decorator",
            "api.api_quota_conditional_perm",
            "api.api_quota_dynamic_kwargs_scope",
            "api.api_quota_dynamic_validator",
            "api.api_quota_dynamic_sink",
        )
    }

    # Even comparing two unknown paths directly must NOT claim parity
    two_unknown_dir = tmp_path / "two_unknown"
    two_unknown_dir.mkdir()
    (two_unknown_dir / "api.py").write_text(
        "\n".join(
            [
                "class UnknownOneApiView(APIView):",
                "    permission_classes = get_perms_a()",
                "    def post(self, request, item_id: int):",
                "        row = Item.objects.get(pk=item_id, tenant_id=request.user.tenant_id)",
                "        row.save()",
                "",
                "class UnknownTwoApiView(APIView):",
                "    permission_classes = get_perms_b()",
                "    def post(self, request, item_id: int):",
                "        row = Item.objects.get(pk=item_id, tenant_id=request.user.tenant_id)",
                "        row.save()",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    two_unknown_map = build_boundary_diff_map("item", two_unknown_dir)
    assert any(
        d.category == DiffCategory.INDETERMINABLE_BOUNDARY
        for d in two_unknown_map.cross_path_diffs
    )


