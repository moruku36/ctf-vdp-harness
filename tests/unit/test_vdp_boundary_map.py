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
    CoverageGapType,
    DiffCategory,
    EntrypointKind,
    INVESTIGATION_CANDIDATE_STATUS,
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

