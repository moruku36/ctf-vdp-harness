"""Runnable synthetic example for the Auth Boundary Diff Map (Feature 1).

Builds a temporary in-memory synthetic multi-entrypoint Python application
(UI, API, Webhook, and Async task) plus a partial test suite, runs
``build_boundary_diff_map(...)``, and prints the formatted Markdown report.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from ctf_mcp.vdp_boundary_map import (
    build_boundary_diff_map,
    format_boundary_diff_map,
)


def _create_demo_app(root: Path) -> tuple[Path, Path]:
    src = root / "demo_app"
    tests = root / "demo_tests"
    src.mkdir(parents=True)
    tests.mkdir(parents=True)

    (src / "services.py").write_text(
        "\n".join(
            [
                "from urllib.parse import urlparse",
                "",
                "def normalize_endpoint_url(raw_url: str) -> str:",
                "    cleaned = raw_url.strip().lower()",
                "    if urlparse(cleaned).scheme != 'https':",
                "        raise ValueError('HTTPS required')",
                "    return cleaned.rstrip('/')",
                "",
                "def save_export_target(target, url: str) -> None:",
                "    target.endpoint_url = url",
                "    target.save()",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    (src / "views.py").write_text(
        "\n".join(
            [
                "from demo_app.services import normalize_endpoint_url, save_export_target",
                "",
                "@login_required",
                "@permission_required('export.edit')",
                "def ui_export_config(request, target_id: int):",
                "    url = normalize_endpoint_url(request.POST['endpoint_url'])",
                "    target = ExportTarget.objects.get(pk=target_id, owner=request.user)",
                "    save_export_target(target, url)",
                "    return {'ok': True}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    (src / "api.py").write_text(
        "\n".join(
            [
                "from demo_app.services import normalize_endpoint_url, save_export_target",
                "",
                "@api_view(['PUT'])",
                "@require_permission('export.edit')",
                "def api_export_config(request, target_id: int):",
                "    url = normalize_endpoint_url(request.data['endpoint_url'])",
                "    target = ExportTarget.objects.filter(id=target_id, owner=request.user).first()",
                "    save_export_target(target, url)",
                "    return {'ok': True}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    (src / "webhooks.py").write_text(
        "\n".join(
            [
                "from demo_app.services import save_export_target",
                "",
                "@app.post('/webhooks/export-config')",
                "def webhook_export_config(payload: dict):",
                "    raw = payload['endpoint_url'].rstrip('/')",
                "    target = ExportTarget.objects.filter(endpoint_url__endswith=raw).first()",
                "    save_export_target(target, raw)",
                "    return {'accepted': True}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    (src / "tasks.py").write_text(
        "\n".join(
            [
                "from demo_app.services import save_export_target",
                "",
                "@shared_task",
                "def async_export_config_task(target_id: int, endpoint_url: str):",
                "    target = ExportTarget.objects.get(pk=target_id)",
                "    save_export_target(target, endpoint_url)",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    (tests / "test_export_config.py").write_text(
        "\n".join(
            [
                "def test_api_export_config_checks_403_and_other_owner():",
                "    assert ('api_export_config', 403, 'other_owner', 400, 'invalid')",
                "",
                "def test_ui_export_config_checks_403_and_other_owner():",
                "    assert ('ui_export_config', 403, 'other_owner', 400, 'invalid')",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    return src, tests


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="vdp_boundary_example_") as tmp:
        src_dir, test_dir = _create_demo_app(Path(tmp))
        diff_map = build_boundary_diff_map(
            "export_config",
            src_dir,
            test_dir=test_dir,
            baseline_kind="api",
        )
        print(format_boundary_diff_map(diff_map, output_format="markdown"))


if __name__ == "__main__":
    main()
