"""CLI integration and regression tests for VDP Feature 1 & Feature 2 subcommands."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

from ctf_mcp.adapters.vdp_product_test import load_registered_vdp_profiles
from ctf_mcp.cli import admin_main, build_admin_parser
from ctf_mcp.vdp_boundary_map import BOUNDARY_MAP_SUBCOMMAND, INVESTIGATION_CANDIDATE_STATUS
from ctf_mcp.vdp_overlay_assistant import OVERLAY_ASSISTANT_COMMAND


def _create_synthetic_boundary_app(root: Path) -> tuple[Path, Path]:
    src_dir = root / "src_app"
    test_dir = root / "app_tests"
    src_dir.mkdir(parents=True)
    test_dir.mkdir(parents=True)

    (src_dir / "__init__.py").write_text("", encoding="utf-8")
    (src_dir / "services.py").write_text(
        "\n".join(
            [
                "def normalize_webhook_url(raw_url: str) -> str:",
                "    return raw_url.strip().lower().rstrip('/')",
                "",
                "def save_sync_config(target, url: str) -> None:",
                "    target.endpoint_url = url",
                "    target.save()",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (src_dir / "api.py").write_text(
        "\n".join(
            [
                "from src_app.services import normalize_webhook_url, save_sync_config",
                "",
                "@api_view(['PUT'])",
                "@permission_required('sync.manage')",
                "def api_sync_config(request, target_id: int):",
                "    url = normalize_webhook_url(request.data['endpoint_url'])",
                "    target = SyncTarget.objects.filter(id=target_id, owner=request.user).first()",
                "    save_sync_config(target, url)",
                "    return {'ok': True}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (src_dir / "webhooks.py").write_text(
        "\n".join(
            [
                "from src_app.services import save_sync_config",
                "",
                "@app.post('/webhooks/sync-config')",
                "def webhook_sync_config(payload: dict):",
                "    target = SyncTarget.objects.filter(endpoint_url__endswith=payload['endpoint_url']).first()",
                "    save_sync_config(target, payload['endpoint_url'])",
                "    return {'accepted': True}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (test_dir / "test_sync_config.py").write_text(
        "\n".join(
            [
                "def test_api_sync_config_checks_403_and_other_owner():",
                "    assert ('api_sync_config', 403, 'other_owner')",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return src_dir, test_dir


def _init_synthetic_git_repo(repo_dir: Path) -> str:
    repo_dir.mkdir(parents=True, exist_ok=True)
    env = {
        "GIT_AUTHOR_NAME": "Synthetic Tester",
        "GIT_AUTHOR_EMAIL": "synthetic@example.invalid",
        "GIT_COMMITTER_NAME": "Synthetic Tester",
        "GIT_COMMITTER_EMAIL": "synthetic@example.invalid",
    }
    subprocess.run(["git", "init"], cwd=str(repo_dir), check=True, capture_output=True)
    (repo_dir / "README.md").write_text("synthetic target\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=str(repo_dir), check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "synthetic init"],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
        env=env,
    )
    res = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
        text=True,
    )
    return res.stdout.strip().lower()


def _write_fake_docker(tmp_path: Path, digest: str, *, exit_code: int = 0) -> Path:
    """Write a POSIX shebang fake-docker executable (runs natively on Linux/WSL2; not Win32)."""
    script = tmp_path / "fake-docker"
    if exit_code == 0:
        body = f"#!{sys.executable}\nimport sys\nprint({digest!r})\n"
    else:
        body = (
            f"#!{sys.executable}\nimport sys\n"
            f"print('daemon unavailable', file=sys.stderr)\n"
            f"sys.exit({exit_code})\n"
        )
    script.write_text(body, encoding="utf-8")
    script.chmod(0o755)
    return script


def test_admin_parser_exposes_feature1_and_feature2_subcommands() -> None:
    parser = build_admin_parser()
    subparsers_actions = [
        action for action in parser._actions if hasattr(action, "choices") and isinstance(action.choices, dict)
    ]
    assert subparsers_actions
    commands = set(subparsers_actions[0].choices.keys())
    assert BOUNDARY_MAP_SUBCOMMAND in commands
    assert OVERLAY_ASSISTANT_COMMAND in commands
    assert "register-vdp-profile" in commands
    assert "check-vdp-env" in commands


def test_admin_main_vdp_boundary_map_json_and_fail_closed(tmp_path: Path, capsys) -> None:
    src_dir, test_dir = _create_synthetic_boundary_app(tmp_path)

    rc = admin_main(
        [
            "vdp-boundary-map",
            "--feature",
            "sync_config",
            "--source-dir",
            str(src_dir),
            "--test-dir",
            str(test_dir),
            "--baseline-kind",
            "api",
            "--format",
            "json",
        ],
        env={},
    )
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["status_policy"] == "investigation_candidate_only"
    assert out["entrypoints_by_kind"]["api"] == 1
    assert out["entrypoints_by_kind"]["webhook"] == 1
    assert out["cross_path_diffs"]
    for diff in out["cross_path_diffs"]:
        assert diff["status"] == INVESTIGATION_CANDIDATE_STATUS
        assert all(":" in loc for loc in diff["evidence_locations"])

    rc_bad = admin_main(
        [
            "vdp-boundary-map",
            "--feature",
            "sync_config",
            "--source-dir",
            str(tmp_path / "missing-src"),
        ],
        env={},
    )
    assert rc_bad == 2
    assert "error (" in capsys.readouterr().err


def test_admin_main_register_vdp_overlay_dry_run_confirm_and_overwrite_refusal(
    tmp_path: Path,
    capsys,
) -> None:
    vault_root = tmp_path / "vault"
    vault_root.mkdir()
    overlay_dir = tmp_path / "synthetic-overlay"
    overlay_dir.mkdir()
    test_file = overlay_dir / "test_synthetic_cli.py"
    test_content = (
        "class TestSyntheticCli:\n"
        "    def test_positive_sync(self):\n"
        "        assert True\n\n"
        "    def test_defense_boundary(self):\n"
        "        assert True\n\n"
        "    def test_custom_probe(self):\n"
        "        assert True\n"
    )
    test_file.write_text(test_content, encoding="utf-8")
    expected_sha = hashlib.sha256(test_content.encode("utf-8")).hexdigest()

    checkout_dir = tmp_path / "checkout"
    commit_sha = _init_synthetic_git_repo(checkout_dir)
    image_digest = "sha256:" + ("2" * 64)
    fake_docker = _write_fake_docker(tmp_path, image_digest)
    custom_selector = "/src/vdp-test-overlay/test_synthetic_cli.py::TestSyntheticCli::test_custom_probe"

    base_args = [
        "register-vdp-overlay",
        "--vault-root",
        str(vault_root),
        "--overlay-dir",
        str(overlay_dir),
        "--profile-name",
        "synthetic-cli-app",
        "--overlay-bundle",
        "synthetic-cli-b1",
        "--image-ref",
        "synthetic-cli:1.0",
        "--image-digest",
        image_digest,
        "--source-commit",
        commit_sha,
        "--checkout-dir",
        str(checkout_dir),
        "--selector-role",
        f"{custom_selector}=anomaly_repro",
        "--config-diff",
        "max_timeout_seconds=90",
        "--docker-bin",
        str(fake_docker),
    ]

    # 1. Default dry-run preview does not write profiles.json
    rc_dry = admin_main(base_args, env={})
    assert rc_dry == 0
    dry_out = json.loads(capsys.readouterr().out)
    assert dry_out["status"] == "dry_run_preview"
    assert dry_out["dry_run"] is True
    assert dry_out["applied"] is False
    assert dry_out["can_apply"] is True
    assert dry_out["env_health"]["healthy"] is True
    assert dry_out["added_overlays"]["synthetic-cli-b1"]["allowed_files"]["test_synthetic_cli.py"] == expected_sha
    assert dry_out["selector_roles"][custom_selector] == "anomaly_repro"
    assert not (vault_root / "_vdp" / "profiles.json").exists()

    # 2. --apply without --confirm-apply fails closed
    rc_no_confirm = admin_main([*base_args, "--apply"], env={})
    assert rc_no_confirm == 2
    err_no_confirm = capsys.readouterr().err
    assert "confirmation_required" in err_no_confirm or "confirm" in err_no_confirm.lower()
    assert not (vault_root / "_vdp" / "profiles.json").exists()

    # 3. --apply --confirm-apply persists profile
    rc_apply = admin_main([*base_args, "--apply", "--confirm-apply", "--require-healthy-env"], env={})
    assert rc_apply == 0
    apply_out = json.loads(capsys.readouterr().out)
    assert apply_out["status"] == "registered"
    assert apply_out["dry_run"] is False
    assert apply_out["applied"] is True
    profiles = load_registered_vdp_profiles(vault_root)
    assert "synthetic-cli-app" in profiles
    assert "synthetic-cli-b1" in profiles["synthetic-cli-app"].allowed_overlays

    # 4. Re-applying the same overlay bundle fails closed without modifying stored profile
    rc_dup = admin_main([*base_args, "--apply", "--confirm-apply"], env={})
    assert rc_dup == 2
    assert "error (" in capsys.readouterr().err


def test_admin_main_register_vdp_overlay_unhealthy_env_refusal_and_cross_base_cli(
    tmp_path: Path,
    capsys,
) -> None:
    vault_root = tmp_path / "vault"
    vault_root.mkdir()
    checkout_dir = tmp_path / "checkout"
    commit_sha = _init_synthetic_git_repo(checkout_dir)
    image_digest = "sha256:" + ("3" * 64)
    healthy_docker = _write_fake_docker(tmp_path, image_digest)
    failing_docker_dir = tmp_path / "bad_docker"
    failing_docker_dir.mkdir()
    failing_docker = _write_fake_docker(failing_docker_dir, image_digest, exit_code=1)

    overlay_t = tmp_path / "overlay-target"
    overlay_t.mkdir()
    (overlay_t / "test_target.py").write_text("def test_positive_target():\n    assert True\n", encoding="utf-8")

    overlay_b = tmp_path / "overlay-base"
    overlay_b.mkdir()
    (overlay_b / "test_base.py").write_text("def test_positive_base():\n    assert True\n", encoding="utf-8")

    # 1. Default unhealthy-env refusal on --apply --confirm-apply (without passing --require-healthy-env)
    unhealthy_args = [
        "register-vdp-overlay",
        "--vault-root",
        str(vault_root),
        "--overlay-dir",
        str(overlay_t),
        "--profile-name",
        "target-app",
        "--overlay-bundle",
        "bundle-target",
        "--image-ref",
        "synthetic-cli:1.0",
        "--image-digest",
        image_digest,
        "--source-commit",
        commit_sha,
        "--checkout-dir",
        str(checkout_dir),
        "--docker-bin",
        str(failing_docker),
    ]
    rc_unhealthy = admin_main([*unhealthy_args, "--apply", "--confirm-apply"], env={})
    assert rc_unhealthy == 2
    assert "error (" in capsys.readouterr().err
    assert not (vault_root / "_vdp" / "profiles.json").exists()

    # 2. Explicit --allow-unhealthy-env overrides env refusal and persists target-app
    rc_override = admin_main(
        [*unhealthy_args, "--apply", "--confirm-apply", "--allow-unhealthy-env"],
        env={},
    )
    assert rc_override == 0
    _ = json.loads(capsys.readouterr().out)
    assert "bundle-target" in load_registered_vdp_profiles(vault_root)["target-app"].allowed_overlays

    # Register base-app cleanly
    rc_base = admin_main(
        [
            "register-vdp-overlay",
            "--vault-root",
            str(vault_root),
            "--overlay-dir",
            str(overlay_b),
            "--profile-name",
            "base-app",
            "--overlay-bundle",
            "bundle-base",
            "--image-ref",
            "synthetic-cli:1.0",
            "--image-digest",
            image_digest,
            "--source-commit",
            commit_sha,
            "--checkout-dir",
            str(checkout_dir),
            "--docker-bin",
            str(healthy_docker),
            "--apply",
            "--confirm-apply",
        ],
        env={},
    )
    assert rc_base == 0
    _ = capsys.readouterr()

    # 3. Cross-base onto existing target-app surfaces removed_overlays & refuses apply
    overlay_extra = tmp_path / "overlay-extra"
    overlay_extra.mkdir()
    (overlay_extra / "test_extra.py").write_text("def test_defense_extra():\n    assert True\n", encoding="utf-8")
    cross_args = [
        "register-vdp-overlay",
        "--vault-root",
        str(vault_root),
        "--overlay-dir",
        str(overlay_extra),
        "--profile-name",
        "target-app",
        "--base-profile",
        "base-app",
        "--overlay-bundle",
        "bundle-extra",
        "--docker-bin",
        str(healthy_docker),
    ]
    rc_cross_dry = admin_main(cross_args, env={})
    assert rc_cross_dry == 0
    cross_out = json.loads(capsys.readouterr().out)
    assert cross_out["can_apply"] is False
    assert "bundle-target" in cross_out["removed_overlays"]
    assert any(c["code"] == "cross_base_profile_existing_target_denied" for c in cross_out["apply_conflicts"])

    rc_cross_apply = admin_main([*cross_args, "--apply", "--confirm-apply"], env={})
    assert rc_cross_apply == 2
    assert "error (" in capsys.readouterr().err
    assert "bundle-target" in load_registered_vdp_profiles(vault_root)["target-app"].allowed_overlays


def test_admin_main_vdp_boundary_map_open_untrusted_and_unknown_cli(
    tmp_path: Path,
    capsys,
) -> None:
    src_dir = tmp_path / "src_edge"
    src_dir.mkdir(parents=True)
    (src_dir / "views.py").write_text(
        "\n".join(
            [
                "class ApiExportView(APIView):",
                "    permission_classes = [IsAuthenticated]",
                "    def post(self, request, item_id):",
                "        obj = Item.objects.filter(id=item_id, tenant_id=request.user.tenant_id).first()",
                "        obj.export_url = request.data['url']",
                "        obj.save()",
                "",
                "class OpenExportView(APIView):",
                "    permission_classes = [AllowAny]",
                "    def post(self, request, item_id):",
                "        def _unused():",
                "            require_permission('export.write')",
                "        obj = Item.objects.filter(id=item_id, tenant_id=request.data['tenant_id']).first()",
                "        obj.export_url = request.data['url']",
                "        obj.save()",
                "",
                "@app.post('/webhooks/export')",
                "def webhook_export(request):",
                "    handler = getattr(handlers, request.data['kind'])",
                "    return handler(request)",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    rc = admin_main(
        [
            "vdp-boundary-map",
            "--feature",
            "export",
            "--source-dir",
            str(src_dir),
            "--baseline-kind",
            "api",
            "--format",
            "json",
        ],
        env={},
    )
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    open_ep = next(ep for ep in payload["entrypoints"] if "OpenExportView" in ep["entrypoint_id"])
    webhook_ep = next(ep for ep in payload["entrypoints"] if ep["name"] == "webhook_export")
    assert open_ep["permission_status"] == "open_access"
    assert open_ep["scoping_status"] == "untrusted_scoped"
    assert webhook_ep["unknown_items"]
    categories = {d["category"] for d in payload["cross_path_diffs"]}
    assert "missing_permission_check" in categories
    assert "scoping_mismatch" in categories
    assert "indeterminable_boundary" in categories
    for diff in payload["cross_path_diffs"]:
        assert diff["status"] == INVESTIGATION_CANDIDATE_STATUS
