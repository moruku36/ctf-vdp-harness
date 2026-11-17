"""Unit and acceptance tests for the synthetic VDP overlay registration assistant."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from ctf_mcp.adapters.vdp_product_test import (
    VdpOverlaySpec,
    VdpTargetProfile,
    load_registered_vdp_profiles,
    save_registered_vdp_profile,
    validate_vdp_profile_registration,
)
from ctf_mcp.contracts import (
    ContractViolationError,
    PathSecurityError,
    ScopeDeniedError,
)
from ctf_mcp.vdp_overlay_assistant import (
    generate_overlay_registration_plan,
    handle_overlay_assistant,
    infer_selector_role,
    preview_and_register_overlay,
    register_overlay_assistant_subparser,
    scan_overlay_directory,
)

SYNTHETIC_IMAGE_REF = "synthetic-target:1.0.0"
SYNTHETIC_IMAGE_DIGEST = "sha256:" + ("1" * 64)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _init_synthetic_git_repo(repo_dir: Path) -> str:
    repo_dir.mkdir(parents=True, exist_ok=True)
    env = {
        "GIT_AUTHOR_NAME": "Synthetic Tester",
        "GIT_AUTHOR_EMAIL": "synthetic@example.invalid",
        "GIT_COMMITTER_NAME": "Synthetic Tester",
        "GIT_COMMITTER_EMAIL": "synthetic@example.invalid",
    }
    subprocess.run(["git", "init"], cwd=str(repo_dir), check=True, capture_output=True)
    (repo_dir / "README.md").write_text("synthetic target repo\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=str(repo_dir), check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "initial synthetic commit"],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
        env=env,
    )
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
        text=True,
    )
    return head.stdout.strip().lower()


def _write_fake_docker(
    tmp_path: Path,
    *,
    image_digest: str = SYNTHETIC_IMAGE_DIGEST,
    inspect_fail: bool = False,
) -> Path:
    script = tmp_path / "fake-docker"
    script.write_text(
        f"""#!{sys.executable}
import sys
args = sys.argv[1:]
if args[:2] == ["image", "inspect"]:
    if {inspect_fail!r}:
        sys.stderr.write("Error: No such image\\n")
        sys.exit(1)
    sys.stdout.write({image_digest!r} + "\\n")
    sys.exit(0)
sys.stderr.write("Unexpected docker subcommand\\n")
sys.exit(2)
""",
        encoding="utf-8",
    )
    script.chmod(0o755)
    return script


def _create_synthetic_overlay(overlay_dir: Path) -> dict[str, str]:
    overlay_dir.mkdir(parents=True, exist_ok=True)
    test_src = """\"\"\"Synthetic overlay tests for registration assistant tests.\"\"\"

def helper_not_a_test():
    return True


class HelperNonTestClass:
    def test_ignored(self):
        assert True


def test_positive_control_case():
    assert True


async def test_env_async_readiness():
    assert True


class TestSyntheticSuite:
    def helper_method(self):
        return 1

    def test_defense_boundary_enforced(self):
        assert True

    def test_anomaly_repro_candidate(self):
        assert True

    def test_custom_named_case(self):
        assert True
"""
    helper_src = "SYNTHETIC_CONSTANT = 42\n"
    test_file = overlay_dir / "test_synthetic.py"
    helper_file = overlay_dir / "helpers.py"
    test_file.write_text(test_src, encoding="utf-8")
    helper_file.write_text(helper_src, encoding="utf-8")
    return {
        "test_synthetic.py": _sha256_bytes(test_file.read_bytes()),
        "helpers.py": _sha256_bytes(helper_file.read_bytes()),
    }


def test_scan_and_plan_discovers_selectors_hashes_and_roles(tmp_path: Path) -> None:
    overlay_dir = tmp_path / "overlay-bundle-1"
    expected_hashes = _create_synthetic_overlay(overlay_dir)
    commit_sha = "a" * 40
    custom_sel = "/src/vdp-test-overlay/test_synthetic.py::TestSyntheticSuite::test_custom_named_case"

    scan = scan_overlay_directory(overlay_dir)
    assert scan["allowed_files"] == expected_hashes
    assert scan["test_files"] == ["test_synthetic.py"]
    assert scan["discovered_selectors"] == [
        "/src/vdp-test-overlay/test_synthetic.py::test_positive_control_case",
        "/src/vdp-test-overlay/test_synthetic.py::test_env_async_readiness",
        "/src/vdp-test-overlay/test_synthetic.py::TestSyntheticSuite::test_defense_boundary_enforced",
        "/src/vdp-test-overlay/test_synthetic.py::TestSyntheticSuite::test_anomaly_repro_candidate",
        custom_sel,
    ]

    plan = generate_overlay_registration_plan(
        overlay_dir=overlay_dir,
        profile_name="synthetic-app",
        overlay_bundle="synthetic-b1",
        role_overrides={custom_sel: "defense_check"},
        config_diffs={"max_timeout_seconds": 120, "notes": "synthetic preview"},
        image_ref=SYNTHETIC_IMAGE_REF,
        expected_image_digest=SYNTHETIC_IMAGE_DIGEST,
        expected_source_commit=commit_sha,
    )
    assert plan["profile_name"] == "synthetic-app"
    assert plan["profile_revision"] == "r1"
    assert plan["can_apply"] is True
    assert plan["apply_conflicts"] == []
    assert plan["added_overlays"]["synthetic-b1"]["allowed_files"] == expected_hashes
    assert plan["selector_roles"] == {
        "/src/vdp-test-overlay/test_synthetic.py::test_positive_control_case": "positive_control",
        "/src/vdp-test-overlay/test_synthetic.py::test_env_async_readiness": "env_check",
        "/src/vdp-test-overlay/test_synthetic.py::TestSyntheticSuite::test_defense_boundary_enforced": "defense_check",
        "/src/vdp-test-overlay/test_synthetic.py::TestSyntheticSuite::test_anomaly_repro_candidate": "anomaly_repro",
        custom_sel: "defense_check",
    }
    assert plan["config_diffs"]["network_mode"] == "none"
    assert plan["config_diffs"]["resource_caps"]["max_timeout_seconds"] == 120
    assert plan["config_diffs"]["notes"] == "synthetic preview"


def test_fail_closed_on_ambiguous_role_symlinks_traversal_and_unsafe_config(tmp_path: Path) -> None:
    # 1. Ambiguous test function name without explicit override fails closed
    ambig_dir = tmp_path / "overlay-ambig"
    ambig_dir.mkdir()
    (ambig_dir / "test_ambig.py").write_text("def test_unclear_behavior():\n    assert True\n", encoding="utf-8")
    with pytest.raises(ContractViolationError, match="Cannot determine selector role"):
        generate_overlay_registration_plan(
            overlay_dir=ambig_dir,
            profile_name="synthetic-app",
            overlay_bundle="bundle-ambig",
            image_ref=SYNTHETIC_IMAGE_REF,
            expected_image_digest=SYNTHETIC_IMAGE_DIGEST,
            expected_source_commit="b" * 40,
        )
    assert infer_selector_role(
        "/src/vdp-test-overlay/test_ambig.py::test_unclear_behavior",
        explicit_roles={"/src/vdp-test-overlay/test_ambig.py::test_unclear_behavior": "env_check"},
    ) == "env_check"

    # 2. Path traversal in overlay_dir rejected
    with pytest.raises(PathSecurityError):
        scan_overlay_directory(str(ambig_dir) + "/../overlay-ambig")

    # 3. Symlink inside overlay_dir rejected
    sym_dir = tmp_path / "overlay-sym"
    sym_dir.mkdir()
    target = tmp_path / "outside.py"
    target.write_text("def test_positive_outside(): assert True\n", encoding="utf-8")
    (sym_dir / "test_link.py").symlink_to(target)
    with pytest.raises(ScopeDeniedError, match="symlink"):
        scan_overlay_directory(sym_dir)

    # 4. Symlinked overlay_dir itself rejected
    sym_root = tmp_path / "overlay-root-link"
    sym_root.symlink_to(ambig_dir)
    with pytest.raises(PathSecurityError, match="non-symlink"):
        scan_overlay_directory(sym_root)

    # 5. Subdirectory inside overlay_dir rejected
    sub_dir = tmp_path / "overlay-nested"
    sub_dir.mkdir()
    (sub_dir / "test_positive_ok.py").write_text("def test_positive_ok(): assert True\n", encoding="utf-8")
    (sub_dir / "nested").mkdir()
    with pytest.raises(ScopeDeniedError, match="regular file"):
        scan_overlay_directory(sub_dir)

    # 6. Sensitive marker rejected
    secret_dir = tmp_path / "overlay-secret"
    secret_dir.mkdir()
    (secret_dir / "test_positive_secret.py").write_text(
        'def test_positive_secret():\n    x = "SYNTHETIC_SECRET_TOKEN"\n',
        encoding="utf-8",
    )
    with pytest.raises(ScopeDeniedError, match="sensitive markers"):
        scan_overlay_directory(secret_dir)

    # 7. Disallowed network_mode and excessive resource caps rejected
    clean_dir = tmp_path / "overlay-clean"
    clean_dir.mkdir()
    (clean_dir / "test_positive_ok.py").write_text("def test_positive_ok(): assert True\n", encoding="utf-8")

    with pytest.raises(ContractViolationError, match="network_mode"):
        generate_overlay_registration_plan(
            overlay_dir=clean_dir,
            profile_name="synthetic-app",
            overlay_bundle="bundle-clean",
            config_diffs={"network_mode": "bridge"},
            image_ref=SYNTHETIC_IMAGE_REF,
            expected_image_digest=SYNTHETIC_IMAGE_DIGEST,
            expected_source_commit="c" * 40,
        )

    with pytest.raises(ContractViolationError, match="max_cpus"):
        generate_overlay_registration_plan(
            overlay_dir=clean_dir,
            profile_name="synthetic-app",
            overlay_bundle="bundle-clean",
            config_diffs={"max_cpus": 16},
            image_ref=SYNTHETIC_IMAGE_REF,
            expected_image_digest=SYNTHETIC_IMAGE_DIGEST,
            expected_source_commit="c" * 40,
        )

    with pytest.raises(ContractViolationError, match="Unsupported or unsafe config_diffs"):
        generate_overlay_registration_plan(
            overlay_dir=clean_dir,
            profile_name="synthetic-app",
            overlay_bundle="bundle-clean",
            config_diffs={"privileged": True},
            image_ref=SYNTHETIC_IMAGE_REF,
            expected_image_digest=SYNTHETIC_IMAGE_DIGEST,
            expected_source_commit="c" * 40,
        )


def test_dry_run_preview_does_not_mutate_vault_or_runs_and_apply_requires_confirm(tmp_path: Path) -> None:
    checkout_dir = tmp_path / "synthetic-checkout"
    commit_sha = _init_synthetic_git_repo(checkout_dir)
    fake_docker = _write_fake_docker(tmp_path)

    vault_root = tmp_path / "vault"
    vault_root.mkdir()
    # Seed synthetic existing run/evidence artifacts to verify zero mutation
    blob_dir = vault_root / "blobs" / "aa"
    blob_dir.mkdir(parents=True)
    blob_file = blob_dir / ("a" * 64)
    blob_file.write_bytes(b"immutable-synthetic-evidence")
    db_file = tmp_path / "harness.db"
    db_file.write_bytes(b"synthetic-db-header")

    base_overlay_dir = tmp_path / "base-overlay"
    base_overlay_dir.mkdir()
    base_test = base_overlay_dir / "test_base.py"
    base_test.write_text("def test_positive_base():\n    assert True\n", encoding="utf-8")
    base_sha = _sha256_bytes(base_test.read_bytes())

    base_profile = validate_vdp_profile_registration(
        VdpTargetProfile(
            profile_name="synthetic-app",
            profile_revision="r1",
            image_ref=SYNTHETIC_IMAGE_REF,
            expected_image_digest=SYNTHETIC_IMAGE_DIGEST,
            expected_source_commit=commit_sha,
            checkout_dir=checkout_dir,
            allowed_test_selectors=("/src/vdp-test-overlay/test_base.py::test_positive_base",),
            positive_selectors=("/src/vdp-test-overlay/test_base.py::test_positive_base",),
            allowed_overlays={
                "bundle-base": VdpOverlaySpec(
                    bundle_name="bundle-base",
                    host_dir=base_overlay_dir,
                    container_target="/src/vdp-test-overlay",
                    allowed_files={"test_base.py": base_sha},
                )
            },
        )
    )
    profiles_path = save_registered_vdp_profile(vault_root, base_profile)
    before_profiles_bytes = profiles_path.read_bytes()

    new_overlay_dir = tmp_path / "new-overlay"
    _create_synthetic_overlay(new_overlay_dir)
    custom_sel = "/src/vdp-test-overlay/test_synthetic.py::TestSyntheticSuite::test_custom_named_case"

    # 1. Default preview (apply=False) runs diff + env check without mutating profiles.json
    preview = preview_and_register_overlay(
        overlay_dir=new_overlay_dir,
        profile_name="synthetic-app",
        overlay_bundle="bundle-next",
        vault_root=vault_root,
        role_overrides={custom_sel: "defense_check"},
        docker_bin=str(fake_docker),
    )
    assert preview["status"] == "dry_run_preview"
    assert preview["dry_run"] is True
    assert preview["applied"] is False
    assert preview["previous_revision"] == "r1"
    assert preview["profile_revision"] == "r2"
    assert preview["can_apply"] is True
    assert "bundle-next" in preview["added_overlays"]
    assert preview["updated_overlays"] == {}
    assert len(preview["added_selectors"]) == 5
    assert preview["env_health"]["healthy"] is True
    assert preview["env_health"]["checks"]["overlays"] == "ok"
    assert preview["existing_runs_and_evidence_untouched"] is True
    assert profiles_path.read_bytes() == before_profiles_bytes
    assert blob_file.read_bytes() == b"immutable-synthetic-evidence"
    assert db_file.read_bytes() == b"synthetic-db-header"

    # 2. apply=True without confirm_apply=True fails closed
    with pytest.raises(ContractViolationError, match="confirm_apply"):
        preview_and_register_overlay(
            overlay_dir=new_overlay_dir,
            profile_name="synthetic-app",
            overlay_bundle="bundle-next",
            vault_root=vault_root,
            role_overrides={custom_sel: "defense_check"},
            docker_bin=str(fake_docker),
            apply=True,
            confirm_apply=False,
        )
    assert profiles_path.read_bytes() == before_profiles_bytes

    # 3. apply=True + confirm_apply=True persists revision r2 cleanly
    applied = preview_and_register_overlay(
        overlay_dir=new_overlay_dir,
        profile_name="synthetic-app",
        overlay_bundle="bundle-next",
        vault_root=vault_root,
        role_overrides={custom_sel: "defense_check"},
        docker_bin=str(fake_docker),
        apply=True,
        confirm_apply=True,
        require_healthy_env=True,
    )
    assert applied["status"] == "registered"
    assert applied["dry_run"] is False
    assert applied["applied"] is True
    assert applied["profile_revision"] == "r2"

    loaded = load_registered_vdp_profiles(vault_root)
    assert loaded["synthetic-app"].profile_revision == "r2"
    assert "bundle-base" in loaded["synthetic-app"].allowed_overlays
    assert "bundle-next" in loaded["synthetic-app"].allowed_overlays
    assert blob_file.read_bytes() == b"immutable-synthetic-evidence"
    assert db_file.read_bytes() == b"synthetic-db-header"

    # 4. Overwriting an existing overlay bundle MUST be refused
    with pytest.raises(ContractViolationError, match="existing overlay bundle"):
        preview_and_register_overlay(
            overlay_dir=new_overlay_dir,
            profile_name="synthetic-app",
            overlay_bundle="bundle-next",
            vault_root=vault_root,
            role_overrides={custom_sel: "defense_check"},
            docker_bin=str(fake_docker),
            apply=True,
            confirm_apply=True,
        )

    # 5. Modifying an existing selector's role MUST be refused
    third_overlay = tmp_path / "third-overlay"
    third_overlay.mkdir()
    (third_overlay / "test_third.py").write_text("def test_env_third():\n    assert True\n", encoding="utf-8")
    with pytest.raises(ContractViolationError, match="alter the role of an existing selector"):
        preview_and_register_overlay(
            overlay_dir=third_overlay,
            profile_name="synthetic-app",
            overlay_bundle="bundle-third",
            vault_root=vault_root,
            role_overrides={"/src/vdp-test-overlay/test_base.py::test_positive_base": "defense_check"},
            docker_bin=str(fake_docker),
            apply=True,
            confirm_apply=True,
        )

    # 6. require_healthy_env=True refuses apply when docker check fails
    bad_docker = _write_fake_docker(tmp_path / "bad-docker-bin-dir", inspect_fail=True) if False else None
    del bad_docker
    bad_docker_dir = tmp_path / "bad-docker"
    bad_docker_dir.mkdir()
    bad_docker_bin = _write_fake_docker(bad_docker_dir, inspect_fail=True)
    with pytest.raises(ContractViolationError, match="Environment health check failed"):
        preview_and_register_overlay(
            overlay_dir=third_overlay,
            profile_name="synthetic-app",
            overlay_bundle="bundle-third",
            vault_root=vault_root,
            docker_bin=str(bad_docker_bin),
            apply=True,
            confirm_apply=True,
            require_healthy_env=True,
        )

    # 7. Overlay inside protected vault dir is refused
    vault_nested_overlay = vault_root / "blobs" / "bad-overlay"
    vault_nested_overlay.mkdir(parents=True)
    (vault_nested_overlay / "test_positive_nested.py").write_text("def test_positive_nested(): pass\n", encoding="utf-8")
    with pytest.raises(PathSecurityError, match="protected vault path"):
        generate_overlay_registration_plan(
            overlay_dir=vault_nested_overlay,
            profile_name="synthetic-app",
            overlay_bundle="bundle-bad",
            vault_root=vault_root,
        )


def test_cli_subparser_and_handler_dry_run_and_apply(tmp_path: Path, capsys: Any) -> None:
    checkout_dir = tmp_path / "cli-checkout"
    commit_sha = _init_synthetic_git_repo(checkout_dir)
    fake_docker = _write_fake_docker(tmp_path)
    vault_root = tmp_path / "cli-vault"
    vault_root.mkdir()
    overlay_dir = tmp_path / "cli-overlay"
    _create_synthetic_overlay(overlay_dir)
    custom_sel = "/src/vdp-test-overlay/test_synthetic.py::TestSyntheticSuite::test_custom_named_case"

    parser = argparse.ArgumentParser(prog="ctf-mcp-admin")
    subparsers = parser.add_subparsers(dest="command", required=True)
    register_overlay_assistant_subparser(subparsers)

    base_argv = [
        "register-vdp-overlay",
        "--vault-root",
        str(vault_root),
        "--overlay-dir",
        str(overlay_dir),
        "--profile-name",
        "synthetic-cli-app",
        "--overlay-bundle",
        "cli-bundle-1",
        "--image-ref",
        SYNTHETIC_IMAGE_REF,
        "--image-digest",
        SYNTHETIC_IMAGE_DIGEST,
        "--source-commit",
        commit_sha,
        "--checkout-dir",
        str(checkout_dir),
        "--selector-role",
        f"{custom_sel}=anomaly_repro",
        "--config-diff",
        "max_cpus=1",
        "--config-diff",
        "notes=cli-test",
        "--docker-bin",
        str(fake_docker),
    ]

    # Dry-run default
    args_dry = parser.parse_args(base_argv)
    rc_dry = handle_overlay_assistant(args_dry, env={})
    assert rc_dry == 0
    dry_out = json.loads(capsys.readouterr().out)
    assert dry_out["status"] == "dry_run_preview"
    assert dry_out["dry_run"] is True
    assert dry_out["applied"] is False
    assert dry_out["env_health"]["healthy"] is True
    assert dry_out["config_diffs"]["resource_caps"]["max_cpus"] == 1
    assert not (vault_root / "_vdp" / "profiles.json").exists()

    # --apply without --confirm-apply refuses
    args_no_confirm = parser.parse_args([*base_argv, "--apply"])
    with pytest.raises(ContractViolationError, match="confirm_apply"):
        handle_overlay_assistant(args_no_confirm, env={})
    assert not (vault_root / "_vdp" / "profiles.json").exists()

    # --apply --confirm-apply persists
    args_apply = parser.parse_args([*base_argv, "--apply", "--confirm-apply", "--require-healthy-env"])
    rc_apply = handle_overlay_assistant(args_apply, env={})
    assert rc_apply == 0
    apply_out = json.loads(capsys.readouterr().out)
    assert apply_out["status"] == "registered"
    assert apply_out["applied"] is True
    assert (vault_root / "_vdp" / "profiles.json").exists()
