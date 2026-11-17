"""Unit and acceptance tests for the synthetic VDP overlay registration assistant."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

import pytest

from ctf_mcp.adapters.vdp_product_test import (
    VdpOverlaySpec,
    VdpTargetProfile,
    compute_vdp_profile_digest,
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


def _make_synthetic_profile(
    *,
    profile_name: str,
    bundle_name: str,
    overlay_dir: Path,
    test_filename: str,
    func_name: str,
    checkout_dir: Path,
    commit_sha: str,
    revision: str = "r1",
) -> VdpTargetProfile:
    overlay_dir.mkdir(parents=True, exist_ok=True)
    test_file = overlay_dir / test_filename
    test_file.write_text(f"def {func_name}():\n    assert True\n", encoding="utf-8")
    file_sha = _sha256_bytes(test_file.read_bytes())
    selector = f"/src/vdp-test-overlay/{test_filename}::{func_name}"
    return validate_vdp_profile_registration(
        VdpTargetProfile(
            profile_name=profile_name,
            profile_revision=revision,
            image_ref=SYNTHETIC_IMAGE_REF,
            expected_image_digest=SYNTHETIC_IMAGE_DIGEST,
            expected_source_commit=commit_sha,
            checkout_dir=checkout_dir,
            allowed_test_selectors=(selector,),
            positive_selectors=(selector,),
            allowed_overlays={
                bundle_name: VdpOverlaySpec(
                    bundle_name=bundle_name,
                    host_dir=overlay_dir,
                    container_target="/src/vdp-test-overlay",
                    allowed_files={test_filename: file_sha},
                )
            },
        )
    )


def test_cross_base_profile_on_existing_target_refused_and_removed_diff_shown(tmp_path: Path) -> None:
    checkout_dir = tmp_path / "checkout"
    commit_sha = _init_synthetic_git_repo(checkout_dir)
    fake_docker = _write_fake_docker(tmp_path)
    vault_root = tmp_path / "vault"
    vault_root.mkdir()

    target_profile = _make_synthetic_profile(
        profile_name="target",
        bundle_name="bundle-target",
        overlay_dir=tmp_path / "ov-target",
        test_filename="test_target.py",
        func_name="test_positive_target",
        checkout_dir=checkout_dir,
        commit_sha=commit_sha,
    )
    # Even when base shares the same selector (previously caused can_apply=True and silent drop!),
    # cross-base on an existing target must surface removed_overlays and fail closed.
    base_shared_sel = _make_synthetic_profile(
        profile_name="base-shared",
        bundle_name="bundle-base-shared",
        overlay_dir=tmp_path / "ov-base-shared",
        test_filename="test_target.py",
        func_name="test_positive_target",
        checkout_dir=checkout_dir,
        commit_sha=commit_sha,
    )
    base_distinct = _make_synthetic_profile(
        profile_name="base-distinct",
        bundle_name="bundle-base-distinct",
        overlay_dir=tmp_path / "ov-base-distinct",
        test_filename="test_base.py",
        func_name="test_positive_base",
        checkout_dir=checkout_dir,
        commit_sha=commit_sha,
    )
    save_registered_vdp_profile(vault_root, target_profile)
    save_registered_vdp_profile(vault_root, base_shared_sel)
    save_registered_vdp_profile(vault_root, base_distinct)
    profiles_path = vault_root / "_vdp" / "profiles.json"
    before_bytes = profiles_path.read_bytes()

    new_ov = tmp_path / "ov-new"
    new_ov.mkdir()
    (new_ov / "test_new.py").write_text("def test_positive_new():\n    assert True\n", encoding="utf-8")

    # 1. Shared-selector base against existing target: removed_overlays catches bundle-target loss
    preview_shared = preview_and_register_overlay(
        overlay_dir=new_ov,
        profile_name="target",
        overlay_bundle="bundle-new",
        base_profile="base-shared",
        vault_root=vault_root,
        docker_bin=str(fake_docker),
    )
    assert preview_shared["can_apply"] is False
    assert "bundle-target" in preview_shared["removed_overlays"]
    assert preview_shared["removed_selectors"] == []
    codes_shared = {c["code"] for c in preview_shared["apply_conflicts"]}
    assert "cross_base_profile_existing_target_denied" in codes_shared
    assert "would_remove_existing_target_overlays" in codes_shared

    with pytest.raises(ContractViolationError) as exc_shared:
        preview_and_register_overlay(
            overlay_dir=new_ov,
            profile_name="target",
            overlay_bundle="bundle-new",
            base_profile="base-shared",
            vault_root=vault_root,
            docker_bin=str(fake_docker),
            apply=True,
            confirm_apply=True,
        )
    assert exc_shared.value.code == "registration_overwrite_refused"
    assert profiles_path.read_bytes() == before_bytes

    # 2. Distinct-selector base against existing target: both removed_overlays & removed_selectors populated against target
    preview_distinct = preview_and_register_overlay(
        overlay_dir=new_ov,
        profile_name="target",
        overlay_bundle="bundle-new",
        base_profile="base-distinct",
        vault_root=vault_root,
        docker_bin=str(fake_docker),
    )
    assert preview_distinct["can_apply"] is False
    assert "bundle-target" in preview_distinct["removed_overlays"]
    assert [s["selector"] for s in preview_distinct["removed_selectors"]] == [
        "/src/vdp-test-overlay/test_target.py::test_positive_target"
    ]
    codes_distinct = {c["code"] for c in preview_distinct["apply_conflicts"]}
    assert {
        "cross_base_profile_existing_target_denied",
        "would_remove_existing_target_overlays",
        "would_remove_existing_target_selectors",
    }.issubset(codes_distinct)

    # 3. Safe path A: updating existing target without --base-profile stacks cleanly
    stacked = preview_and_register_overlay(
        overlay_dir=new_ov,
        profile_name="target",
        overlay_bundle="bundle-new",
        vault_root=vault_root,
        docker_bin=str(fake_docker),
        apply=True,
        confirm_apply=True,
    )
    assert stacked["applied"] is True
    assert stacked["removed_overlays"] == {}
    assert stacked["removed_selectors"] == []
    loaded_target = load_registered_vdp_profiles(vault_root)["target"]
    assert set(loaded_target.allowed_overlays.keys()) == {"bundle-target", "bundle-new"}

    # 4. Safe path B: passing --base-profile target (self) stacks cleanly too
    ov_third = tmp_path / "ov-third"
    ov_third.mkdir()
    (ov_third / "test_third.py").write_text("def test_positive_third():\n    assert True\n", encoding="utf-8")
    stacked_self = preview_and_register_overlay(
        overlay_dir=ov_third,
        profile_name="target",
        overlay_bundle="bundle-third",
        base_profile="target",
        vault_root=vault_root,
        docker_bin=str(fake_docker),
        apply=True,
        confirm_apply=True,
    )
    assert stacked_self["applied"] is True
    assert stacked_self["removed_overlays"] == {}
    loaded_target_after = load_registered_vdp_profiles(vault_root)["target"]
    assert set(loaded_target_after.allowed_overlays.keys()) == {
        "bundle-target",
        "bundle-new",
        "bundle-third",
    }

    # 5. Safe path C: --base-profile base-distinct when creating a brand-new profile works cleanly
    cloned = preview_and_register_overlay(
        overlay_dir=new_ov,
        profile_name="brand-new-target",
        overlay_bundle="bundle-new",
        base_profile="base-distinct",
        vault_root=vault_root,
        docker_bin=str(fake_docker),
        apply=True,
        confirm_apply=True,
    )
    assert cloned["applied"] is True
    assert cloned["removed_overlays"] == {}
    assert cloned["removed_selectors"] == []
    loaded_all = load_registered_vdp_profiles(vault_root)
    assert set(loaded_all["brand-new-target"].allowed_overlays.keys()) == {
        "bundle-base-distinct",
        "bundle-new",
    }
    assert set(loaded_all["base-distinct"].allowed_overlays.keys()) == {"bundle-base-distinct"}


def test_unhealthy_env_refused_by_default_on_apply_and_cli_opt_out(tmp_path: Path, capsys: Any) -> None:
    checkout_dir = tmp_path / "checkout"
    commit_sha = _init_synthetic_git_repo(checkout_dir)
    bad_docker = _write_fake_docker(tmp_path, inspect_fail=True)
    vault_root = tmp_path / "vault"
    vault_root.mkdir()
    overlay_dir = tmp_path / "ov"
    overlay_dir.mkdir()
    (overlay_dir / "test_ok.py").write_text("def test_positive_ok():\n    assert True\n", encoding="utf-8")

    # 1. Dry-run preview surfaces env_check_failed and can_apply=False by default
    preview = preview_and_register_overlay(
        overlay_dir=overlay_dir,
        profile_name="unhealthy-app",
        overlay_bundle="bundle-1",
        vault_root=vault_root,
        image_ref=SYNTHETIC_IMAGE_REF,
        expected_image_digest=SYNTHETIC_IMAGE_DIGEST,
        expected_source_commit=commit_sha,
        checkout_dir=checkout_dir,
        docker_bin=str(bad_docker),
    )
    assert preview["env_health"]["healthy"] is False
    assert preview["can_apply"] is False
    assert any(c["code"] == "env_check_failed" for c in preview["apply_conflicts"])

    # 2. apply=True with default require_healthy_env=True refuses unhealthy env
    with pytest.raises(ContractViolationError) as exc:
        preview_and_register_overlay(
            overlay_dir=overlay_dir,
            profile_name="unhealthy-app",
            overlay_bundle="bundle-1",
            vault_root=vault_root,
            image_ref=SYNTHETIC_IMAGE_REF,
            expected_image_digest=SYNTHETIC_IMAGE_DIGEST,
            expected_source_commit=commit_sha,
            checkout_dir=checkout_dir,
            docker_bin=str(bad_docker),
            apply=True,
            confirm_apply=True,
        )
    assert exc.value.code == "env_check_failed"
    assert not (vault_root / "_vdp" / "profiles.json").exists()

    # 3. CLI default also refuses unhealthy env on --apply --confirm-apply without --require-healthy-env
    parser = argparse.ArgumentParser(prog="ctf-mcp-admin")
    subparsers = parser.add_subparsers(dest="command", required=True)
    register_overlay_assistant_subparser(subparsers)
    cli_args = [
        "register-vdp-overlay",
        "--vault-root",
        str(vault_root),
        "--overlay-dir",
        str(overlay_dir),
        "--profile-name",
        "unhealthy-app",
        "--overlay-bundle",
        "bundle-1",
        "--image-ref",
        SYNTHETIC_IMAGE_REF,
        "--image-digest",
        SYNTHETIC_IMAGE_DIGEST,
        "--source-commit",
        commit_sha,
        "--checkout-dir",
        str(checkout_dir),
        "--docker-bin",
        str(bad_docker),
        "--apply",
        "--confirm-apply",
    ]
    with pytest.raises(ContractViolationError) as cli_exc:
        handle_overlay_assistant(parser.parse_args(cli_args), env={})
    assert cli_exc.value.code == "env_check_failed"
    assert not (vault_root / "_vdp" / "profiles.json").exists()

    # 4. Explicit --allow-unhealthy-env opt-out permits apply when operator overrides
    rc = handle_overlay_assistant(parser.parse_args([*cli_args, "--allow-unhealthy-env"]), env={})
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["applied"] is True
    assert out["env_health"]["healthy"] is False
    assert "unhealthy-app" in load_registered_vdp_profiles(vault_root)


def test_concurrent_overlay_registration_cas_prevents_lost_updates(tmp_path: Path) -> None:
    checkout_dir = tmp_path / "checkout"
    commit_sha = _init_synthetic_git_repo(checkout_dir)
    vault_root = tmp_path / "vault"
    vault_root.mkdir()

    # Fake docker with brief delay so both threads overlap during env check before save
    slow_docker = tmp_path / "slow-fake-docker"
    slow_docker.write_text(
        f"#!{sys.executable}\n"
        "import sys, time\n"
        "time.sleep(0.05)\n"
        f"sys.stdout.write({SYNTHETIC_IMAGE_DIGEST!r} + '\\n')\n",
        encoding="utf-8",
    )
    slow_docker.chmod(0o755)

    base_prof = _make_synthetic_profile(
        profile_name="concurrent-app",
        bundle_name="bundle-base",
        overlay_dir=tmp_path / "ov-base",
        test_filename="test_base.py",
        func_name="test_positive_base",
        checkout_dir=checkout_dir,
        commit_sha=commit_sha,
        revision="r1",
    )
    save_registered_vdp_profile(vault_root, base_prof)

    ov_a = tmp_path / "ov-a"
    ov_a.mkdir()
    (ov_a / "test_a.py").write_text("def test_positive_a():\n    assert True\n", encoding="utf-8")
    ov_b = tmp_path / "ov-b"
    ov_b.mkdir()
    (ov_b / "test_b.py").write_text("def test_positive_b():\n    assert True\n", encoding="utf-8")

    # 1. Two concurrent writers adding distinct bundles to the same profile:
    #    exactly one succeeds (r2) and the stale writer fails closed with profile_cas_conflict.
    barrier = threading.Barrier(2)
    outcomes: list[tuple[str, str, Any]] = []
    outcomes_lock = threading.Lock()

    def _worker(ov_dir: Path, bundle: str) -> None:
        barrier.wait(timeout=5.0)
        try:
            res = preview_and_register_overlay(
                overlay_dir=ov_dir,
                profile_name="concurrent-app",
                overlay_bundle=bundle,
                vault_root=vault_root,
                docker_bin=str(slow_docker),
                apply=True,
                confirm_apply=True,
            )
            with outcomes_lock:
                outcomes.append(("ok", bundle, res["profile_revision"]))
        except ContractViolationError as exc:
            with outcomes_lock:
                outcomes.append(("conflict", bundle, exc.code))

    t1 = threading.Thread(target=_worker, args=(ov_a, "bundle-a"))
    t2 = threading.Thread(target=_worker, args=(ov_b, "bundle-b"))
    t1.start()
    t2.start()
    t1.join(timeout=15.0)
    t2.join(timeout=15.0)

    assert len(outcomes) == 2
    winners = [item for item in outcomes if item[0] == "ok"]
    losers = [item for item in outcomes if item[0] == "conflict"]
    assert len(winners) == 1
    assert len(losers) == 1
    assert winners[0][2] == "r2"
    assert losers[0][2] == "profile_cas_conflict"

    winning_bundle = winners[0][1]
    losing_bundle = losers[0][1]
    losing_dir = ov_a if losing_bundle == "bundle-a" else ov_b

    loaded_after_race = load_registered_vdp_profiles(vault_root)["concurrent-app"]
    assert loaded_after_race.profile_revision == "r2"
    assert set(loaded_after_race.allowed_overlays.keys()) == {"bundle-base", winning_bundle}

    # Re-running the rejected bundle sequentially against r2 stacks cleanly to r3 with zero lost bundles
    retried = preview_and_register_overlay(
        overlay_dir=losing_dir,
        profile_name="concurrent-app",
        overlay_bundle=losing_bundle,
        vault_root=vault_root,
        docker_bin=str(slow_docker),
        apply=True,
        confirm_apply=True,
    )
    assert retried["profile_revision"] == "r3"
    loaded_final = load_registered_vdp_profiles(vault_root)["concurrent-app"]
    assert set(loaded_final.allowed_overlays.keys()) == {"bundle-base", "bundle-a", "bundle-b"}

    # 2. Direct save_registered_vdp_profile CAS conflict check + multi-profile lock check
    stale_digest = compute_vdp_profile_digest(base_prof)
    with pytest.raises(ContractViolationError) as cas_exc:
        save_registered_vdp_profile(
            vault_root,
            loaded_final.model_copy(update={"profile_revision": "r4"}),
            expected_profile_revision="r1",
            expected_profile_digest=stale_digest,
        )
    assert cas_exc.value.code == "profile_cas_conflict"

    # Concurrent saves to distinct profiles in the same vault must preserve every profile
    p_one = _make_synthetic_profile(
        profile_name="distinct-one",
        bundle_name="b-one",
        overlay_dir=tmp_path / "ov-one",
        test_filename="test_one.py",
        func_name="test_positive_one",
        checkout_dir=checkout_dir,
        commit_sha=commit_sha,
    )
    p_two = _make_synthetic_profile(
        profile_name="distinct-two",
        bundle_name="b-two",
        overlay_dir=tmp_path / "ov-two",
        test_filename="test_two.py",
        func_name="test_positive_two",
        checkout_dir=checkout_dir,
        commit_sha=commit_sha,
    )
    barrier2 = threading.Barrier(2)
    errors: list[BaseException] = []

    def _save_distinct(prof: VdpTargetProfile) -> None:
        barrier2.wait(timeout=5.0)
        try:
            save_registered_vdp_profile(vault_root, prof, expected_profile_revision=None)
        except BaseException as exc:  # pragma: no cover - regression check
            errors.append(exc)

    s1 = threading.Thread(target=_save_distinct, args=(p_one,))
    s2 = threading.Thread(target=_save_distinct, args=(p_two,))
    s1.start()
    s2.start()
    s1.join(timeout=15.0)
    s2.join(timeout=15.0)
    assert errors == []
    all_profiles = load_registered_vdp_profiles(vault_root)
    assert {"concurrent-app", "distinct-one", "distinct-two"}.issubset(all_profiles.keys())
