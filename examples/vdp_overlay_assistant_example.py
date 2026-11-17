"""Synthetic example demonstrating Feature 2: VDP overlay registration assistant.

Runs completely offline inside a temporary directory with a synthetic overlay,
temporary vault, and fake Docker inspect stub so no real runtime, targets, or
profiles are ever touched.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

from ctf_mcp.vdp_overlay_assistant import (
    generate_overlay_registration_plan,
    preview_and_register_overlay,
)


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="vdp-overlay-assistant-demo-") as tmp:
        root = Path(tmp)
        vault_root = root / "vault"
        vault_root.mkdir()
        overlay_dir = root / "synthetic-overlay"
        overlay_dir.mkdir()

        (overlay_dir / "test_synthetic_example.py").write_text(
            (
                "class TestSyntheticFeature:\n"
                "    def test_positive_nominal(self):\n"
                "        assert True\n\n"
                "    def test_defense_boundary(self):\n"
                "        assert True\n\n"
                "    def test_custom_probe(self):\n"
                "        assert True\n"
            ),
            encoding="utf-8",
        )

        fake_docker = root / "fake-docker"
        fake_digest = "sha256:" + ("0" * 64)
        fake_docker.write_text(
            f"#!{sys.executable}\nimport sys\nprint({fake_digest!r})\n",
            encoding="utf-8",
        )
        fake_docker.chmod(0o755)

        custom_sel = (
            "/src/vdp-test-overlay/test_synthetic_example.py"
            "::TestSyntheticFeature::test_custom_probe"
        )

        # 1. Generate registration plan only
        plan = generate_overlay_registration_plan(
            overlay_dir=overlay_dir,
            profile_name="synthetic-demo-app",
            overlay_bundle="synthetic-demo-r1",
            vault_root=vault_root,
            role_overrides={custom_sel: "env_check"},
            config_diffs={"max_timeout_seconds": 90, "notes": "synthetic example"},
            image_ref="synthetic-demo:1.0",
            expected_image_digest=fake_digest,
            expected_source_commit="1" * 40,
        )
        print("=== Registration Plan ===")
        print(json.dumps({"can_apply": plan["can_apply"], "selector_roles": plan["selector_roles"]}, indent=2))

        # 2. Combined dry-run preview (default apply=False; does not mutate profiles.json)
        preview = preview_and_register_overlay(
            overlay_dir=overlay_dir,
            profile_name="synthetic-demo-app",
            overlay_bundle="synthetic-demo-r1",
            vault_root=vault_root,
            role_overrides={custom_sel: "env_check"},
            config_diffs={"max_timeout_seconds": 90, "notes": "synthetic example"},
            image_ref="synthetic-demo:1.0",
            expected_image_digest=fake_digest,
            expected_source_commit="1" * 40,
            docker_bin=str(fake_docker),
        )
        print("=== Dry-Run Preview ===")
        print(
            json.dumps(
                {
                    "status": preview["status"],
                    "dry_run": preview["dry_run"],
                    "added_overlays": preview["added_overlays"],
                    "removed_overlays": preview["removed_overlays"],
                    "added_selectors": preview["added_selectors"],
                    "removed_selectors": preview["removed_selectors"],
                    "env_healthy": preview["env_health"]["healthy"],
                    "can_apply": preview["can_apply"],
                },
                indent=2,
            )
        )


if __name__ == "__main__":
    main()
