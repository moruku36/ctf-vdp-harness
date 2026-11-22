"""Synthetic example demonstrating Test-vs-Production Setting Diff auto-recording."""

from __future__ import annotations

import json

from ctf_mcp.vdp_setting_diff import SettingDiffRecorder


def main() -> None:
    recorder = SettingDiffRecorder()
    recorder.detect_from_settings(
        {
            "CELERY_TASK_ALWAYS_EAGER": True,
            "repo_url": "https://user:example-secret@127.0.0.1:8080/synthetic/repo.git",
            "test_ca_bundle": "/tmp/synthetic-ca.pem",
            "private_ip_allowlist": ["127.0.0.1/32"],
            "force_login": True,
            "db_engine": "sqlite:///:memory:",
        },
        stage_verification={"update_scheduled": True, "sync_completed": True, "data_changed": True},
    )
    print(json.dumps(recorder.to_marker_payload(), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
