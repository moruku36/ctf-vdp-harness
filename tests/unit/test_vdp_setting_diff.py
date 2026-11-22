"""Unit tests for test-vs-production setting difference auto-recorder (PR-2A / ACC-F4-01)."""

from __future__ import annotations

import json

import pytest

from ctf_mcp.contracts import ContractViolationError
from ctf_mcp.vdp_setting_diff import (
    MAX_SETTING_DIFF_ENTRIES,
    SETTING_DIFF_SCHEMA,
    SettingDiffEntry,
    SettingDiffRecorder,
)


def test_detect_from_settings_covers_categories_and_redacts_secrets() -> None:
    recorder = SettingDiffRecorder()
    detected = recorder.detect_from_settings(
        {
            "CELERY_TASK_ALWAYS_EAGER": True,
            "repo_url": "https://alice:SYNTHETIC_SECRET_password123@127.0.0.1:8080/org/synth.git",
            "test_ca_bundle": "/tmp/synth-test-ca.pem",
            "private_ip_allowlist": ["127.0.0.1/32", "10.0.0.0/8"],
            "force_login": True,
            "db_engine": "django.db.backends.sqlite3://:memory:?token=Bearer secret_tok_999999",
        },
        env={"REQUESTS_CA_BUNDLE": "/tmp/override.crt"},
        registration_config_diffs=[
            "CELERY_TASK_ALWAYS_EAGER=True vs prod async worker",
            "csrf_disabled=True during bearer token=SYNTHETIC_SECRET_XYZ",
        ],
        stage_verification={"update_scheduled": True, "sync_completed": True, "data_changed": False},
    )
    assert len(detected) >= 6

    payload = recorder.to_marker_payload()
    assert payload["setting_diff_schema"] == SETTING_DIFF_SCHEMA
    unverified = set(payload["unverified_conditions"])
    confirmed = set(payload["confirmed_conditions"])

    assert "celery_eager_test_settings_async_unverified" in unverified
    assert "loopback_fixture_vs_real_vcs_transport_unverified" in unverified
    assert "test_ca_or_private_allowlist_vs_prod_tls_policy_unverified" in unverified
    assert "auth_shortcut_unverified" in unverified
    assert "ephemeral_db_concurrency_unverified" in unverified
    # Stage-aware narrow confirmation does NOT clear remote transport unverified tag
    assert "loopback_git_http_sync_confirmed" in confirmed

    serialized = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    assert "SYNTHETIC_SECRET" not in serialized
    assert "password123" not in serialized
    assert "secret_tok_999999" not in serialized
    assert "alice:" not in serialized
    assert "***:***@" in serialized


def test_real_auth_middleware_without_shortcuts_marks_confirmed() -> None:
    recorder = SettingDiffRecorder()
    recorder.detect_from_settings({"real_auth_middleware_exercised": True, "DEBUG": False})
    payload = recorder.to_marker_payload()
    assert payload["confirmed_conditions"] == ["auth_middleware_parity_confirmed"]
    assert payload["unverified_conditions"] == []


def test_unverified_wins_over_confirmed_and_entry_cap_enforced() -> None:
    recorder = SettingDiffRecorder(max_entries=2)
    recorder.record_diff(
        category="auth_middleware",
        setting_name="middleware_mode",
        test_value="shortcut",
        production_baseline="full",
        condition_tag="auth_shortcut_unverified",
        verification_status="unverified",
    )
    # Attempting to overwrite same key with confirmed keeps unverified
    recorder.record_entry(
        SettingDiffEntry(
            category="auth_middleware",
            setting_name="middleware_mode",
            test_value="shortcut",
            production_baseline="full",
            condition_tag="auth_shortcut_unverified",
            verification_status="confirmed",
        )
    )
    assert recorder.entries[0].verification_status == "unverified"

    recorder.record_diff(
        category="storage_backend",
        setting_name="cache_backend",
        test_value="locmem",
        production_baseline="redis",
        condition_tag="ephemeral_db_concurrency_unverified",
        verification_status="unverified",
    )
    with pytest.raises(ContractViolationError, match="cannot store more"):
        recorder.record_diff(
            category="other",
            setting_name="extra_flag",
            test_value="1",
            production_baseline="0",
            condition_tag="extra_flag_unverified",
            verification_status="unverified",
        )

    # Deterministic sorted emission
    assert json.dumps(recorder.to_marker_payload(), sort_keys=True) == json.dumps(
        recorder.to_marker_payload(), sort_keys=True
    )


def test_rejects_secret_setting_names_and_invalid_condition_tags() -> None:
    assert MAX_SETTING_DIFF_ENTRIES == 32
    with pytest.raises(ContractViolationError):
        SettingDiffEntry(
            category="other",
            setting_name="SYNTHETIC_SECRET_TOKEN",
            test_value="1",
            production_baseline="0",
            condition_tag="valid_tag",
        )
    with pytest.raises(ContractViolationError):
        SettingDiffEntry(
            category="other",
            setting_name="flag_x",
            test_value="1",
            production_baseline="0",
            condition_tag="bad tag with spaces",
        )
