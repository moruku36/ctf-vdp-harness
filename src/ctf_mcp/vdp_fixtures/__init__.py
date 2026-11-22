"""Local, loopback-only test fixtures for isolated VDP verification."""

from __future__ import annotations

from typing import Any

from ctf_mcp.vdp_fixtures.local_git_http import (
    LocalGitHttpFixture,
    ScenarioStageRecord,
    StageComparisonRecorder,
    emit_vdp_evidence_marker,
    redact_sensitive_text,
    redact_structure,
)

_LAZY_SETTING_DIFF_EXPORTS = frozenset(
    {
        "SETTING_DIFF_SCHEMA",
        "SettingDiffEntry",
        "SettingDiffRecorder",
        "emit_setting_diff_evidence_marker",
    }
)


def __getattr__(name: str) -> Any:
    if name in _LAZY_SETTING_DIFF_EXPORTS:
        from ctf_mcp import vdp_setting_diff

        return getattr(vdp_setting_diff, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "SETTING_DIFF_SCHEMA",
    "LocalGitHttpFixture",
    "ScenarioStageRecord",
    "SettingDiffEntry",
    "SettingDiffRecorder",
    "StageComparisonRecorder",
    "emit_setting_diff_evidence_marker",
    "emit_vdp_evidence_marker",
    "redact_sensitive_text",
    "redact_structure",
]
