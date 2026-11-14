"""Local, loopback-only test fixtures for isolated VDP verification."""

from __future__ import annotations

from ctf_mcp.vdp_fixtures.local_git_http import (
    LocalGitHttpFixture,
    ScenarioStageRecord,
    StageComparisonRecorder,
    emit_vdp_evidence_marker,
    redact_sensitive_text,
    redact_structure,
)

__all__ = [
    "LocalGitHttpFixture",
    "ScenarioStageRecord",
    "StageComparisonRecorder",
    "emit_vdp_evidence_marker",
    "redact_sensitive_text",
    "redact_structure",
]
