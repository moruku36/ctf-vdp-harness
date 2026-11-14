"""Unit tests for the local loopback-only Git HTTP VDP fixture."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from ctf_mcp.vdp_fixtures import (
    LocalGitHttpFixture,
    ScenarioStageRecord,
    StageComparisonRecorder,
)


def test_local_git_http_fixture_clone_advance_fetch(tmp_path: Path) -> None:
    with LocalGitHttpFixture("org/sample-project.git") as fixture:
        head1 = fixture.head_commit()
        assert fixture.host == "127.0.0.1"
        url = fixture.clone_url()
        assert url.startswith("http://127.0.0.1:")

        clone_dir = tmp_path / "clone"
        proc_clone = subprocess.run(
            ["git", "clone", url, str(clone_dir)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc_clone.returncode == 0, proc_clone.stderr
        assert "Hello v1" in (clone_dir / "locales" / "en.po").read_text(encoding="utf-8")

        head2 = fixture.advance_commit(
            {
                "locales/en.po": (
                    'msgid ""\n'
                    'msgstr ""\n'
                    '"Content-Type: text/plain; charset=UTF-8\\n"\n\n'
                    'msgid "hello"\n'
                    'msgstr "Hello v2"\n'
                )
            },
            message="Second commit",
        )
        assert head2 != head1

        proc_pull = subprocess.run(
            ["git", "pull", "--ff-only"],
            cwd=str(clone_dir),
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc_pull.returncode == 0, proc_pull.stderr
        assert "Hello v2" in (clone_dir / "locales" / "en.po").read_text(encoding="utf-8")
        assert any(method == "GET" for method, _ in fixture.requests)


def test_local_git_http_fixture_reinit_and_initial_files_isolated_env(
    monkeypatch: object,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("GIT_DIR", str(tmp_path / "bogus.git"))  # type: ignore[attr-defined]
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")  # type: ignore[attr-defined]
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "protocol.http.allow")  # type: ignore[attr-defined]
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "never")  # type: ignore[attr-defined]
    with LocalGitHttpFixture(
        "org/reinit.git",
        initial_files={"README.md": "boot-v1\n"},
    ) as fixture:
        v1 = fixture.head_commit()
        v2 = fixture.init_repo({"README.md": "reinit-v2\n"})
        assert v2 != v1
        assert fixture.head_commit() == v2


def test_local_git_http_fixture_basic_auth_and_stage_marker_redaction(
    capsys: object,
) -> None:
    with LocalGitHttpFixture("team/repo.git", basic_auth=("vcsuser", "secret-pass-123")) as fixture:
        unauth_url = fixture.clone_url(include_basic_auth=False)
        auth_url = fixture.clone_url(include_basic_auth=True)
        ls_unauth = subprocess.run(
            ["git", "-c", "credential.helper=", "ls-remote", unauth_url],
            capture_output=True,
            text=True,
            check=False,
            env={"GIT_TERMINAL_PROMPT": "0"},
        )
        assert ls_unauth.returncode != 0

        ls_auth = subprocess.run(
            ["git", "-c", "credential.helper=", "ls-remote", auth_url],
            capture_output=True,
            text=True,
            check=False,
            env={"GIT_TERMINAL_PROMPT": "0"},
        )
        assert ls_auth.returncode == 0

    recorder = StageComparisonRecorder(
        sender_auth_state="unauthenticated_sender",
        config_creation_path="validated_ui_api_clean_repo",
        target_component="team/repo",
    )
    recorder.add_scenario(
        ScenarioStageRecord(
            scenario_id="unauth_ordinary_mismatch",
            sender_auth_state="unauthenticated",
            url_kind="ordinary_non_matching",
            submitted_url="http://vcsuser:secret-pass-123@127.0.0.1:9999/other/repo.git",
            config_creation_path="validated_ui_api_clean_repo",
            config_accepted=True,
            http_status=200,
            update_scheduled=False,
            sync_completed=False,
            data_changed=False,
            before_state={"token": "top-secret-token", "head": "aaa"},
            after_state={"head": "aaa"},
        )
    )
    recorder.add_scenario(
        ScenarioStageRecord(
            scenario_id="unauth_suffix_match",
            sender_auth_state="unauthenticated",
            url_kind="path_suffix_match",
            submitted_url="http://127.0.0.1:9999/team/repo.git",
            config_creation_path="validated_ui_api_clean_repo",
            config_accepted=True,
            http_status=200,
            update_scheduled=True,
            sync_completed=True,
            data_changed=True,
            before_state={"head": "aaa"},
            after_state={"head": "bbb"},
        )
    )
    emitted = recorder.emit()
    captured = capsys.readouterr().out  # type: ignore[attr-defined]
    assert "secret-pass-123" not in captured
    assert "top-secret-token" not in captured
    assert "***:***@" in captured
    assert "[REDACTED]" in captured
    marker_line = [ln for ln in captured.splitlines() if ln.startswith("VDP_EVIDENCE_MARKER:")][0]
    parsed = json.loads(marker_line.split("VDP_EVIDENCE_MARKER:", 1)[1])
    assert parsed == emitted
    assert parsed["stage_verification"] == {
        "update_scheduled": True,
        "sync_completed": True,
        "data_changed": True,
    }
