"""Self-managed loopback-only Git HTTP fixture for isolated VDP update verification.

Designed for network-isolated (``--network none``) containers and local unit tests.
Uses only Python stdlib + local ``git`` binary bound strictly to ``127.0.0.1``,
and redacts credentials from structured marker emissions.
"""

from __future__ import annotations

import base64
import json
import os
import re
import shutil
import socketserver
import subprocess
import tempfile
import threading
from dataclasses import asdict, dataclass, field
from functools import partial
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote

_SENSITIVE_KEY_RE = re.compile(
    r"(password|secret|token|authorization|cookie|api[_-]?key|private[_-]?key)",
    re.IGNORECASE,
)
_URL_USERINFO_RE = re.compile(r"([a-zA-Z][a-zA-Z0-9+.-]*://)([^/@\s]+@)")
_BEARER_RE = re.compile(r"\b(Bearer|Basic)\s+[A-Za-z0-9+/=._-]{6,}", re.IGNORECASE)


def redact_sensitive_text(text: str) -> str:
    """Scrub URL userinfo credentials and auth header tokens from text."""
    scrubbed = _URL_USERINFO_RE.sub(r"\1***:***@", text)
    return _BEARER_RE.sub(r"\1 [REDACTED]", scrubbed)


def redact_structure(value: Any) -> Any:
    """Recursively redact sensitive keys and credentialed URLs from JSON-like data."""
    if isinstance(value, str):
        return redact_sensitive_text(value)
    if isinstance(value, list):
        return [redact_structure(item) for item in value]
    if isinstance(value, tuple):
        return [redact_structure(item) for item in value]
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            key_str = str(key)
            if _SENSITIVE_KEY_RE.search(key_str):
                redacted[key_str] = "[REDACTED]"
            else:
                redacted[key_str] = redact_structure(item)
        return redacted
    return value


def _find_git_http_backend() -> str | None:
    """Locate ``git-http-backend`` binary if available on this host/container."""
    candidates = [
        "/usr/lib/git-core/git-http-backend",
        "/usr/libexec/git-core/git-http-backend",
    ]
    git_bin = shutil.which("git")
    if git_bin:
        try:
            proc = subprocess.run(
                [git_bin, "--exec-path"],
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                candidates.insert(0, str(Path(proc.stdout.strip()) / "git-http-backend"))
        except OSError:
            pass
    for cand in candidates:
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


class _LocalGitHttpHandler(SimpleHTTPRequestHandler):
    """Serve bare Git repositories strictly from the fixture root with smart/dumb HTTP."""

    server_version = "CtfVdpLocalGitFixture/1.0"

    def __init__(
        self,
        *args: Any,
        directory: str,
        fixture: "LocalGitHttpFixture",
        **kwargs: Any,
    ) -> None:
        self._fixture = fixture
        super().__init__(*args, directory=directory, **kwargs)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        # Keep stdout/stderr clean during pytest capture unless explicitly logged by fixture.
        return

    def _check_basic_auth(self) -> bool:
        creds = self._fixture.basic_auth
        if creds is None:
            return True
        auth_header = self.headers.get("Authorization", "")
        if not auth_header.startswith("Basic "):
            self.send_response(HTTPStatus.UNAUTHORIZED)
            self.send_header("WWW-Authenticate", 'Basic realm="local-git-fixture"')
            self.end_headers()
            return False
        try:
            decoded = base64.b64decode(auth_header[6:].strip()).decode("utf-8")
        except Exception:
            self.send_response(HTTPStatus.UNAUTHORIZED)
            self.end_headers()
            return False
        expected = f"{creds[0]}:{creds[1]}"
        if decoded != expected:
            self.send_response(HTTPStatus.UNAUTHORIZED)
            self.end_headers()
            return False
        return True

    def _try_git_http_backend(self, method: str) -> bool:
        backend = self._fixture.http_backend_path
        if not backend:
            return False
        raw_path, _, query_string = self.path.partition("?")
        clean_path = unquote(raw_path)
        if "/.." in clean_path or "\\" in clean_path:
            self.send_error(HTTPStatus.BAD_REQUEST, "Invalid path")
            return True
        if not (
            clean_path.endswith("/info/refs")
            or clean_path.endswith("/git-upload-pack")
            or clean_path.endswith("/git-receive-pack")
        ):
            return False
        if "service=git-receive-pack" in query_string or clean_path.endswith("/git-receive-pack"):
            self.send_error(HTTPStatus.FORBIDDEN, "Push disabled on local read fixture")
            return True

        content_length = int(self.headers.get("Content-Length") or "0")
        body = self.rfile.read(content_length) if content_length > 0 else b""
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "GIT_PROJECT_ROOT": str(self._fixture.repos_root),
            "GIT_HTTP_EXPORT_ALL": "1",
            "REQUEST_METHOD": method,
            "PATH_INFO": clean_path,
            "QUERY_STRING": query_string,
            "CONTENT_TYPE": self.headers.get("Content-Type", ""),
            "CONTENT_LENGTH": str(len(body)),
            "REMOTE_ADDR": "127.0.0.1",
        }
        proc = subprocess.run(
            [backend],
            input=body,
            capture_output=True,
            env=env,
            timeout=15,
            check=False,
        )
        raw_resp = proc.stdout
        header_sep = b"\r\n\r\n" if b"\r\n\r\n" in raw_resp else b"\n\n"
        header_bytes, _, payload = raw_resp.partition(header_sep)
        status_code = 200
        headers: list[tuple[str, str]] = []
        for line in header_bytes.decode("latin-1", errors="replace").splitlines():
            if ":" not in line:
                continue
            k, v = line.split(":", 1)
            k_low = k.strip().lower()
            v_str = v.strip()
            if k_low == "status":
                try:
                    status_code = int(v_str.split()[0])
                except ValueError:
                    status_code = 200
            else:
                headers.append((k.strip(), v_str))
        self.send_response(status_code)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if method != "HEAD" and payload:
            self.wfile.write(payload)
        return True

    def do_GET(self) -> None:
        if not self._check_basic_auth():
            return
        self._fixture.record_request("GET", self.path)
        if self._try_git_http_backend("GET"):
            return
        super().do_GET()

    def do_HEAD(self) -> None:
        if not self._check_basic_auth():
            return
        self._fixture.record_request("HEAD", self.path)
        if self._try_git_http_backend("HEAD"):
            return
        super().do_HEAD()

    def do_POST(self) -> None:
        if not self._check_basic_auth():
            return
        self._fixture.record_request("POST", self.path)
        if self._try_git_http_backend("POST"):
            return
        self.send_error(HTTPStatus.METHOD_NOT_ALLOWED, "POST not supported on static path")


class _ThreadedLoopbackServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


class LocalGitHttpFixture:
    """Context-managed loopback-only Git bare repo + HTTP server for VDP tests."""

    def __init__(
        self,
        repo_name: str = "demo/repo.git",
        *,
        default_branch: str = "main",
        basic_auth: tuple[str, str] | None = None,
        initial_files: dict[str, str] | None = None,
    ) -> None:
        if ".." in repo_name or repo_name.startswith("/"):
            raise ValueError(f"Unsafe relative repo_name {repo_name!r}.")
        self.repo_name = repo_name.strip("/")
        self.default_branch = default_branch
        self.basic_auth = basic_auth
        self._initial_files = initial_files
        self._tmpdir = Path(tempfile.mkdtemp(prefix="ctf-vdp-localgit-"))
        self.repos_root = self._tmpdir / "www"
        self.bare_dir = self.repos_root / self.repo_name
        self._work_dir = self._tmpdir / "work"
        self.http_backend_path = _find_git_http_backend()
        self._server: _ThreadedLoopbackServer | None = None
        self._thread: threading.Thread | None = None
        self._requests_lock = threading.Lock()
        self.requests: list[tuple[str, str]] = []
        self._git_bin = shutil.which("git") or "git"

    def _isolated_git_env(self) -> dict[str, str]:
        env = {
            k: v
            for k, v in os.environ.items()
            if k
            not in {
                "GIT_DIR",
                "GIT_WORK_TREE",
                "GIT_INDEX_FILE",
                "GIT_CONFIG",
                "GIT_CONFIG_GLOBAL",
                "GIT_CONFIG_SYSTEM",
                "GIT_CONFIG_COUNT",
            }
            and not k.startswith("GIT_CONFIG_KEY_")
            and not k.startswith("GIT_CONFIG_VALUE_")
        }
        env["HOME"] = str(self._tmpdir)
        env["GIT_CONFIG_NOSYSTEM"] = "1"
        env["GIT_TERMINAL_PROMPT"] = "0"
        return env

    def _run_git(self, args: list[str], *, cwd: Path | None = None) -> str:
        proc = subprocess.run(
            [self._git_bin, *args],
            cwd=str(cwd) if cwd is not None else None,
            env=self._isolated_git_env(),
            capture_output=True,
            text=True,
            check=False,
            timeout=20,
        )
        if proc.returncode != 0:
            raise RuntimeError(
                f"git {' '.join(args)} failed (rc={proc.returncode}): "
                f"{proc.stderr.strip() or proc.stdout.strip()}"
            )
        return proc.stdout.strip()

    def init_repo(self, initial_files: dict[str, str] | None = None) -> str:
        """Create bare repo, populate an initial commit, and prepare HTTP server info."""
        if self.bare_dir.exists():
            shutil.rmtree(self.bare_dir)
        if self._work_dir.exists():
            shutil.rmtree(self._work_dir)
        self.bare_dir.parent.mkdir(parents=True, exist_ok=True)
        self._run_git(["init", "--bare", f"--initial-branch={self.default_branch}", str(self.bare_dir)])
        self._run_git(["--git-dir", str(self.bare_dir), "config", "http.receivepack", "false"])
        self._run_git(["--git-dir", str(self.bare_dir), "config", "uploadpack.allowReachableSHA1InWant", "true"])

        self._work_dir.mkdir(parents=True, exist_ok=True)
        self._run_git(["init", f"--initial-branch={self.default_branch}", str(self._work_dir)])
        self._run_git(["config", "user.name", "VDP Fixture Bot"], cwd=self._work_dir)
        self._run_git(["config", "user.email", "fixture@localhost.invalid"], cwd=self._work_dir)

        files = initial_files or {
            "README.md": "Local VDP Git fixture\n",
            "locales/en.po": (
                'msgid ""\n'
                'msgstr ""\n'
                '"Content-Type: text/plain; charset=UTF-8\\n"\n\n'
                'msgid "hello"\n'
                'msgstr "Hello v1"\n'
            ),
        }
        for rel, content in files.items():
            target = self._work_dir / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")

        self._run_git(["add", "."], cwd=self._work_dir)
        self._run_git(["commit", "-m", "Initial fixture commit"], cwd=self._work_dir)
        self._run_git(["remote", "add", "origin", str(self.bare_dir)], cwd=self._work_dir)
        self._run_git(["push", "-u", "origin", self.default_branch], cwd=self._work_dir)
        self._run_git(["--git-dir", str(self.bare_dir), "symbolic-ref", "HEAD", f"refs/heads/{self.default_branch}"])
        self._run_git(["--git-dir", str(self.bare_dir), "update-server-info"])
        return self.head_commit()

    def advance_commit(self, files: dict[str, str], *, message: str = "Update fixture commit") -> str:
        """Push a new commit to the bare repository and refresh HTTP metadata."""
        for rel, content in files.items():
            target = self._work_dir / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        self._run_git(["add", "."], cwd=self._work_dir)
        self._run_git(["commit", "-m", message], cwd=self._work_dir)
        self._run_git(["push", "origin", self.default_branch], cwd=self._work_dir)
        self._run_git(["--git-dir", str(self.bare_dir), "update-server-info"])
        return self.head_commit()

    def head_commit(self) -> str:
        """Return the current SHA-1 HEAD of the bare repository."""
        return self._run_git(
            ["--git-dir", str(self.bare_dir), "rev-parse", f"refs/heads/{self.default_branch}"]
        )

    def start(self) -> str:
        """Start the loopback-only (127.0.0.1) HTTP server and return the clone URL."""
        if not self.bare_dir.exists():
            self.init_repo(self._initial_files)
        handler_cls = partial(_LocalGitHttpHandler, directory=str(self.repos_root), fixture=self)
        self._server = _ThreadedLoopbackServer(("127.0.0.1", 0), handler_cls)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self.clone_url()

    @property
    def host(self) -> str:
        return "127.0.0.1"

    @property
    def port(self) -> int:
        if self._server is None:
            raise RuntimeError("LocalGitHttpFixture server has not been started.")
        return int(self._server.server_address[1])

    def clone_url(self, *, repo_path: str | None = None, include_basic_auth: bool = False) -> str:
        """Return a loopback HTTP clone URL (optionally for an alias/suffix repo path)."""
        rel = (repo_path or self.repo_name).strip("/")
        if include_basic_auth and self.basic_auth is not None:
            user, pwd = self.basic_auth
            return f"http://{user}:{pwd}@127.0.0.1:{self.port}/{rel}"
        return f"http://127.0.0.1:{self.port}/{rel}"

    def record_request(self, method: str, path: str) -> None:
        with self._requests_lock:
            self.requests.append((method, redact_sensitive_text(path)))

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=3.0)
            self._thread = None
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def __enter__(self) -> "LocalGitHttpFixture":
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.stop()


@dataclass
class ScenarioStageRecord:
    """Per-scenario comparison and stage breakdown for VDP test evidence."""

    scenario_id: str
    sender_auth_state: str
    url_kind: str
    submitted_url: str
    config_creation_path: str
    config_accepted: bool
    http_status: int | None
    update_scheduled: bool
    sync_completed: bool
    data_changed: bool
    before_state: dict[str, Any] = field(default_factory=dict)
    after_state: dict[str, Any] = field(default_factory=dict)
    notes: str = ""
    configured_url: str = ""
    payload_url: str = ""
    target_component: str = ""


class StageComparisonRecorder:
    """Collect scenario stage observations and emit redacted VDP evidence markers."""

    def __init__(
        self,
        *,
        sender_auth_state: str = "unauthenticated_webhook_sender",
        config_creation_path: str = "validated_ui_api_clean_repo",
        target_component: str = "synthetic/demo",
    ) -> None:
        self.sender_auth_state = sender_auth_state
        self.config_creation_path = config_creation_path
        self.target_component = target_component
        self.scenarios: list[ScenarioStageRecord] = []
        self.confirmed_conditions: list[str] = []
        self.unverified_conditions: list[str] = []

    def add_scenario(self, record: ScenarioStageRecord) -> None:
        self.scenarios.append(record)

    def to_marker_payload(self) -> dict[str, Any]:
        any_scheduled = any(s.update_scheduled for s in self.scenarios)
        any_synced = any(s.sync_completed for s in self.scenarios)
        any_changed = any(s.data_changed for s in self.scenarios)
        stage_verification = {
            "update_scheduled": any_scheduled if self.scenarios else None,
            "sync_completed": any_synced if self.scenarios else None,
            "data_changed": any_changed if self.scenarios else None,
        }
        payload: dict[str, Any] = {
            "sender_auth_state": self.sender_auth_state,
            "config_creation_path": self.config_creation_path,
            "target_component": self.target_component,
            "stage_verification": stage_verification,
            "scenario_comparisons": [
                {
                    **asdict(s),
                    "submitted_url": redact_sensitive_text(s.submitted_url),
                    "configured_url": redact_sensitive_text(s.configured_url),
                    "payload_url": redact_sensitive_text(s.payload_url),
                    "notes": redact_sensitive_text(s.notes),
                }
                for s in self.scenarios
            ],
            "confirmed_conditions": list(dict.fromkeys(self.confirmed_conditions)),
            "unverified_conditions": list(dict.fromkeys(self.unverified_conditions)),
        }
        return redact_structure(payload)

    def emit(self) -> dict[str, Any]:
        payload = self.to_marker_payload()
        emit_vdp_evidence_marker(payload)
        return payload


def emit_vdp_evidence_marker(payload: dict[str, Any]) -> None:
    """Print a single-line redacted ``VDP_EVIDENCE_MARKER`` JSON record to stdout."""
    clean = redact_structure(payload)
    print(f"VDP_EVIDENCE_MARKER:{json.dumps(clean, ensure_ascii=False, sort_keys=True)}")
