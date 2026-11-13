"""Scoped HTTP/HTTPS network probe adapter (`net.probe`, CTF-09).

Executes every HTTP request hop inside an isolated stdlib-only child process
via ``SubprocessRunner(shell=False)``, pinning TCP connections strictly to the
pre-validated IP address returned by the injected ``network_guard`` without
child-side DNS lookups and without automatic HTTP redirect following.
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import hashlib
import http.client
import ipaddress
import json
import os
import socket
import ssl
import stat
import sys
import tempfile
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol

MAX_PROBE_BODY_BYTES = 64 * 1024
MAX_PROBE_STDOUT_BYTES = 256 * 1024
MAX_PROBE_REDIRECTS = 5
SCOPED_HTTP_PROBE_ADAPTER_ID = "ctf-scoped-http-probe"
SCOPED_HTTP_PROBE_TOOL_NAME = "net.probe"
SCOPED_HTTP_PROBE_COMMIT = "p4-scoped-http-probe-1"
SCOPED_HTTP_PROBE_OPERATIONS: tuple[str, ...] = ("request", "get", "head")
_FORBIDDEN_HEADER_NAMES: frozenset[str] = frozenset(
    {
        "host",
        "content-length",
        "transfer-encoding",
        "connection",
        "proxy-connection",
        "proxy-authorization",
        "keep-alive",
        "upgrade",
        "te",
        "trailer",
    }
)

SCOPED_HTTP_PROBE_ARG_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["url"],
    "properties": {
        "url": {"type": "string", "minLength": 1, "maxLength": 2048},
        "method": {"type": "string", "enum": ["GET", "HEAD"]},
        "headers": {
            "type": "object",
            "maxProperties": 16,
            "additionalProperties": {"type": "string", "maxLength": 512},
        },
        "follow_redirects": {"type": "boolean"},
        "max_redirects": {"type": "integer", "minimum": 0, "maximum": MAX_PROBE_REDIRECTS},
        "max_bytes": {"type": "integer", "minimum": 1, "maximum": MAX_PROBE_BODY_BYTES},
    },
    "additionalProperties": False,
}


def _configure_stdio_utf8() -> None:
    """Force UTF-8 encoding on worker stdio streams (critical on Windows)."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass


def _read_regular_non_symlink(path: Path, *, max_bytes: int) -> bytes:
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise ValueError("hop config path is not a regular non-symlink file")
    with open(path, "rb") as handle:
        fst = os.fstat(handle.fileno())
        if fst.st_ino != st.st_ino or fst.st_dev != st.st_dev:
            raise ValueError("hop config changed concurrently during open")
        data = handle.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError("hop config exceeds size limit")
    return data


def _validate_pinned_ip_in_worker(raw_ip: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    ip_obj = ipaddress.ip_address(raw_ip)
    if ip_obj.is_multicast or ip_obj.is_unspecified:
        raise ValueError(f"forbidden pinned target IP {raw_ip!r}")
    if isinstance(ip_obj, ipaddress.IPv6Address):
        if ip_obj.ipv4_mapped is not None or ip_obj.sixtofour is not None or ip_obj.teredo is not None:
            raise ValueError(f"forbidden mapped/tunneled IPv6 address {raw_ip!r}")
    return ip_obj


class _PinnedHttpConnection(http.client.HTTPConnection):
    """HTTPConnection connecting directly to a pre-resolved IP without DNS."""

    def __init__(self, pinned_ip: str, port: int, *, timeout: float) -> None:
        super().__init__(pinned_ip, port=port, timeout=timeout)
        self._pinned_ip_obj = _validate_pinned_ip_in_worker(pinned_ip)

    def connect(self) -> None:
        family = socket.AF_INET6 if self._pinned_ip_obj.version == 6 else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        addr: tuple[Any, ...]
        if self._pinned_ip_obj.version == 6:
            addr = (str(self._pinned_ip_obj), self.port, 0, 0)
        else:
            addr = (str(self._pinned_ip_obj), self.port)
        try:
            sock.connect(addr)
        except Exception:
            sock.close()
            raise
        self.sock = sock


class _PinnedHttpsConnection(http.client.HTTPSConnection):
    """HTTPSConnection connecting directly to a pinned IP with proper SNI."""

    def __init__(
        self,
        pinned_ip: str,
        port: int,
        *,
        server_hostname: str,
        timeout: float,
        context: ssl.SSLContext,
    ) -> None:
        super().__init__(pinned_ip, port=port, timeout=timeout, context=context)
        self._pinned_ip_obj = _validate_pinned_ip_in_worker(pinned_ip)
        self._sni_hostname = server_hostname

    def connect(self) -> None:
        family = socket.AF_INET6 if self._pinned_ip_obj.version == 6 else socket.AF_INET
        raw_sock = socket.socket(family, socket.SOCK_STREAM)
        raw_sock.settimeout(self.timeout)
        addr: tuple[Any, ...]
        if self._pinned_ip_obj.version == 6:
            addr = (str(self._pinned_ip_obj), self.port, 0, 0)
        else:
            addr = (str(self._pinned_ip_obj), self.port)
        try:
            raw_sock.connect(addr)
            self.sock = self._context.wrap_socket(raw_sock, server_hostname=self._sni_hostname)
        except Exception:
            raw_sock.close()
            raise


def _execute_single_pinned_hop(hop: dict[str, Any]) -> dict[str, Any]:
    """Perform exactly one non-redirecting HTTP/HTTPS request to ``pinned_ip``."""
    scheme = str(hop["scheme"]).lower()
    pinned_ip = str(hop["pinned_ip"])
    port = int(hop["port"])
    host_header = str(hop["host_header"])
    server_hostname = str(hop["server_hostname"])
    request_target = str(hop["request_target"])
    method = str(hop["method"]).upper()
    max_bytes = max(1, min(int(hop.get("max_bytes", MAX_PROBE_BODY_BYTES)), MAX_PROBE_BODY_BYTES))
    timeout = max(0.5, min(float(hop.get("timeout_seconds", 15.0)), 60.0))
    headers = dict(hop.get("headers", {}))

    if scheme not in {"http", "https"}:
        raise ValueError(f"unsupported scheme {scheme!r}")
    if method not in {"GET", "HEAD"}:
        raise ValueError(f"unsupported HTTP method {method!r}")

    conn: http.client.HTTPConnection
    if scheme == "https":
        ssl_ctx = ssl.create_default_context()
        conn = _PinnedHttpsConnection(
            pinned_ip,
            port,
            server_hostname=server_hostname,
            timeout=timeout,
            context=ssl_ctx,
        )
    else:
        conn = _PinnedHttpConnection(pinned_ip, port, timeout=timeout)

    try:
        conn.putrequest(method, request_target, skip_host=True, skip_accept_encoding=False)
        conn.putheader("Host", host_header)
        conn.putheader("Connection", "close")
        for hdr_name, hdr_val in headers.items():
            conn.putheader(str(hdr_name), str(hdr_val))
        conn.endheaders()

        resp = conn.getresponse()
        raw_headers = [(k, v) for k, v in resp.getheaders()]
        location = resp.getheader("Location")

        body_chunks: list[bytes] = []
        total_read = 0
        truncated = False
        while total_read < max_bytes + 1:
            chunk = resp.read(min(8192, (max_bytes + 1) - total_read))
            if not chunk:
                break
            body_chunks.append(chunk)
            total_read += len(chunk)

        body = b"".join(body_chunks)
        if len(body) > max_bytes:
            body = body[:max_bytes]
            truncated = True

        try:
            body_text = body.decode("utf-8", errors="strict")
            body_encoding = "utf-8"
            encoded_body = body_text
        except UnicodeDecodeError:
            body_encoding = "base64"
            encoded_body = base64.b64encode(body).decode("ascii")

        return {
            "ok": True,
            "status_code": int(resp.status),
            "reason": str(resp.reason or ""),
            "location": location,
            "headers": raw_headers,
            "body_bytes": len(body),
            "body_truncated": truncated,
            "body_encoding": body_encoding,
            "body": encoded_body,
        }
    finally:
        conn.close()


def _worker_main(argv: list[str] | None = None) -> int:
    """Entrypoint for the isolated pinned-IP HTTP probe worker process."""
    _configure_stdio_utf8()
    parser = argparse.ArgumentParser(description="Pinned-IP scoped HTTP probe worker")
    parser.add_argument("--hop-file", required=True)
    args = parser.parse_args(argv)

    try:
        hop_bytes = _read_regular_non_symlink(Path(args.hop_file), max_bytes=64 * 1024)
        hop = json.loads(hop_bytes.decode("utf-8"))
        if not isinstance(hop, dict):
            raise ValueError("hop config must be a JSON object")
        result = _execute_single_pinned_hop(hop)
        sys.stdout.write(json.dumps(result, ensure_ascii=False))
        sys.stdout.flush()
        return 0
    except Exception as exc:
        err = {"ok": False, "error_code": "network_probe_error", "message": str(exc)}
        sys.stderr.write(json.dumps(err, ensure_ascii=False))
        sys.stderr.flush()
        return 1


if __name__ != "__main__":
    from ctf_mcp.adapters.base import (
        AdapterExecutionOutcome,
        BaseAdapter,
        build_signed_descriptor,
        validate_action_request_inputs,
    )
    from ctf_mcp.adapters.runner import SubprocessOutcome, SubprocessResult, SubprocessRunner
    from ctf_mcp.contracts import (
        ActionRecord,
        CapabilityDescriptor,
        CapabilityLimits,
        ContractViolationError,
        EnvelopeStatus,
        ErrorDetail,
        EvidenceVaultPort,
        ExecutionClass,
        ProvenanceInfo,
        ResultEnvelope,
        RunMode,
        ScopeDeniedError,
        ScopePolicy,
        UsageMetrics,
    )

    _SCRIPT_PATH = Path(__file__).resolve()

    class PinnedTargetProtocol(Protocol):
        """Structural contract matching Layer-2 ``PinnedNetworkTarget`` without importing gateway."""

        @property
        def url(self) -> str: ...
        @property
        def scheme(self) -> str: ...
        @property
        def host(self) -> str: ...
        @property
        def port(self) -> int: ...
        @property
        def pinned_ip(self) -> str: ...
        @property
        def ip_version(self) -> int: ...
        @property
        def host_header(self) -> str: ...
        @property
        def server_hostname(self) -> str: ...
        @property
        def request_target(self) -> str: ...
        @property
        def method(self) -> str: ...
        @property
        def scope_revision(self) -> str: ...

    class NetworkGuardProtocol(Protocol):
        """Structural contract matching ``ScopedNetworkPolicyGuard`` without Layer-2 cross-import."""

        def resolve_live_policy(
            self,
            *,
            policy: ScopePolicy | None = None,
            run_id: str | None = None,
        ) -> ScopePolicy: ...

        def validate_and_resolve(
            self,
            url: str,
            *,
            method: str = "GET",
            policy: ScopePolicy | None = None,
            run_id: str | None = None,
        ) -> PinnedTargetProtocol: ...

        def validate_redirect_hop(
            self,
            current_url: str,
            location: str,
            *,
            hop_index: int,
            original_method: str,
            status_code: int,
            policy: ScopePolicy | None = None,
            run_id: str | None = None,
            max_redirects: int | None = None,
        ) -> PinnedTargetProtocol: ...

    def get_dependency_lock_sha256() -> str:
        """Compute SHA-256 of repository pyproject.toml for descriptor pinning."""
        repo_root = Path(__file__).resolve().parents[3]
        lock_file = repo_root / "pyproject.toml"
        if lock_file.is_file():
            return hashlib.sha256(lock_file.read_bytes()).hexdigest()
        return hashlib.sha256(b"ctf-vdp-harness-stdlib-only").hexdigest()

    def create_scoped_http_probe_descriptor(
        *,
        name: str = SCOPED_HTTP_PROBE_TOOL_NAME,
        enabled: bool = True,
        adapter_commit: str = SCOPED_HTTP_PROBE_COMMIT,
        profile_modes: tuple[RunMode, ...] = (RunMode.SCOPED_CTF, RunMode.VDP),
        limits: CapabilityLimits | None = None,
    ) -> CapabilityDescriptor:
        """Build the signed capability descriptor for ``net.probe``."""
        return build_signed_descriptor(
            name=name,
            adapter_id=SCOPED_HTTP_PROBE_ADAPTER_ID,
            adapter_commit=adapter_commit,
            dependency_lock_sha256=get_dependency_lock_sha256(),
            operations=SCOPED_HTTP_PROBE_OPERATIONS,
            arg_schema=SCOPED_HTTP_PROBE_ARG_SCHEMA,
            execution_classes=(ExecutionClass.NETWORK,),
            required_scope={
                "modes": [mode.value for mode in profile_modes],
                "network_enabled": True,
            },
            limits=limits
            or CapabilityLimits(
                timeout_seconds=30,
                max_output_bytes=MAX_PROBE_STDOUT_BYTES,
                max_decode_bytes=MAX_PROBE_BODY_BYTES,
            ),
            enabled=enabled,
            profile_modes=profile_modes,
        )

    def _validate_client_headers(raw_headers: Any) -> dict[str, str]:
        if raw_headers is None:
            return {}
        if not isinstance(raw_headers, dict):
            raise ContractViolationError("headers must be a mapping", code="invalid_headers")
        clean: dict[str, str] = {}
        for k, v in raw_headers.items():
            if not isinstance(k, str) or not isinstance(v, str):
                raise ContractViolationError("header names and values must be strings", code="invalid_headers")
            if any(c in k or c in v for c in ("\r", "\n", "\x00")):
                raise ContractViolationError("header contains forbidden CRLF or NUL", code="header_injection")
            if not k.strip() or any(ord(ch) <= 0x20 or ord(ch) >= 0x7F or ch == ":" for ch in k):
                raise ContractViolationError(f"invalid header name {k!r}", code="invalid_headers")
            if k.strip().lower() in _FORBIDDEN_HEADER_NAMES:
                raise ScopeDeniedError(
                    f"Setting restricted HTTP header {k!r} is forbidden",
                    code="forbidden_header",
                )
            clean[k.strip()] = v
        return clean

    @dataclasses.dataclass
    class _HopDispatchState:
        action: ActionRecord
        initial_target: PinnedTargetProtocol | None
        url: str
        method: str
        headers: dict[str, str]
        follow_redirects: bool
        max_redirects: int
        max_bytes: int
        policy: ScopePolicy | None
        denied_error: ScopeDeniedError | None = None
        last_sub_res: SubprocessResult | None = None
        total_wall_ms: int = 0
        total_cpu_ms: int = 0
        max_rss_bytes: int = 0

    class _ProbeRunnerDelegate:
        """Runner wrapper allowing ``BaseAdapter`` to run hop-by-hop via ``SubprocessRunner``."""

        def __init__(self, adapter: ScopedHttpProbeAdapter, real_runner: SubprocessRunner) -> None:
            self._adapter = adapter
            self._real_runner = real_runner

        def run(
            self,
            argv: list[str],
            *,
            timeout_seconds: int | None = None,
            max_output_bytes: int | None = None,
            extra_env: dict[str, str] | None = None,
            cwd: str | Path | None = None,
            cancel_event: threading.Event | None = None,
            on_output_chunk: Any = None,
        ) -> SubprocessResult:
            if len(argv) == 2 and argv[0] == "__hop_dispatch__":
                return self._adapter._execute_hop_loop(
                    action_id=argv[1],
                    timeout_seconds=timeout_seconds,
                    max_output_bytes=max_output_bytes,
                    cancel_event=cancel_event,
                )
            return self._real_runner.run(
                argv,
                timeout_seconds=timeout_seconds,
                max_output_bytes=max_output_bytes,
                extra_env=extra_env,
                cwd=cwd,
                cancel_event=cancel_event,
                on_output_chunk=on_output_chunk,
            )

        def __getattr__(self, name: str) -> Any:
            return getattr(self._real_runner, name)

    class ScopedHttpProbeAdapter(BaseAdapter):
        """Scoped HTTP/HTTPS network probe adapter (`net.probe`, CTF-09)."""

        def __init__(
            self,
            descriptor: CapabilityDescriptor | None = None,
            *,
            runner: SubprocessRunner | None = None,
            evidence_vault: EvidenceVaultPort | None = None,
            network_guard: NetworkGuardProtocol | None = None,
            policy_provider: Callable[[str], ScopePolicy | None] | None = None,
            worker_script: Path | None = None,
        ) -> None:
            resolved = descriptor or create_scoped_http_probe_descriptor()
            self._real_runner = runner or SubprocessRunner()
            delegate = _ProbeRunnerDelegate(self, self._real_runner)
            super().__init__(resolved, runner=delegate, evidence_vault=evidence_vault)  # type: ignore[arg-type]
            self._network_guard = network_guard
            self._policy_provider = policy_provider
            self._worker_script = (worker_script or _SCRIPT_PATH).resolve()
            self._lock = threading.Lock()
            self._pre_pinned: dict[str, tuple[PinnedTargetProtocol, ScopePolicy | None]] = {}
            self._active_states: dict[str, _HopDispatchState] = {}

        def attach_network_guard(
            self,
            network_guard: NetworkGuardProtocol,
            *,
            policy_provider: Callable[[str], ScopePolicy | None] | None = None,
            override_existing_guard: bool = False,
        ) -> None:
            """Attach controller guard/policy provider without overriding custom test guards."""
            if self._network_guard is None or override_existing_guard:
                self._network_guard = network_guard
            if policy_provider is not None and self._policy_provider is None:
                self._policy_provider = policy_provider

        @staticmethod
        def _resolve_method(operation: str, arguments: dict[str, Any]) -> str:
            explicit = arguments.get("method")
            if operation == "get":
                if explicit is not None and str(explicit).upper() != "GET":
                    raise ContractViolationError(
                        "Operation 'get' conflicts with non-GET method argument",
                        code="invalid_probe_method",
                    )
                return "GET"
            if operation == "head":
                if explicit is not None and str(explicit).upper() != "HEAD":
                    raise ContractViolationError(
                        "Operation 'head' conflicts with non-HEAD method argument",
                        code="invalid_probe_method",
                    )
                return "HEAD"
            return str(explicit or "GET").upper()

        def preflight_request(
            self,
            *,
            run_id: str,
            operation: str,
            arguments: dict[str, Any],
            policy: ScopePolicy,
        ) -> PinnedTargetProtocol:
            """Validate initial URL + DNS before TX1 budget reservation/launch."""
            if self._network_guard is None:
                raise ScopeDeniedError(
                    "ScopedHttpProbeAdapter requires an attached network_guard",
                    code="network_guard_missing",
                )
            desc = self._descriptor
            if operation not in desc.operations:
                raise ContractViolationError(
                    f"Operation {operation!r} is not permitted for capability {desc.name!r}.",
                    code="capability_denied",
                )
            if not isinstance(arguments, dict) or not isinstance(arguments.get("url"), str):
                raise ContractViolationError(
                    "net.probe requires mapping arguments containing a string 'url'.",
                    code="invalid_arguments",
                )
            _validate_client_headers(arguments.get("headers"))
            method = self._resolve_method(operation, arguments)
            url = str(arguments["url"])
            return self._network_guard.validate_and_resolve(
                url,
                method=method,
                policy=policy,
                run_id=run_id,
            )

        def bind_preflight_target(
            self,
            action_id: str,
            pinned_target: PinnedTargetProtocol,
            policy: ScopePolicy,
        ) -> None:
            """Attach a TX1 preflight-resolved Hop 0 target to ``action_id``."""
            with self._lock:
                self._pre_pinned[action_id] = (pinned_target, policy)

        def preflight_network_target(
            self,
            action: ActionRecord,
            *,
            policy: ScopePolicy,
        ) -> PinnedTargetProtocol:
            """Validate initial URL + DNS once pre-launch so hop 0 is not resolved twice."""
            pinned = self.preflight_request(
                run_id=action.run_id,
                operation=action.operation,
                arguments=action.sanitized_args,
                policy=policy,
            )
            self.bind_preflight_target(action.action_id, pinned, policy)
            return pinned

        def clear_preflight(self, action_id: str) -> None:
            """Discard any pre-pinned hop target if execution was aborted before launch."""
            with self._lock:
                self._pre_pinned.pop(action_id, None)

        def _get_current_policy(
            self,
            run_id: str,
            fallback_policy: ScopePolicy | None,
        ) -> ScopePolicy:
            if self._policy_provider is not None:
                live = self._policy_provider(run_id)
                if live is not None:
                    return live
            if self._network_guard is not None:
                return self._network_guard.resolve_live_policy(
                    policy=fallback_policy,
                    run_id=run_id,
                )
            if fallback_policy is not None:
                return fallback_policy
            raise ScopeDeniedError("Missing ScopePolicy for net.probe", code="scope_missing")

        def execute_with_capture(
            self,
            action: ActionRecord,
            *,
            artifact_paths: dict[str, Path] | None = None,
            cancel_event: threading.Event | None = None,
            policy: ScopePolicy | None = None,
        ) -> AdapterExecutionOutcome:
            if self._network_guard is None:
                raise ScopeDeniedError(
                    "ScopedHttpProbeAdapter requires an attached network_guard",
                    code="network_guard_missing",
                )
            validate_action_request_inputs(self._descriptor, action)
            args = dict(action.sanitized_args)
            method = self._resolve_method(action.operation, args)
            headers = _validate_client_headers(args.get("headers"))

            with self._lock:
                pre_entry = self._pre_pinned.pop(action.action_id, None)
            initial_target: PinnedTargetProtocol | None = None
            resolved_policy = policy
            if pre_entry is not None:
                initial_target, pre_policy = pre_entry
                if resolved_policy is None:
                    resolved_policy = pre_policy

            state = _HopDispatchState(
                action=action,
                initial_target=initial_target,
                url=str(args["url"]),
                method=method,
                headers=headers,
                follow_redirects=bool(args.get("follow_redirects", True)),
                max_redirects=int(args.get("max_redirects", MAX_PROBE_REDIRECTS)),
                max_bytes=int(args.get("max_bytes", 32_768)),
                policy=resolved_policy,
            )
            with self._lock:
                self._active_states[action.action_id] = state

            try:
                return super().execute_with_capture(
                    action,
                    artifact_paths=artifact_paths,
                    cancel_event=cancel_event,
                )
            except ScopeDeniedError as exc:
                scope_rev = action.scope_revision
                if state.initial_target is not None:
                    scope_rev = state.initial_target.scope_revision
                fallback_sub = state.last_sub_res or SubprocessResult(
                    outcome=SubprocessOutcome.FAILED,
                    returncode=None,
                    stdout=b"",
                    stderr=b"",
                    wall_ms=max(0, state.total_wall_ms),
                    output_bytes=0,
                    bytes_observed=0,
                    capture_complete=True,
                    cleanup_confirmed=True,
                )
                usage = UsageMetrics(
                    wall_ms=max(0, state.total_wall_ms),
                    output_bytes=0,
                    peak_rss_bytes=state.max_rss_bytes if state.max_rss_bytes > 0 else None,
                    cpu_ms=state.total_cpu_ms if state.total_cpu_ms > 0 else None,
                )
                envelope = ResultEnvelope(
                    run_id=action.run_id,
                    action_id=action.action_id,
                    status=EnvelopeStatus.DENIED,
                    summary=(
                        f"net.probe denied ({exc.code or 'scope_denied'}): {str(exc)[:180]}"
                    ),
                    evidence=(),
                    truncated=False,
                    next_cursor=None,
                    error=ErrorDetail(
                        code=exc.code or "scope_denied",
                        message=str(exc),
                        retryable=False,
                    ),
                    usage=usage,
                    provenance=ProvenanceInfo(
                        adapter_revision=self._descriptor.adapter_commit,
                        scope_revision=scope_rev,
                    ),
                )
                return AdapterExecutionOutcome(
                    envelope=envelope,
                    subprocess_result=fallback_sub,
                    captured_bytes=b"",
                    capture_complete=True,
                    cleanup_confirmed=bool(fallback_sub.cleanup_confirmed),
                )
            finally:
                with self._lock:
                    self._active_states.pop(action.action_id, None)

        def _build_invocation(
            self,
            action: ActionRecord,
            *,
            artifact_paths: dict[str, Path],
        ) -> tuple[list[str], dict[str, str] | None, Path | None]:
            return ["__hop_dispatch__", action.action_id], None, None

        def _execute_hop_loop(
            self,
            *,
            action_id: str,
            timeout_seconds: int | None,
            max_output_bytes: int | None,
            cancel_event: threading.Event | None,
        ) -> SubprocessResult:
            with self._lock:
                state = self._active_states[action_id]
            assert self._network_guard is not None

            budget_timeout = float(
                timeout_seconds
                if timeout_seconds is not None
                else self._descriptor.limits.timeout_seconds
            )
            deadline = time.monotonic() + max(1.0, budget_timeout)
            capture_cap = int(
                max_output_bytes
                if max_output_bytes is not None
                else self._descriptor.limits.max_output_bytes
            )

            hops_trace: list[dict[str, Any]] = []
            current_target = state.initial_target
            all_cleanup_confirmed = True
            final_hop_payload: dict[str, Any] | None = None

            for hop_idx in range(state.max_redirects + 1):
                if cancel_event is not None and cancel_event.is_set():
                    if state.last_sub_res is not None:
                        return state.last_sub_res.model_copy(
                            update={
                                "outcome": SubprocessOutcome.CANCELLED,
                                "wall_ms": state.total_wall_ms,
                                "cpu_ms": (
                                    state.total_cpu_ms
                                    if state.total_cpu_ms > 0
                                    else state.last_sub_res.cpu_ms
                                ),
                                "peak_rss_bytes": (
                                    state.max_rss_bytes
                                    if state.max_rss_bytes > 0
                                    else state.last_sub_res.peak_rss_bytes
                                ),
                                "cleanup_confirmed": all_cleanup_confirmed,
                            }
                        )
                    return SubprocessResult(
                        outcome=SubprocessOutcome.CANCELLED,
                        returncode=None,
                        stdout=b"",
                        stderr=b"",
                        wall_ms=state.total_wall_ms,
                        output_bytes=0,
                        bytes_observed=0,
                        capture_complete=True,
                        cleanup_confirmed=True,
                    )

                if current_target is None:
                    live_policy = self._get_current_policy(state.action.run_id, state.policy)
                    current_target = self._network_guard.validate_and_resolve(
                        state.url,
                        method=state.method,
                        policy=live_policy,
                        run_id=state.action.run_id,
                    )
                    if state.initial_target is None:
                        state.initial_target = current_target
                elif hop_idx == 0 and self._policy_provider is not None:
                    # Re-check live policy even on pre-pinned hop 0 in case of concurrent revoke.
                    live_policy = self._get_current_policy(state.action.run_id, state.policy)
                    if getattr(live_policy, "revoked_at", None) is not None:
                        raise ScopeDeniedError(
                            "Run scope has been revoked",
                            code="scope_revoked",
                            details={"scope_revision": live_policy.scope_revision},
                        )

                remaining_sec = deadline - time.monotonic()
                if remaining_sec <= 0:
                    if state.last_sub_res is not None:
                        return state.last_sub_res.model_copy(
                            update={
                                "outcome": SubprocessOutcome.TIMEOUT,
                                "wall_ms": state.total_wall_ms,
                                "cpu_ms": (
                                    state.total_cpu_ms
                                    if state.total_cpu_ms > 0
                                    else state.last_sub_res.cpu_ms
                                ),
                                "peak_rss_bytes": (
                                    state.max_rss_bytes
                                    if state.max_rss_bytes > 0
                                    else state.last_sub_res.peak_rss_bytes
                                ),
                                "cleanup_confirmed": all_cleanup_confirmed,
                            }
                        )
                    remaining_sec = 0.2

                hop_config = {
                    "scheme": current_target.scheme,
                    "pinned_ip": current_target.pinned_ip,
                    "port": current_target.port,
                    "host_header": current_target.host_header,
                    "server_hostname": current_target.server_hostname,
                    "request_target": current_target.request_target,
                    "method": current_target.method,
                    "headers": state.headers,
                    "max_bytes": state.max_bytes,
                    "timeout_seconds": max(0.5, min(remaining_sec, budget_timeout)),
                }

                with tempfile.TemporaryDirectory(prefix="ctf-net-hop-") as tmp_dir:
                    hop_file = Path(tmp_dir) / "hop.json"
                    hop_file.write_text(json.dumps(hop_config, ensure_ascii=False), encoding="utf-8")
                    sub_res = self._real_runner.run(
                        [sys.executable, str(self._worker_script), "--hop-file", str(hop_file)],
                        timeout_seconds=max(1, int(remaining_sec + 0.999)),
                        max_output_bytes=capture_cap,
                        cancel_event=cancel_event,
                    )

                state.last_sub_res = sub_res
                state.total_wall_ms += max(0, int(sub_res.wall_ms))
                if sub_res.cpu_ms is not None:
                    state.total_cpu_ms += max(0, int(sub_res.cpu_ms))
                if sub_res.peak_rss_bytes is not None:
                    state.max_rss_bytes = max(state.max_rss_bytes, int(sub_res.peak_rss_bytes))
                all_cleanup_confirmed = all_cleanup_confirmed and bool(sub_res.cleanup_confirmed)

                if (
                    sub_res.outcome != SubprocessOutcome.COMPLETED
                    or sub_res.returncode != 0
                    or not sub_res.cleanup_confirmed
                ):
                    return sub_res.model_copy(
                        update={
                            "wall_ms": state.total_wall_ms,
                            "cpu_ms": (
                                state.total_cpu_ms
                                if state.total_cpu_ms > 0
                                else sub_res.cpu_ms
                            ),
                            "peak_rss_bytes": (
                                state.max_rss_bytes
                                if state.max_rss_bytes > 0
                                else sub_res.peak_rss_bytes
                            ),
                            "cleanup_confirmed": all_cleanup_confirmed,
                        }
                    )

                hop_out = json.loads(sub_res.stdout.decode("utf-8", errors="strict"))
                status_code = int(hop_out["status_code"])
                hops_trace.append(
                    {
                        "hop": hop_idx,
                        "url": current_target.url,
                        "method": current_target.method,
                        "pinned_ip": current_target.pinned_ip,
                        "host_header": current_target.host_header,
                        "status_code": status_code,
                    }
                )
                final_hop_payload = hop_out

                if state.follow_redirects and status_code in {301, 302, 303, 307, 308}:
                    location = hop_out.get("location")
                    if not isinstance(location, str) or not location.strip():
                        err = json.dumps(
                            {
                                "ok": False,
                                "error_code": "invalid_redirect",
                                "message": f"HTTP {status_code} redirect missing Location header",
                            }
                        ).encode("utf-8")
                        return sub_res.model_copy(
                            update={
                                "outcome": SubprocessOutcome.FAILED,
                                "returncode": 1,
                                "stdout": b"",
                                "stderr": err,
                                "output_bytes": len(err),
                                "bytes_observed": max(sub_res.bytes_observed, len(err)),
                                "wall_ms": state.total_wall_ms,
                                "cpu_ms": (
                                    state.total_cpu_ms
                                    if state.total_cpu_ms > 0
                                    else sub_res.cpu_ms
                                ),
                                "peak_rss_bytes": (
                                    state.max_rss_bytes
                                    if state.max_rss_bytes > 0
                                    else sub_res.peak_rss_bytes
                                ),
                                "cleanup_confirmed": all_cleanup_confirmed,
                            }
                        )
                    live_policy = self._get_current_policy(state.action.run_id, state.policy)
                    current_target = self._network_guard.validate_redirect_hop(
                        current_target.url,
                        location,
                        hop_index=hop_idx + 1,
                        original_method=current_target.method,
                        status_code=status_code,
                        policy=live_policy,
                        run_id=state.action.run_id,
                        max_redirects=state.max_redirects,
                    )
                    continue
                break

            # Final live-policy check before finalizing HTTP response evidence.
            if self._policy_provider is not None:
                live_policy = self._get_current_policy(state.action.run_id, state.policy)
                if getattr(live_policy, "revoked_at", None) is not None:
                    raise ScopeDeniedError(
                        "Run scope was revoked during network probe",
                        code="scope_revoked",
                        details={"scope_revision": live_policy.scope_revision},
                    )

            assert state.last_sub_res is not None
            assert final_hop_payload is not None
            assert current_target is not None

            combined = {
                "ok": True,
                "initial_url": state.url,
                "final_url": current_target.url,
                "method": current_target.method,
                "pinned_ip": current_target.pinned_ip,
                "ip_version": current_target.ip_version,
                "status_code": int(final_hop_payload["status_code"]),
                "reason": str(final_hop_payload.get("reason", "")),
                "hops": hops_trace,
                "headers": final_hop_payload.get("headers", []),
                "body_bytes": int(final_hop_payload.get("body_bytes", 0)),
                "body_truncated": bool(final_hop_payload.get("body_truncated", False)),
                "body_encoding": str(final_hop_payload.get("body_encoding", "utf-8")),
                "body": str(final_hop_payload.get("body", "")),
            }
            encoded = json.dumps(combined, ensure_ascii=False).encode("utf-8")
            truncated_output = bool(final_hop_payload.get("body_truncated", False))
            if len(encoded) > capture_cap:
                excess = len(encoded) - capture_cap + 64
                body_str = str(combined["body"])
                if len(body_str) > excess:
                    combined["body"] = body_str[:-excess]
                else:
                    combined["body"] = ""
                combined["body_truncated"] = True
                truncated_output = True
                encoded = json.dumps(combined, ensure_ascii=False).encode("utf-8")
                if len(encoded) > capture_cap:
                    combined["body"] = ""
                    combined["headers"] = []
                    encoded = json.dumps(combined, ensure_ascii=False).encode("utf-8")[:capture_cap]

            return state.last_sub_res.model_copy(
                update={
                    "stdout": encoded,
                    "stderr": b"",
                    "output_bytes": len(encoded),
                    "bytes_observed": max(state.last_sub_res.bytes_observed, len(encoded)),
                    "capture_complete": bool(
                        state.last_sub_res.capture_complete and not truncated_output
                    ),
                    "omission_reason": (
                        "response_body_truncated" if truncated_output else state.last_sub_res.omission_reason
                    ),
                    "wall_ms": state.total_wall_ms,
                    "cpu_ms": (
                        state.total_cpu_ms
                        if state.total_cpu_ms > 0
                        else state.last_sub_res.cpu_ms
                    ),
                    "peak_rss_bytes": (
                        state.max_rss_bytes
                        if state.max_rss_bytes > 0
                        else state.last_sub_res.peak_rss_bytes
                    ),
                    "cleanup_confirmed": all_cleanup_confirmed,
                }
            )

        def _summarize_result(self, action: ActionRecord, sub_res: Any) -> str:
            if sub_res.outcome != SubprocessOutcome.COMPLETED or sub_res.returncode != 0:
                err_text = sub_res.stderr.decode("utf-8", errors="replace").strip()
                try:
                    err_obj = json.loads(err_text)
                    return (
                        f"net.probe {action.operation} failed: "
                        f"{err_obj.get('message', err_text)[:180]}"
                    )
                except Exception:
                    return (
                        f"net.probe {action.operation} failed "
                        f"(outcome={getattr(sub_res.outcome, 'value', sub_res.outcome)}, "
                        f"returncode={sub_res.returncode}): {err_text[:180]}"
                    )
            try:
                parsed = json.loads(sub_res.stdout.decode("utf-8", errors="strict"))
                return (
                    f"net.probe {parsed.get('method')} {parsed.get('final_url')} -> "
                    f"status={parsed.get('status_code')} pinned_ip={parsed.get('pinned_ip')} "
                    f"hops={len(parsed.get('hops', []))} body_bytes={parsed.get('body_bytes')}."
                )
            except Exception:
                return f"net.probe {action.operation} completed ({len(sub_res.stdout)}B captured)."


if __name__ == "__main__":
    raise SystemExit(_worker_main())
