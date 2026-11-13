"""CTF-09 integration tests: Scoped HTTP Probe (`net.probe`), DNS pinning & rebinding,
per-hop 3xx redirect re-validation, IPv4-mapped/IPv6/metadata SSRF blocking, userinfo
rejection, live scope revocation, and OFFLINE_CTF isolation via FastMCP.
"""

from __future__ import annotations

import asyncio
import json
import socket
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client

from ctf_mcp.adapters import ScopedHttpProbeAdapter, create_scoped_http_probe_descriptor
from ctf_mcp.contracts import (
    ActionRequest,
    BudgetSpec,
    CapabilityLimits,
    EnvelopeStatus,
    ExecutionClass,
    PrincipalContext,
    RunMode,
    ScopePolicy,
    canonical_digest,
)
from ctf_mcp.controller import create_default_controller
from ctf_mcp.gateway import ScopedNetworkPolicyGuard
from ctf_mcp.server import create_mcp_server
from ctf_mcp.storage import Storage


class _MutableClock:
    def __init__(self, start: datetime | None = None) -> None:
        self.now = start or datetime(2026, 11, 13, 4, 0, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: int) -> datetime:
        self.now = self.now + timedelta(seconds=seconds)
        return self.now


def _principal(pid: str = "alice") -> PrincipalContext:
    return PrincipalContext(
        principal_id=pid,
        auth_method="stdio_local",
        client_kind="Codex",
        model_label="ctf09-test-model",
    )


def _scoped_net_policy(
    *,
    mode: RunMode = RunMode.SCOPED_CTF,
    task_id: str = "task-ctf09",
    rev: str = "scope-ctf09-v1",
    allowed_targets: tuple[str, ...],
    network_enabled: bool = True,
    caps: tuple[str, ...] = ("analysis.query", "net.probe"),
    exec_classes: tuple[ExecutionClass, ...] = (ExecutionClass.STATIC, ExecutionClass.NETWORK),
    clock: _MutableClock | None = None,
) -> ScopePolicy:
    base = clock() if clock is not None else datetime.now(UTC)
    exp = base + timedelta(hours=2)
    payload = {
        "mode": mode.value,
        "task_id": task_id,
        "scope_revision": rev,
        "allowed_capabilities": list(caps),
        "allowed_execution_classes": [ec.value for ec in exec_classes],
        "network_enabled": network_enabled,
        "allowed_targets": list(allowed_targets),
        "expires_at": exp.isoformat(),
    }
    return ScopePolicy(
        scope_revision=rev,
        scope_sha256=canonical_digest(payload),
        mode=mode,
        task_id=task_id,
        authorization_reference="OWNED_LOCAL_CTF09_FIXTURE",
        allowed_execution_classes=exec_classes,
        allowed_capabilities=caps,
        expires_at=exp,
        network_enabled=network_enabled,
        allowed_targets=allowed_targets,
        external_submission=False,
    )


def _budget(**overrides: Any) -> BudgetSpec:
    defaults = {
        "run_budget_seconds": 300,
        "action_timeout_seconds": 10,
        "session_idle_seconds": 900,
        "max_tool_calls": 50,
        "max_output_chars_per_page": 250,
        "max_evidence_bytes_per_run": 1_048_576,
        "heavy_job_concurrency": 1,
        "interactive_session_limit": 1,
    }
    defaults.update(overrides)
    return BudgetSpec(**defaults)


def _tool_payload(res: Any) -> dict[str, Any]:
    if getattr(res, "structured_content", None) is not None:
        return dict(res.structured_content)
    if getattr(res, "data", None) is not None:
        return dict(res.data)
    return json.loads(res.content[0].text)


def _read_all_evidence_json(
    ctrl: Any,
    *,
    principal: PrincipalContext,
    run_id: str,
    evidence_id: str,
    max_chars: int = 300,
) -> dict[str, Any]:
    chunks: list[str] = []
    cursor: str | None = None
    while True:
        page = ctrl.read_evidence(
            principal=principal,
            run_id=run_id,
            evidence_id=evidence_id,
            cursor=cursor,
            max_chars=max_chars,
        )
        chunks.append(page.content)
        if page.next_cursor is None:
            break
        cursor = page.next_cursor
    return json.loads("".join(chunks))


def _start_fixture_servers(
    *,
    on_revoke_trigger: Any = None,
) -> tuple[ThreadingHTTPServer, ThreadingHTTPServer, dict[str, dict[str, int]]]:
    """Start Server A (scoped primary fixture) and Server B (out-of-scope neighbor)."""
    state_lock = threading.Lock()
    counters: dict[str, dict[str, int]] = {"a": {}, "b": {}}

    def _inc(srv_key: str, path: str) -> None:
        with state_lock:
            counters[srv_key][path] = counters[srv_key].get(path, 0) + 1

    class _ServerBHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: Any) -> None:
            _ = (fmt, args)

        def do_GET(self) -> None:  # noqa: N802
            _inc("b", self.path)
            body = json.dumps({"server": "B", "path": self.path}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server_b = ThreadingHTTPServer(("127.0.0.1", 0), _ServerBHandler)
    port_b = server_b.server_address[1]

    class _ServerAHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: Any) -> None:
            _ = (fmt, args)

        def do_HEAD(self) -> None:  # noqa: N802
            _inc("a", f"HEAD:{self.path}")
            self.send_response(200)
            self.send_header("X-Probe-Method", "HEAD")
            self.send_header("X-Observed-Host", self.headers.get("Host", ""))
            self.end_headers()

        def do_GET(self) -> None:  # noqa: N802
            port_a = self.server.server_address[1]  # type: ignore[attr-defined]
            path = self.path.split("?", 1)[0]
            _inc("a", f"GET:{path}")

            if path == "/public/flag":
                payload = json.dumps(
                    {
                        "server": "A",
                        "host_header": self.headers.get("Host", ""),
                        "path": self.path,
                        "ok": True,
                    }
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return

            if path == "/public/large":
                payload = ("CTF09_STREAM_" * 9000).encode("ascii")
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return

            if path == "/public/redir-ok":
                self.send_response(302)
                self.send_header("Location", "/public/flag?from=redir")
                self.end_headers()
                return

            if path == "/public/redir-to-b":
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{port_b}/secret")
                self.end_headers()
                return

            if path == "/public/redir-admin":
                self.send_response(302)
                self.send_header("Location", f"http://allowed.test:{port_a}/admin/secret")
                self.end_headers()
                return

            if path == "/public/redir-metadata":
                self.send_response(302)
                self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
                self.end_headers()
                return

            if path == "/public/redir-ipv6-loopback":
                self.send_response(302)
                self.send_header("Location", f"http://[::1]:{port_a}/public/secret")
                self.end_headers()
                return

            if path == "/public/redir-ipv6-mapped":
                self.send_response(302)
                self.send_header("Location", f"http://[::ffff:127.0.0.1]:{port_a}/public/secret")
                self.end_headers()
                return

            if path == "/public/redir-file":
                self.send_response(302)
                self.send_header("Location", "file:///etc/passwd")
                self.end_headers()
                return

            if path == "/public/redir-userinfo":
                self.send_response(302)
                self.send_header("Location", f"http://allowed.test@127.0.0.1:{port_a}/public/secret")
                self.end_headers()
                return

            if path == "/public/redir-rebind":
                self.send_response(302)
                self.send_header("Location", f"http://rebind.test:{port_a}/public/secret")
                self.end_headers()
                return

            if path == "/public/revoke-and-redir":
                if callable(on_revoke_trigger):
                    on_revoke_trigger()
                self.send_response(302)
                self.send_header("Location", "/public/secret")
                self.end_headers()
                return

            body = json.dumps({"path": self.path, "note": "protected"}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server_a = ThreadingHTTPServer(("127.0.0.1", 0), _ServerAHandler)

    threading.Thread(target=server_a.serve_forever, daemon=True).start()
    threading.Thread(target=server_b.serve_forever, daemon=True).start()
    return server_a, server_b, counters


# ---------------------------------------------------------------------------
# 1. In-scope GET/HEAD, DNS pinning, Host header preservation, paging, OFFLINE isolation
# ---------------------------------------------------------------------------


def test_ctf09_in_scope_get_head_dns_pinning_paging_and_offline_isolation(
    tmp_path: Path,
) -> None:
    clock = _MutableClock()
    server_a, server_b, _counters = _start_fixture_servers()
    try:
        port_a = server_a.server_address[1]
        port_b = server_b.server_address[1]

        def _resolver(host: str, port: int) -> list[Any]:
            if host == "allowed.test":
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]
            raise OSError(f"unexpected lookup {host}")

        guard = ScopedNetworkPolicyGuard(dns_resolver=_resolver, clock=clock)
        ctrl = create_default_controller(
            storage=Storage(tmp_path / "state" / "harness.db"),
            vault_root=tmp_path / "vault",
            export_root=tmp_path / "exports",
            cursor_hmac_key=b"ctf09-basic-fixed-hmac-32bytes!!",
            network_guard=guard,
            include_scoped_http_probe=True,
            clock=clock,
        )
        # Re-bind guard's live scope provider to controller (not overwritten because controller uses its own? Wait!)
        # Make sure guard also checks controller live scope via new guard attached with scope_provider if needed
        alice = _principal("alice")

        # Offline run: net.probe MUST be hidden and denied
        off_run = ctrl.create_run(
            principal=alice,
            task_id="task-ctf09-offline",
            mode=RunMode.OFFLINE_CTF,
            scope=_scoped_net_policy(
                mode=RunMode.OFFLINE_CTF,
                task_id="task-ctf09-offline",
                rev="scope-off-1",
                allowed_targets=(),
                network_enabled=False,
                caps=("analysis.query", "net.probe"),
                exec_classes=(ExecutionClass.STATIC,),
                clock=clock,
            ),
            budget=_budget(),
        )
        srv_off = create_mcp_server(ctrl, default_stdio_principal=alice, active_run_id=off_run.run_id)

        async def _check_offline() -> None:
            async with Client(srv_off.mcp) as client:
                listed = {t.name for t in await client.list_tools()}
                assert "net.probe" not in listed
                assert "session.control" not in listed
                denied = await client.call_tool("net.probe", {}, raise_on_error=False)
                assert denied.is_error is True
                dp = _tool_payload(denied)
                assert dp["status"] == "denied"
                assert dp["error"]["code"] == "tool_denied"

        asyncio.run(_check_offline())

        # Scoped CTF run: explicit host:port/prefix|ip=127.0.0.1 binding
        scoped_run = ctrl.create_run(
            principal=alice,
            task_id="task-ctf09-scoped",
            mode=RunMode.SCOPED_CTF,
            scope=_scoped_net_policy(
                mode=RunMode.SCOPED_CTF,
                task_id="task-ctf09-scoped",
                rev="scope-ctf09-1",
                allowed_targets=(
                    f"http://allowed.test:{port_a}/public|ip=127.0.0.1|methods=GET,HEAD",
                ),
                network_enabled=True,
                caps=("analysis.query", "net.probe"),
                exec_classes=(ExecutionClass.STATIC, ExecutionClass.NETWORK),
                clock=clock,
            ),
            budget=_budget(),
        )
        assert port_b != port_a
        srv = create_mcp_server(ctrl, default_stdio_principal=alice, active_run_id=scoped_run.run_id)

        async def _check_scoped() -> None:
            async with Client(srv.mcp) as client:
                listed = {t.name for t in await client.list_tools()}
                assert "net.probe" in listed

                # Case-insensitive host + trailing dot normalized cleanly while pinning 127.0.0.1
                rev = ctrl.runs.get_run_snapshot(scoped_run.run_id).revision
                get_res = _tool_payload(
                    await client.call_tool(
                        "net.probe",
                        {
                            "run_id": scoped_run.run_id,
                            "request_id": "req-net-get-ok",
                            "expected_revision": rev,
                            "operation": "get",
                            "arguments": {"url": f"HTTP://ALLOWED.TEST.:{port_a}/public/flag"},
                        },
                    )
                )
                assert get_res["status"] == "ok"
                assert get_res["usage"]["wall_ms"] >= 0
                assert get_res["usage"]["output_bytes"] > 0
                assert get_res["usage"]["peak_rss_bytes"] > 0
                assert get_res["usage"]["cpu_ms"] >= 0
                ev = _read_all_evidence_json(
                    ctrl,
                    principal=alice,
                    run_id=scoped_run.run_id,
                    evidence_id=get_res["evidence"][0]["id"],
                )
                assert ev["status_code"] == 200
                assert ev["pinned_ip"] == "127.0.0.1"
                body_obj = json.loads(ev["body"])
                assert body_obj["server"] == "A"
                assert body_obj["host_header"] == f"allowed.test:{port_a}"

                # HEAD request succeeds with zero body
                rev = ctrl.runs.get_run_snapshot(scoped_run.run_id).revision
                head_res = _tool_payload(
                    await client.call_tool(
                        "net.probe",
                        {
                            "run_id": scoped_run.run_id,
                            "request_id": "req-net-head-ok",
                            "expected_revision": rev,
                            "operation": "head",
                            "arguments": {"url": f"http://allowed.test:{port_a}/public/head"},
                        },
                    )
                )
                assert head_res["status"] == "ok"
                head_ev = _read_all_evidence_json(
                    ctrl,
                    principal=alice,
                    run_id=scoped_run.run_id,
                    evidence_id=head_res["evidence"][0]["id"],
                )
                assert head_ev["status_code"] == 200
                assert head_ev["method"] == "HEAD"
                assert head_ev["body"] == ""

                # In-scope 302 redirect follows safely to /public/flag
                rev = ctrl.runs.get_run_snapshot(scoped_run.run_id).revision
                redir_ok = _tool_payload(
                    await client.call_tool(
                        "net.probe",
                        {
                            "run_id": scoped_run.run_id,
                            "request_id": "req-net-redir-ok",
                            "expected_revision": rev,
                            "operation": "get",
                            "arguments": {
                                "url": f"http://allowed.test:{port_a}/public/redir-ok",
                                "follow_redirects": True,
                            },
                        },
                    )
                )
                assert redir_ok["status"] == "ok"
                redir_ev = _read_all_evidence_json(
                    ctrl,
                    principal=alice,
                    run_id=scoped_run.run_id,
                    evidence_id=redir_ok["evidence"][0]["id"],
                )
                assert redir_ev["status_code"] == 200
                assert len(redir_ev["hops"]) == 2
                assert json.loads(redir_ev["body"])["path"] == "/public/flag?from=redir"

                # Bounded response truncation (>64 KiB body capped safely)
                rev = ctrl.runs.get_run_snapshot(scoped_run.run_id).revision
                large_res = _tool_payload(
                    await client.call_tool(
                        "net.probe",
                        {
                            "run_id": scoped_run.run_id,
                            "request_id": "req-net-large",
                            "expected_revision": rev,
                            "operation": "get",
                            "arguments": {"url": f"http://allowed.test:{port_a}/public/large"},
                        },
                    )
                )
                assert large_res["status"] == "ok"
                large_ev = _read_all_evidence_json(
                    ctrl,
                    principal=alice,
                    run_id=scoped_run.run_id,
                    evidence_id=large_res["evidence"][0]["id"],
                    max_chars=250,
                )
                assert large_ev["body_truncated"] is True
                assert large_ev["status_code"] == 200

        asyncio.run(_check_scoped())
    finally:
        server_a.shutdown()
        server_a.server_close()
        server_b.shutdown()
        server_b.server_close()


# ---------------------------------------------------------------------------
# 2. Malicious 3xx redirects, userinfo, metadata, IPv6/IPv4-mapped SSRF blocked pre-connect
# ---------------------------------------------------------------------------


def test_ctf09_blocks_malicious_redirects_userinfo_and_unallowed_targets(
    tmp_path: Path,
) -> None:
    clock = _MutableClock()
    server_a, server_b, counters = _start_fixture_servers()
    try:
        port_a = server_a.server_address[1]
        port_b = server_b.server_address[1]

        def _resolver(host: str, port: int) -> list[Any]:
            if host == "allowed.test":
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]
            raise OSError(f"blocked dns {host}")

        guard = ScopedNetworkPolicyGuard(dns_resolver=_resolver, clock=clock)
        ctrl = create_default_controller(
            storage=Storage(tmp_path / "state" / "harness.db"),
            vault_root=tmp_path / "vault",
            export_root=tmp_path / "exports",
            cursor_hmac_key=b"ctf09-redir-fixed-hmac-32bytes!!",
            network_guard=guard,
            include_scoped_http_probe=True,
            clock=clock,
        )
        alice = _principal("alice")
        run = ctrl.create_run(
            principal=alice,
            task_id="task-ctf09-redir",
            mode=RunMode.VDP,
            scope=_scoped_net_policy(
                mode=RunMode.VDP,
                task_id="task-ctf09-redir",
                rev="scope-vdp-1",
                allowed_targets=(
                    f"http://allowed.test:{port_a}/public|ip=127.0.0.1|methods=GET,HEAD",
                ),
                network_enabled=True,
                caps=("analysis.query", "net.probe"),
                exec_classes=(ExecutionClass.STATIC, ExecutionClass.NETWORK),
                clock=clock,
            ),
            budget=_budget(),
        )
        srv = create_mcp_server(ctrl, default_stdio_principal=alice, active_run_id=run.run_id)

        async def _check() -> None:
            async with Client(srv.mcp) as client:
                direct_blocked_urls = [
                    f"http://allowed.test@127.0.0.1:{port_a}/public/secret",
                    f"http://user:pass@allowed.test:{port_a}/public/secret",
                    "file:///etc/passwd",
                    f"http://127.0.0.1:{port_b}/secret",
                    "http://169.254.169.254/latest/meta-data/",
                    f"http://[::1]:{port_a}/public/secret",
                    f"http://[::ffff:127.0.0.1]:{port_a}/public/secret",
                    "http://10.0.0.1/internal",
                ]
                for idx, bad_url in enumerate(direct_blocked_urls):
                    rev = ctrl.runs.get_run_snapshot(run.run_id).revision
                    res = _tool_payload(
                        await client.call_tool(
                            "net.probe",
                            {
                                "run_id": run.run_id,
                                "request_id": f"req-bad-direct-{idx}",
                                "expected_revision": rev,
                                "operation": "get",
                                "arguments": {"url": bad_url},
                            },
                        )
                    )
                    assert res["status"] == "denied", f"{bad_url} should be denied, got {res}"

                redirect_paths = [
                    "/public/redir-to-b",
                    "/public/redir-admin",
                    "/public/redir-metadata",
                    "/public/redir-ipv6-loopback",
                    "/public/redir-ipv6-mapped",
                    "/public/redir-file",
                    "/public/redir-userinfo",
                ]
                for idx, rpath in enumerate(redirect_paths):
                    rev = ctrl.runs.get_run_snapshot(run.run_id).revision
                    res = _tool_payload(
                        await client.call_tool(
                            "net.probe",
                            {
                                "run_id": run.run_id,
                                "request_id": f"req-bad-redir-{idx}",
                                "expected_revision": rev,
                                "operation": "get",
                                "arguments": {
                                    "url": f"http://allowed.test:{port_a}{rpath}",
                                    "follow_redirects": True,
                                },
                            },
                        )
                    )
                    assert res["status"] == "denied", f"{rpath} should be denied, got {res}"

        asyncio.run(_check())
        assert counters["b"] == {}
        assert counters["a"].get("GET:/admin/secret", 0) == 0
        assert counters["a"].get("GET:/public/secret", 0) == 0
    finally:
        server_a.shutdown()
        server_a.server_close()
        server_b.shutdown()
        server_b.server_close()


# ---------------------------------------------------------------------------
# 3. DNS rebinding, mixed multi-record DNS rejection, and live `revoke_scope`
# ---------------------------------------------------------------------------


def test_ctf09_dns_rebinding_multi_record_and_live_scope_revocation(
    tmp_path: Path,
) -> None:
    clock = _MutableClock()
    alice = _principal("alice")
    ctrl_holder: dict[str, Any] = {}
    run_holder: dict[str, str] = {}

    def _revoke_mid_redirect() -> None:
        ctrl_holder["ctrl"].revoke_scope(principal=alice, run_id=run_holder["run_id"])

    server_a, server_b, counters = _start_fixture_servers(
        on_revoke_trigger=_revoke_mid_redirect
    )
    try:
        port_a = server_a.server_address[1]
        dns_calls = {"rebind": 0}

        # Note: For rebind.test we attach IP rule in allowed_targets to prove rebind flip to 127.0.0.2 / ::1 fails!
        def _rebinding_resolver(host: str, port: int) -> list[Any]:
            if host == "allowed.test":
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]
            if host == "rebind.test":
                dns_calls["rebind"] += 1
                if dns_calls["rebind"] == 1:
                    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]
                if dns_calls["rebind"] == 2:
                    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.2", port))]
                return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", port, 0, 0))]
            if host == "poison.test":
                return [
                    (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port)),
                    (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", port)),
                ]
            raise OSError(f"unknown host {host}")

        storage = Storage(tmp_path / "state" / "harness.db")
        ctrl = create_default_controller(
            storage=storage,
            vault_root=tmp_path / "vault",
            export_root=tmp_path / "exports",
            cursor_hmac_key=b"ctf09-rebind-fixed-hmac-32bytes!",
            include_scoped_http_probe=False,
            clock=clock,
        )
        guard = ScopedNetworkPolicyGuard(
            dns_resolver=_rebinding_resolver,
            scope_provider=ctrl._load_live_scope_policy,
            clock=clock,
        )
        ctrl.network_guard = guard
        probe_adapter = ScopedHttpProbeAdapter(
            descriptor=create_scoped_http_probe_descriptor(
                limits=CapabilityLimits(timeout_seconds=10, max_output_bytes=65_536, max_decode_bytes=65_536)
            ),
            evidence_vault=ctrl.evidence_vault,
            network_guard=guard,
            policy_provider=ctrl._load_live_scope_policy,
        )
        ctrl.register_adapter(probe_adapter, tool_group="net.probe")
        ctrl_holder["ctrl"] = ctrl

        run = ctrl.create_run(
            principal=alice,
            task_id="task-ctf09-rebind",
            mode=RunMode.SCOPED_CTF,
            scope=_scoped_net_policy(
                mode=RunMode.SCOPED_CTF,
                task_id="task-ctf09-rebind",
                rev="scope-rebind-1",
                allowed_targets=(
                    f"http://allowed.test:{port_a}/public|ip=127.0.0.1",
                    f"http://rebind.test:{port_a}/public|ip=127.0.0.1",
                    f"http://poison.test:{port_a}/public|ip=127.0.0.1",
                ),
                network_enabled=True,
                caps=("analysis.query", "net.probe"),
                exec_classes=(ExecutionClass.STATIC, ExecutionClass.NETWORK),
                clock=clock,
            ),
            budget=_budget(),
        )
        run_holder["run_id"] = run.run_id
        srv = create_mcp_server(ctrl, default_stdio_principal=alice, active_run_id=run.run_id)

        async def _check() -> None:
            async with Client(srv.mcp) as client:
                # 1) Multi-record poisoned DNS ([127.0.0.1, 169.254.169.254]) rejected pre-connect
                poison_res = _tool_payload(
                    await client.call_tool(
                        "net.probe",
                        {
                            "run_id": run.run_id,
                            "request_id": "req-net-poison",
                            "expected_revision": ctrl.runs.get_run_snapshot(run.run_id).revision,
                            "operation": "get",
                            "arguments": {"url": f"http://poison.test:{port_a}/public/secret"},
                        },
                    )
                )
                assert poison_res["status"] == "denied"

                # 2) DNS Rebinding across redirect: Hop 0 resolves rebind.test->127.0.0.1, receives 302 to
                # rebind.test/public/secret; Hop 1 resolves rebind.test->127.0.0.2 -> BLOCKED pre-connect!
                reb_res = _tool_payload(
                    await client.call_tool(
                        "net.probe",
                        {
                            "run_id": run.run_id,
                            "request_id": "req-net-rebind-redirect",
                            "expected_revision": ctrl.runs.get_run_snapshot(run.run_id).revision,
                            "operation": "get",
                            "arguments": {
                                "url": f"http://rebind.test:{port_a}/public/redir-rebind",
                                "follow_redirects": True,
                            },
                        },
                    )
                )
                assert reb_res["status"] == "denied"
                assert counters["a"].get("GET:/public/redir-rebind", 0) == 1
                assert counters["a"].get("GET:/public/secret", 0) == 0

                # Next resolution flips to ::1 -> preflight blocks immediately
                reb_v6 = _tool_payload(
                    await client.call_tool(
                        "net.probe",
                        {
                            "run_id": run.run_id,
                            "request_id": "req-net-rebind-v6",
                            "expected_revision": ctrl.runs.get_run_snapshot(run.run_id).revision,
                            "operation": "get",
                            "arguments": {"url": f"http://rebind.test:{port_a}/public/secret"},
                        },
                    )
                )
                assert reb_v6["status"] == "denied"
                assert counters["a"].get("GET:/public/secret", 0) == 0

                # 3) Live mid-redirect revoke_scope triggers immediate scope_revoked before Hop 1!
                rev_res = _tool_payload(
                    await client.call_tool(
                        "net.probe",
                        {
                            "run_id": run.run_id,
                            "request_id": "req-net-mid-revoke",
                            "expected_revision": ctrl.runs.get_run_snapshot(run.run_id).revision,
                            "operation": "get",
                            "arguments": {
                                "url": f"http://allowed.test:{port_a}/public/revoke-and-redir",
                                "follow_redirects": True,
                            },
                        },
                    )
                )
                assert rev_res["status"] == "denied"
                assert rev_res["error"]["code"] == "scope_revoked"
                assert counters["a"].get("GET:/public/secret", 0) == 0

                # 4) Post-revoke tools/list drops net.probe and direct call returns scope_revoked
                listed_after = {t.name for t in await client.list_tools()}
                assert "net.probe" not in listed_after

                post_rev = await client.call_tool(
                    "net.probe",
                    {
                        "run_id": run.run_id,
                        "request_id": "req-net-post-revoke",
                        "expected_revision": ctrl.runs.get_run_snapshot(run.run_id).revision,
                        "operation": "get",
                        "arguments": {"url": f"http://allowed.test:{port_a}/public/flag"},
                    },
                    raise_on_error=False,
                )
                assert post_rev.is_error is True
                pr_payload = _tool_payload(post_rev)
                assert pr_payload["status"] == "denied"
                assert pr_payload["error"]["code"] == "scope_revoked"

        asyncio.run(_check())
    finally:
        server_a.shutdown()
        server_a.server_close()
        server_b.shutdown()
        server_b.server_close()
