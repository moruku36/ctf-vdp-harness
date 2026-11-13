"""Layer 4 FastMCP server exposing the typed CTF/VDP analysis harness surface.

Exposes only typed harness tools over ``stdio`` and ``streamable-http``,
enforces fail-closed bearer/stdio authentication via ``PrincipalAuthenticator``,
dynamically filters ``tools/list`` from ``CapabilityCatalog`` and active run
scope, rejects direct ``call_tool`` invocations on hidden/forbidden tools, and
never authorizes access based on MCP ``readOnlyHint`` annotations.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, Literal

import anyio
from fastmcp import FastMCP
from fastmcp.server.auth import AccessToken, TokenVerifier
from fastmcp.server.dependencies import get_access_token, get_http_headers
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools import ToolResult
from mcp import types as mt

from ctf_mcp.adapters import is_os_process_alive
from ctf_mcp.config import (
    HarnessConfig,
    RuntimeSettings,
    get_cursor_hmac_key,
    load_config_file,
    load_runtime_settings,
)
from ctf_mcp.contracts import (
    ActionLifecycleState,
    ActionRequest,
    AuthenticationError,
    CapabilityDeniedError,
    ConfigurationError,
    EvidenceAccessDeniedError,
    FindingRecord,
    GuestHealthState,
    HarnessError,
    PrincipalContext,
    ScopeDeniedError,
    TransportMode,
)
from ctf_mcp.controller import (
    ALWAYS_FORBIDDEN_TOOLS,
    ACTION_DISPATCH_TOOLS,
    HarnessController,
    create_default_controller,
    register_default_verifier,
)
from ctf_mcp.evidence import ReportMetadata
from ctf_mcp.gateway import sanitize_audit_text
from ctf_mcp.storage import Storage

SUPPORTED_TOOL_NAMES: tuple[str, ...] = (
    "run.describe",
    "artifact.inspect",
    "analysis.query",
    "helper.transform",
    "evidence.read",
    "hypothesis.update",
    "run.verify",
    "run.close",
)


def _error_status_for_exception(exc: HarnessError) -> Literal["denied", "tool_error"]:
    """Map domain exceptions to safe structured MCP error statuses."""
    if isinstance(
        exc,
        (
            AuthenticationError,
            ScopeDeniedError,
            CapabilityDeniedError,
            EvidenceAccessDeniedError,
        ),
    ):
        return "denied"
    return "tool_error"


def _tool_json_result(payload: Mapping[str, Any], *, is_error: bool = False) -> ToolResult:
    """Serialize a structured dict cleanly for FastMCP ToolResult consumers."""
    data = dict(payload)
    text = json.dumps(data, ensure_ascii=False, default=str)
    return ToolResult(content=text, structured_content=data, is_error=is_error)


def _error_tool_result(
    *,
    status: Literal["denied", "tool_error"],
    code: str,
    message: str,
    retryable: bool = False,
    details: Mapping[str, Any] | None = None,
) -> ToolResult:
    """Create a sanitized MCP ToolResult with ``is_error=True`` and structured error JSON."""
    clean_msg = sanitize_audit_text(message) or code
    payload: dict[str, Any] = {
        "status": status,
        "error": {
            "code": code,
            "message": clean_msg,
            "retryable": retryable,
        },
    }
    if details:
        payload["details"] = dict(details)
    return _tool_json_result(payload, is_error=True)


class HarnessTokenVerifier(TokenVerifier):
    """Fail-closed FastMCP bearer TokenVerifier backed by PrincipalAuthenticator."""

    def __init__(self, server: HarnessMcpServer) -> None:
        super().__init__()
        self._server = server

    async def verify_token(self, token: str) -> AccessToken | None:
        """Verify an HTTP Bearer token against registered operator bindings."""
        try:
            principal = self._server.controller.authenticator.authenticate(
                TransportMode.STREAMABLE_HTTP,
                token=token,
            )
        except HarnessError:
            return None
        return AccessToken(
            token=token,
            client_id=principal.principal_id,
            scopes=["ctf:harness"],
            subject=principal.principal_id,
            claims={"principal": principal.model_dump(mode="json")},
        )


class HarnessGateMiddleware(Middleware):
    """Dynamic tool visibility filter and fail-closed server-side invocation gate.

    Security boundaries enforced here:
    - Always exclude ``exec_shell`` / generic shell tools and disabled/unaccepted capabilities.
    - Never trust MCP ``ToolAnnotations.readOnlyHint`` for authorization.
    - Pre-deny direct ``call_tool`` invocations targeting hidden, unaccepted, or
      forbidden tools before reaching any tool handler.
    """

    def __init__(self, server: HarnessMcpServer) -> None:
        super().__init__()
        self._server = server

    async def on_list_tools(
        self,
        context: MiddlewareContext[mt.ListToolsRequest],
        call_next: CallNext[mt.ListToolsRequest, Sequence[Any]],
    ) -> Sequence[Any]:
        """Return only MCP tools visible for the authenticated principal and active run/profile."""
        principal = self._server.resolve_principal()
        run_id = self._server.resolve_scope_run_id()
        visible = await anyio.to_thread.run_sync(
            lambda: self._server.visible_tool_names(
                principal=principal,
                run_id=run_id,
            )
        )
        tools = await call_next(context)
        return [
            tool
            for tool in tools
            if tool.name in visible and tool.name not in ALWAYS_FORBIDDEN_TOOLS
        ]

    async def on_call_tool(
        self,
        context: MiddlewareContext[mt.CallToolRequestParams],
        call_next: CallNext[mt.CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        """Authenticate caller and reject hidden/forbidden tools before execution."""
        try:
            principal = self._server.resolve_principal()
        except HarnessError as exc:
            return _error_tool_result(
                status="denied",
                code=exc.code,
                message=str(exc),
            )

        tool_name = context.message.name
        arguments = context.message.arguments or {}

        if (
            tool_name in ALWAYS_FORBIDDEN_TOOLS
            or tool_name == "session.control"
            or tool_name not in SUPPORTED_TOOL_NAMES
        ):
            return _error_tool_result(
                status="denied",
                code="tool_denied",
                message=f"Tool {tool_name!r} is disabled or not permitted.",
                details={"tool_name": tool_name},
            )

        scope_run_id = self._server.resolve_scope_run_id(arguments=arguments)
        try:
            visible = await anyio.to_thread.run_sync(
                lambda: self._server.visible_tool_names(
                    principal=principal,
                    run_id=scope_run_id,
                )
            )
        except HarnessError as exc:
            return _error_tool_result(
                status=_error_status_for_exception(exc),
                code=exc.code,
                message=str(exc),
                details={"tool_name": tool_name},
            )

        # Allow action tools to surface domain denial/expiry ResultEnvelopes when an
        # active/owned run's scope expired ONLY if the tool itself is enabled in the
        # run's mode catalog; otherwise pre-deny hidden tools directly here.
        if tool_name not in visible:
            if tool_name in ACTION_DISPATCH_TOOLS and scope_run_id is not None:
                reason = await anyio.to_thread.run_sync(
                    lambda: self._server.describe_hidden_reason(
                        principal=principal,
                        run_id=scope_run_id,
                        tool_name=tool_name,
                    )
                )
            else:
                reason = (
                    f"Tool {tool_name!r} is hidden or unaccepted for the current "
                    "profile/scope."
                )
            code = "scope_expired" if "expired" in reason.lower() else "tool_denied"
            return _error_tool_result(
                status="denied",
                code=code,
                message=reason,
                details={"tool_name": tool_name},
            )

        return await call_next(context)


class HarnessMcpServer:
    """Layer 4 FastMCP server binding typed CTF/VDP tools to HarnessController."""

    def __init__(
        self,
        *,
        controller: HarnessController,
        transport_mode: TransportMode = TransportMode.STDIO,
        runtime_settings: RuntimeSettings | None = None,
        default_stdio_principal: PrincipalContext | None = None,
        stdio_principal_id: str = "local-operator",
        active_run_id: str | None = None,
        principal_resolver: Callable[[], PrincipalContext] | None = None,
        name: str = "ctf-vdp-harness",
        instructions: str | None = None,
    ) -> None:
        if runtime_settings is not None:
            transport_mode = runtime_settings.transport

        if transport_mode == TransportMode.STREAMABLE_HTTP:
            if runtime_settings is not None and runtime_settings.auth_token is None:
                raise ConfigurationError(
                    "streamable-http transport requires CTF_MCP_AUTH_TOKEN."
                )

        self.controller = controller
        self.transport_mode = transport_mode
        self.runtime_settings = runtime_settings
        self._active_run_id = active_run_id
        self._principal_resolver = principal_resolver

        if default_stdio_principal is not None:
            self._stdio_principal: PrincipalContext | None = default_stdio_principal
        elif transport_mode == TransportMode.STDIO:
            self._stdio_principal = controller.authenticator.authenticate_stdio(
                principal_id=stdio_principal_id
            )
        else:
            self._stdio_principal = None

        auth_provider = (
            HarnessTokenVerifier(self)
            if transport_mode == TransportMode.STREAMABLE_HTTP
            else None
        )
        self.mcp = FastMCP(
            name=name,
            instructions=instructions
            or (
                "Typed offline CTF/VDP analysis harness. All authorization, scope, "
                "budget, and evidence boundaries are enforced server-side."
            ),
            auth=auth_provider,
            middleware=[HarnessGateMiddleware(self)],
        )
        self._register_tools()

    def set_active_run(self, run_id: str | None) -> None:
        """Bind or clear the active run_id used for default tools/list scope filtering."""
        self._active_run_id = run_id

    def resolve_principal(self) -> PrincipalContext:
        """Authenticate the current caller without trusting tool arguments or readOnlyHint."""
        if self._principal_resolver is not None:
            return self._principal_resolver()

        access_token = get_access_token()
        if access_token is not None:
            raw_principal = access_token.claims.get("principal")
            if isinstance(raw_principal, Mapping):
                return PrincipalContext.model_validate(raw_principal)
            return self.controller.authenticator.authenticate(
                TransportMode.STREAMABLE_HTTP,
                token=access_token.token,
            )

        if self.transport_mode == TransportMode.STREAMABLE_HTTP:
            headers = get_http_headers()
            auth_header = headers.get("authorization")
            return self.controller.authenticator.authenticate(
                TransportMode.STREAMABLE_HTTP,
                authorization=auth_header,
            )

        if self._stdio_principal is not None:
            return self._stdio_principal

        raise AuthenticationError(
            "Unable to authenticate MCP caller for current transport."
        )

    def resolve_scope_run_id(
        self,
        *,
        arguments: Mapping[str, Any] | None = None,
    ) -> str | None:
        """Resolve run_id from request arguments, HTTP header, or server active run."""
        if arguments is not None:
            arg_run = arguments.get("run_id")
            if isinstance(arg_run, str) and arg_run.strip():
                return arg_run.strip()
        try:
            headers = get_http_headers()
            header_run = headers.get("x-ctf-run-id")
            if isinstance(header_run, str) and header_run.strip():
                return header_run.strip()
        except Exception:
            pass
        return self._active_run_id

    def visible_tool_names(
        self,
        *,
        principal: PrincipalContext,
        run_id: str | None = None,
    ) -> set[str]:
        """Compute currently visible MCP tool names for principal and optional run."""
        return self.controller.get_visible_mcp_tool_names(
            principal=principal,
            run_id=run_id,
            mode=self.controller.default_mode,
        )

    def describe_hidden_reason(
        self,
        *,
        principal: PrincipalContext,
        run_id: str,
        tool_name: str,
    ) -> str:
        """Build a safe denial explanation when a hidden dispatch tool is called directly."""
        try:
            self.controller.scope_validator.get_active_scope(
                run_id, now=self.controller._now()
            )
        except ScopeDeniedError as exc:
            return sanitize_audit_text(str(exc)) or f"Scope denied for tool {tool_name!r}."
        return (
            f"Tool {tool_name!r} is disabled or excluded from the active scope/profile "
            f"for run {run_id!r}."
        )

    async def _run_guarded(self, fn: Callable[[], dict[str, Any]]) -> ToolResult:
        """Run a synchronous controller call off the event loop and convert HarnessErrors."""
        try:
            payload = await anyio.to_thread.run_sync(fn)
        except HarnessError as exc:
            return _error_tool_result(
                status=_error_status_for_exception(exc),
                code=exc.code,
                message=str(exc),
            )
        return _tool_json_result(payload, is_error=False)

    async def _dispatch_action(
        self,
        *,
        tool_group: str,
        run_id: str,
        request_id: str,
        expected_revision: int,
        operation: str,
        capability_name: str | None = None,
        arguments: dict[str, Any] | None = None,
        repeat_of: str | None = None,
        pre_launch_expired_reason: str | None = None,
    ) -> ToolResult:
        """Shared dispatcher for artifact.inspect, analysis.query, and helper.transform."""
        try:
            principal = self.resolve_principal()
        except HarnessError as exc:
            return _error_tool_result(status="denied", code=exc.code, message=str(exc))

        def _invoke() -> dict[str, Any]:
            chosen_cap = self.controller.resolve_capability_for_tool_group(
                tool_group=tool_group,
                capability_name=capability_name,
                principal=principal,
                run_id=run_id,
            )
            req = ActionRequest(
                run_id=run_id,
                request_id=request_id,
                expected_revision=expected_revision,
                capability_name=chosen_cap,
                operation=operation,
                arguments=dict(arguments or {}),
                repeat_of=repeat_of,
            )
            envelope = self.controller.execute_action(
                principal=principal,
                request=req,
                pre_launch_expired_reason=pre_launch_expired_reason,
            )
            return envelope.model_dump(mode="json")

        return await self._run_guarded(_invoke)

    def _register_tools(self) -> None:
        """Register the fixed set of typed MVP harness tools (never exec_shell)."""
        read_only_hint = mt.ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            openWorldHint=False,
        )
        mutating_hint = mt.ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=False,
            openWorldHint=False,
        )

        @self.mcp.tool(
            name="run.describe",
            description="Inspect run manifest, artifacts, budget, hypotheses, actions, and visible tools.",
            annotations=read_only_hint,
        )
        async def run_describe(run_id: str) -> ToolResult:
            principal = self.resolve_principal()
            return await self._run_guarded(
                lambda: self.controller.describe_run(principal=principal, run_id=run_id)
            )

        @self.mcp.tool(
            name="artifact.inspect",
            description="Execute an accepted static artifact inspection capability.",
            annotations=read_only_hint,
        )
        async def artifact_inspect(
            run_id: str,
            request_id: str,
            expected_revision: int,
            operation: str = "observe",
            capability_name: str | None = None,
            arguments: dict[str, Any] | None = None,
            repeat_of: str | None = None,
            pre_launch_expired_reason: str | None = None,
        ) -> ToolResult:
            return await self._dispatch_action(
                tool_group="artifact.inspect",
                run_id=run_id,
                request_id=request_id,
                expected_revision=expected_revision,
                operation=operation,
                capability_name=capability_name,
                arguments=arguments,
                repeat_of=repeat_of,
                pre_launch_expired_reason=pre_launch_expired_reason,
            )

        @self.mcp.tool(
            name="analysis.query",
            description="Execute an accepted offline analysis capability with typed arguments.",
            annotations=read_only_hint,
        )
        async def analysis_query(
            run_id: str,
            request_id: str,
            expected_revision: int,
            operation: str,
            capability_name: str | None = None,
            arguments: dict[str, Any] | None = None,
            repeat_of: str | None = None,
            pre_launch_expired_reason: str | None = None,
        ) -> ToolResult:
            return await self._dispatch_action(
                tool_group="analysis.query",
                run_id=run_id,
                request_id=request_id,
                expected_revision=expected_revision,
                operation=operation,
                capability_name=capability_name,
                arguments=arguments,
                repeat_of=repeat_of,
                pre_launch_expired_reason=pre_launch_expired_reason,
            )

        @self.mcp.tool(
            name="helper.transform",
            description="Execute an accepted deterministic helper transform capability.",
            annotations=read_only_hint,
        )
        async def helper_transform(
            run_id: str,
            request_id: str,
            expected_revision: int,
            operation: str,
            capability_name: str | None = None,
            arguments: dict[str, Any] | None = None,
            repeat_of: str | None = None,
            pre_launch_expired_reason: str | None = None,
        ) -> ToolResult:
            return await self._dispatch_action(
                tool_group="helper.transform",
                run_id=run_id,
                request_id=request_id,
                expected_revision=expected_revision,
                operation=operation,
                capability_name=capability_name,
                arguments=arguments,
                repeat_of=repeat_of,
                pre_launch_expired_reason=pre_launch_expired_reason,
            )

        @self.mcp.tool(
            name="evidence.read",
            description="Read a bounded EvidencePage using an HMAC-signed cursor.",
            annotations=read_only_hint,
        )
        async def evidence_read(
            run_id: str,
            evidence_id: str,
            cursor: str | None = None,
            max_chars: int | None = None,
            max_decode_bytes: int | None = None,
        ) -> ToolResult:
            principal = self.resolve_principal()
            return await self._run_guarded(
                lambda: self.controller.read_evidence(
                    principal=principal,
                    run_id=run_id,
                    evidence_id=evidence_id,
                    cursor=cursor,
                    max_chars=max_chars,
                    max_decode_bytes=max_decode_bytes,
                ).model_dump(mode="json")
            )

        @self.mcp.tool(
            name="hypothesis.update",
            description="Create or optimistically update a structured run hypothesis record.",
            annotations=mutating_hint,
        )
        async def hypothesis_update(
            run_id: str,
            state: str = "unknown",
            hypothesis_id: str | None = None,
            expected_revision: int | None = None,
            claim: str | None = None,
            next_observation: str | None = None,
            supporting_evidence_ids: list[str] | None = None,
            contradicting_evidence_ids: list[str] | None = None,
            add_supporting_evidence_ids: list[str] | None = None,
            add_contradicting_evidence_ids: list[str] | None = None,
            request_id: str | None = None,
        ) -> ToolResult:
            principal = self.resolve_principal()
            return await self._run_guarded(
                lambda: self.controller.update_hypothesis(
                    principal=principal,
                    run_id=run_id,
                    hypothesis_id=hypothesis_id,
                    expected_revision=expected_revision,
                    state=state,
                    claim=claim,
                    next_observation=next_observation,
                    supporting_evidence_ids=tuple(supporting_evidence_ids or ()),
                    contradicting_evidence_ids=tuple(contradicting_evidence_ids or ()),
                    add_supporting_evidence_ids=tuple(add_supporting_evidence_ids or ()),
                    add_contradicting_evidence_ids=tuple(add_contradicting_evidence_ids or ()),
                    request_id=request_id,
                ).model_dump(mode="json")
            )

        @self.mcp.tool(
            name="run.verify",
            description="Run a registered local verifier against run evidence or claim without leaking secrets.",
            annotations=mutating_hint,
        )
        async def run_verify(
            run_id: str,
            verifier_id: str = "ctf.local_digest",
            evidence_ids: list[str] | None = None,
            claim: str | None = None,
            auto_redact_after_verify: bool = False,
        ) -> ToolResult:
            principal = self.resolve_principal()
            return await self._run_guarded(
                lambda: self.controller.verify_run(
                    principal=principal,
                    run_id=run_id,
                    verifier_id=verifier_id,
                    evidence_ids=tuple(evidence_ids or ()),
                    claim=claim,
                    auto_redact_after_verify=auto_redact_after_verify,
                ).model_dump(mode="json")
            )

        @self.mcp.tool(
            name="run.close",
            description="Verify host close integrity, export sanitized report, mark guest rollback, and close the run.",
            annotations=mutating_hint,
        )
        async def run_close(
            run_id: str,
            language: Literal["ja", "en"] = "ja",
            output_relpath: str | None = None,
            overwrite: bool = False,
            findings: list[dict[str, Any]] | None = None,
            metadata: dict[str, Any] | None = None,
            forbidden_literals: list[str] | None = None,
            require_verification: bool = False,
            expected_evidence_ids: list[str] | None = None,
            auto_redact_report: bool = True,
        ) -> ToolResult:
            principal = self.resolve_principal()

            def _close() -> dict[str, Any]:
                parsed_findings = [
                    FindingRecord.model_validate(item) for item in (findings or ())
                ]
                parsed_meta = (
                    ReportMetadata.model_validate(metadata)
                    if metadata is not None
                    else None
                )
                (
                    child_processes_stopped,
                    unconfirmed_pids,
                    import_completed,
                    import_errors,
                ) = _derive_host_close_checks(self.controller, run_id)
                result = self.controller.close_run(
                    principal=principal,
                    run_id=run_id,
                    language=language,
                    output_relpath=output_relpath,
                    overwrite=overwrite,
                    findings=parsed_findings,
                    metadata=parsed_meta,
                    forbidden_literals=tuple(forbidden_literals or ()),
                    require_verification=require_verification,
                    child_processes_confirmed_stopped=child_processes_stopped,
                    unconfirmed_process_ids=unconfirmed_pids,
                    import_completed=import_completed,
                    import_errors=import_errors,
                    expected_evidence_ids=tuple(expected_evidence_ids or ()),
                    auto_redact_report=auto_redact_report,
                )
                return {
                    "manifest": result.manifest.model_dump(mode="json"),
                    "export_result": result.export_result.model_dump(mode="json"),
                    "integrity_report": result.integrity_report.model_dump(mode="json"),
                    "guest_rolled_back": result.guest_rolled_back,
                }

            return await self._run_guarded(_close)

    def http_app(self, *, path: str = "/mcp") -> Any:
        """Return the ASGI Streamable HTTP Starlette app with bearer authentication."""
        return self.mcp.http_app(path=path, transport="streamable-http")

    def run(
        self,
        *,
        host: str = "127.0.0.1",
        port: int = 8000,
        path: str = "/mcp",
        show_banner: bool = False,
    ) -> None:
        """Start the FastMCP server using configured stdio or streamable-http transport."""
        if self.transport_mode == TransportMode.STREAMABLE_HTTP:
            self.mcp.run(
                transport="streamable-http",
                show_banner=show_banner,
                host=host,
                port=port,
                path=path,
            )
            return
        self.mcp.run(transport="stdio", show_banner=show_banner)


def create_mcp_server(
    controller: HarnessController,
    *,
    transport_mode: TransportMode = TransportMode.STDIO,
    runtime_settings: RuntimeSettings | None = None,
    default_stdio_principal: PrincipalContext | None = None,
    stdio_principal_id: str = "local-operator",
    active_run_id: str | None = None,
    principal_resolver: Callable[[], PrincipalContext] | None = None,
) -> HarnessMcpServer:
    """Construct a configured Layer 4 HarnessMcpServer wrapping HarnessController."""
    return HarnessMcpServer(
        controller=controller,
        transport_mode=transport_mode,
        runtime_settings=runtime_settings,
        default_stdio_principal=default_stdio_principal,
        stdio_principal_id=stdio_principal_id,
        active_run_id=active_run_id,
        principal_resolver=principal_resolver,
    )


def _derive_host_close_checks(
    controller: HarnessController,
    run_id: str,
) -> tuple[bool, list[str], bool, list[str]]:
    """Derive host child-process cleanup and bounded import completeness server-side."""
    child_stopped = True
    unconfirmed_pids: list[str] = []
    import_completed = True
    import_errors: list[str] = []

    with controller.storage.read_connection() as conn:
        run_row = conn.execute(
            "SELECT guest_health, active_heavy_jobs, active_sessions FROM runs WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        if run_row is not None:
            health = GuestHealthState(str(run_row["guest_health"]))
            if (
                health == GuestHealthState.CLEANUP_UNCONFIRMED
                or int(run_row["active_heavy_jobs"]) > 0
                or int(run_row["active_sessions"]) > 0
            ):
                child_stopped = False

            leases_table = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'session_leases'"
            ).fetchone()
            if leases_table is not None:
                active_leases = conn.execute(
                    "SELECT session_id FROM session_leases WHERE run_id = ? AND state = 'active'",
                    (run_id,),
                ).fetchall()
                if active_leases:
                    child_stopped = False

            action_rows = conn.execute(
                """
                SELECT action_id, state, process_start_id, error_code, envelope_json
                FROM actions
                WHERE run_id = ?
                ORDER BY created_at ASC
                """,
                (run_id,),
            ).fetchall()
            stored_evidence_ids = {
                str(r["evidence_id"])
                for r in conn.execute(
                    "SELECT evidence_id FROM evidence_objects WHERE run_id = ?",
                    (run_id,),
                ).fetchall()
            }
            evidence_with_views = {
                str(r["evidence_id"])
                for r in conn.execute(
                    "SELECT DISTINCT evidence_id FROM evidence_views WHERE run_id = ?",
                    (run_id,),
                ).fetchall()
            }

            for arow in action_rows:
                state = ActionLifecycleState(str(arow["state"]))
                pid_token = (
                    str(arow["process_start_id"])
                    if arow["process_start_id"] is not None
                    else None
                )
                if state in {
                    ActionLifecycleState.RESERVED,
                    ActionLifecycleState.RUNNING,
                    ActionLifecycleState.RECONCILIATION_REQUIRED,
                }:
                    child_stopped = False
                    if pid_token and is_os_process_alive(pid_token):
                        unconfirmed_pids.append(pid_token)
                else:
                    if pid_token and is_os_process_alive(pid_token):
                        child_stopped = False
                        unconfirmed_pids.append(pid_token)
                    if (
                        arow["error_code"] == "cleanup_unconfirmed"
                        and health != GuestHealthState.READY
                    ):
                        child_stopped = False

                env_raw = arow["envelope_json"]
                if env_raw:
                    try:
                        env_data = json.loads(str(env_raw))
                    except json.JSONDecodeError:
                        import_completed = False
                        import_errors.append(f"corrupt_envelope:{arow['action_id']}")
                        continue
                    for ev in env_data.get("evidence") or ():
                        eid = str(ev.get("id") or "").strip()
                        if not eid:
                            continue
                        if eid not in stored_evidence_ids:
                            import_completed = False
                            import_errors.append(f"missing_evidence_object:{eid}")
                        elif eid not in evidence_with_views:
                            import_completed = False
                            import_errors.append(f"missing_evidence_view:{eid}")

    return child_stopped, unconfirmed_pids, import_completed, import_errors


def build_server_from_env(
    env: Mapping[str, str] | None = None,
    *,
    config_path: str | Path | None = None,
    allow_ephemeral_cursor_key: bool = False,
) -> HarnessMcpServer:
    """Build a fail-closed HarnessController + HarnessMcpServer from environment config."""
    eff_env = env if env is not None else os.environ
    settings = load_runtime_settings(eff_env)
    if settings.db_path is None or settings.vault_root is None:
        raise ConfigurationError(
            "CTF_MCP_DB_PATH and CTF_MCP_VAULT_ROOT must be configured."
        )
    config: HarnessConfig | None = load_config_file(config_path) if config_path else None
    if config is not None and not str(eff_env.get("CTF_MCP_PROFILE", "")).strip():
        settings = settings.model_copy(update={"profile": config.profile})
    hmac_key = get_cursor_hmac_key(
        eff_env, allow_ephemeral_dev_key=allow_ephemeral_cursor_key
    )
    storage = Storage(settings.db_path)
    export_root = settings.vault_root / "_exports"
    controller = create_default_controller(
        storage=storage,
        vault_root=settings.vault_root,
        export_root=export_root,
        cursor_hmac_key=hmac_key,
        config=config,
        runtime_settings=settings,
        allow_synthetic_adapters=False,
        initialize=True,
        enable_local_verifier=False,
    )
    if controller.config is not None:
        if controller.config.acceptance.require_registered_verifier:
            register_default_verifier(controller)
    else:
        register_default_verifier(controller)
    return create_mcp_server(
        controller,
        transport_mode=settings.transport,
        runtime_settings=settings,
    )


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entrypoint supporting stdio and authenticated streamable-http transports."""
    parser = argparse.ArgumentParser(description="CTF/VDP Analysis Harness FastMCP Server")
    parser.add_argument("--config", type=Path, default=None, help="Optional validated HarnessConfig JSON")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host for streamable-http")
    parser.add_argument("--port", type=int, default=8000, help="Bind port for streamable-http")
    parser.add_argument("--path", default="/mcp", help="MCP endpoint path for streamable-http")
    args = parser.parse_args(list(argv) if argv is not None else None)

    server = build_server_from_env(config_path=args.config)
    server.run(host=args.host, port=args.port, path=args.path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
