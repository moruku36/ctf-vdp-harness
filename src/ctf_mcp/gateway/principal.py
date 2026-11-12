"""Gateway principal authentication and transport identity binding.

Enforces fail-closed authentication for HTTP transports (``docs/01`` N6,
``docs/02`` section 4.2, ``docs/05`` section 3) and constructs validated local
``PrincipalContext`` identities for ``stdio`` sessions.
"""

from __future__ import annotations

import hashlib
import hmac
from datetime import UTC, datetime

from pydantic import Field

from ctf_mcp.config import PLACEHOLDER_PREFIXES, RuntimeSettings
from ctf_mcp.contracts import (
    SHA256_PATTERN,
    AuthenticationError,
    PrincipalContext,
    StrictModel,
    TransportMode,
)


def _is_placeholder_secret(value: str) -> bool:
    stripped = value.strip()
    if not stripped:
        return True
    upper = stripped.upper()
    return any(upper.startswith(prefix) for prefix in PLACEHOLDER_PREFIXES)


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def extract_bearer_token(authorization: str | None) -> str:
    """Parse an HTTP ``Authorization: Bearer <token>`` header strictly."""
    if authorization is None or not authorization.strip():
        raise AuthenticationError("Missing Authorization header.")
    parts = authorization.strip().split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise AuthenticationError("Authorization header must use Bearer scheme.")
    token = parts[1].strip()
    if not token or any(ch.isspace() for ch in token):
        raise AuthenticationError("Bearer token is malformed or empty.")
    return token


class TokenBinding(StrictModel):
    """Registered token hash bound to a principal identity (never stores raw secret)."""

    token_sha256: str = Field(pattern=SHA256_PATTERN)
    principal: PrincipalContext
    expires_at: datetime | None = None
    revoked: bool = False


class PrincipalAuthenticator:
    """Fail-closed gateway authenticator for HTTP Bearer and local stdio paths."""

    def __init__(self, *, require_token_for_stdio: bool = False) -> None:
        self._bindings: dict[str, TokenBinding] = {}
        self._require_token_for_stdio = require_token_for_stdio

    @classmethod
    def from_runtime_settings(
        cls,
        settings: RuntimeSettings,
        *,
        principal_id: str = "local-operator",
        client_kind: str = "OPERATOR_SELECTED",
        model_label: str = "RECORD_ACTUAL_UI_LABEL",
        require_token_for_stdio: bool = False,
    ) -> PrincipalAuthenticator:
        """Build an authenticator from validated ``RuntimeSettings``."""
        auth = cls(require_token_for_stdio=require_token_for_stdio)
        if settings.auth_token is not None:
            secret_value = settings.auth_token.get_secret_value()
            if not _is_placeholder_secret(secret_value):
                auth.register_token(
                    secret_value,
                    PrincipalContext(
                        principal_id=principal_id,
                        auth_method="bearer_token",
                        client_kind=client_kind,
                        model_label=model_label,
                    ),
                )
        return auth

    def register_token(
        self,
        token: str,
        principal: PrincipalContext,
        *,
        expires_at: datetime | None = None,
    ) -> None:
        """Register a non-placeholder credential bound to ``principal``."""
        stripped = token.strip()
        if not stripped or _is_placeholder_secret(stripped):
            raise AuthenticationError("Cannot register empty or placeholder auth token.")
        if any(ch.isspace() for ch in stripped):
            raise AuthenticationError("Auth token cannot contain whitespace.")
        digest = _hash_token(stripped)
        self._bindings[digest] = TokenBinding(
            token_sha256=digest,
            principal=principal,
            expires_at=_ensure_utc(expires_at) if expires_at is not None else None,
            revoked=False,
        )

    def revoke_token(self, token: str) -> bool:
        """Revoke a specific credential token."""
        digest = _hash_token(token.strip())
        binding = self._bindings.get(digest)
        if binding is None:
            return False
        self._bindings[digest] = binding.model_copy(update={"revoked": True})
        return True

    def revoke_principal(self, principal_id: str) -> int:
        """Revoke all tokens bound to ``principal_id``."""
        revoked_count = 0
        for digest, binding in list(self._bindings.items()):
            if binding.principal.principal_id == principal_id and not binding.revoked:
                self._bindings[digest] = binding.model_copy(update={"revoked": True})
                revoked_count += 1
        return revoked_count

    def authenticate_token(
        self,
        token: str | None,
        *,
        now: datetime | None = None,
    ) -> PrincipalContext:
        """Verify a raw Bearer/API token in constant time (fail closed)."""
        if token is None or not token.strip() or _is_placeholder_secret(token):
            raise AuthenticationError("Missing or placeholder authentication token.")
        candidate_digest = _hash_token(token.strip())

        matched_binding: TokenBinding | None = None
        for registered_digest, binding in self._bindings.items():
            if hmac.compare_digest(candidate_digest, registered_digest):
                matched_binding = binding

        if matched_binding is None:
            raise AuthenticationError("Invalid authentication token.")
        if matched_binding.revoked:
            raise AuthenticationError("Authentication token has been revoked.")

        current_time = _ensure_utc(now) if now is not None else datetime.now(UTC)
        if matched_binding.expires_at is not None and current_time >= matched_binding.expires_at:
            raise AuthenticationError("Authentication token has expired.")
        return matched_binding.principal

    def authenticate_bearer(
        self,
        authorization: str | None,
        *,
        now: datetime | None = None,
    ) -> PrincipalContext:
        """Verify an HTTP ``Authorization: Bearer <token>`` header."""
        token = extract_bearer_token(authorization)
        return self.authenticate_token(token, now=now)

    def authenticate_stdio(
        self,
        *,
        principal_id: str,
        client_kind: str = "OPERATOR_SELECTED",
        model_label: str = "RECORD_ACTUAL_UI_LABEL",
        token: str | None = None,
        now: datetime | None = None,
    ) -> PrincipalContext:
        """Construct or verify a local ``stdio`` principal identity."""
        clean_principal = principal_id.strip()
        clean_client = client_kind.strip()
        clean_model = model_label.strip()
        if not clean_principal or not clean_client or not clean_model:
            raise AuthenticationError("stdio principal requires non-empty identity metadata.")

        if self._require_token_for_stdio or token is not None:
            verified = self.authenticate_token(token, now=now)
            if verified.principal_id != clean_principal:
                raise AuthenticationError("stdio principal_id does not match token binding.")
            return verified

        return PrincipalContext(
            principal_id=clean_principal,
            auth_method="stdio_local",
            client_kind=clean_client,
            model_label=clean_model,
        )

    def authenticate(
        self,
        transport: TransportMode,
        *,
        authorization: str | None = None,
        token: str | None = None,
        stdio_principal_id: str | None = None,
        client_kind: str = "OPERATOR_SELECTED",
        model_label: str = "RECORD_ACTUAL_UI_LABEL",
        now: datetime | None = None,
    ) -> PrincipalContext:
        """Authenticate a gateway request according to its active ``TransportMode``."""
        if transport == TransportMode.STREAMABLE_HTTP:
            if authorization is not None:
                return self.authenticate_bearer(authorization, now=now)
            if token is not None:
                return self.authenticate_token(token, now=now)
            raise AuthenticationError("Streamable HTTP transport requires authentication.")

        if transport == TransportMode.STDIO:
            if stdio_principal_id is None:
                raise AuthenticationError("stdio transport requires stdio_principal_id.")
            return self.authenticate_stdio(
                principal_id=stdio_principal_id,
                client_kind=client_kind,
                model_label=model_label,
                token=token,
                now=now,
            )

        raise AuthenticationError(f"Unsupported transport mode: {transport!r}")


__all__ = [
    "PrincipalAuthenticator",
    "TokenBinding",
    "extract_bearer_token",
]
