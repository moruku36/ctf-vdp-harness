"""Scoped network policy guard and DNS-pinning URL/redirect validator (CTF-09).

Prevents SSRF, userinfo confusion, scheme/port/path smuggling, private/loopback/
link-local/metadata/IPv6-mapped IP access, DNS rebinding, and unvalidated HTTP
3xx redirects.
"""

from __future__ import annotations

import ipaddress
import posixpath
import re
import socket
import urllib.parse
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from ctf_mcp.contracts import ExecutionClass, RunMode, ScopeDeniedError, ScopePolicy

IpAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

DEFAULT_ALLOWED_METHODS: frozenset[str] = frozenset({"GET", "HEAD"})
SUPPORTED_PROBE_METHODS: frozenset[str] = frozenset({"GET", "HEAD", "OPTIONS"})
SUPPORTED_SCHEMES: frozenset[str] = frozenset({"http", "https"})
DEFAULT_PORTS: dict[str, int] = {"http": 80, "https": 443}
MAX_REDIRECT_HOPS = 5

_IPV4_CGNAT = ipaddress.IPv4Network("100.64.0.0/10")
_IPV4_METADATA = ipaddress.IPv4Network("169.254.0.0/16")
_IPV4_ZERO = ipaddress.IPv4Network("0.0.0.0/8")
_IPV6_ULA = ipaddress.IPv6Network("fc00::/7")
_IPV6_LINK_LOCAL = ipaddress.IPv6Network("fe80::/10")
_IPV6_AWS_METADATA = ipaddress.IPv6Address("fd00:ec2::254")


def _default_clock() -> datetime:
    return datetime.now(UTC)


def _default_dns_resolver(host: str, port: int) -> list[Any]:
    return socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)


@dataclass(frozen=True)
class AllowedTargetRule:
    """Parsed scoped network target entry derived from ``ScopePolicy.allowed_targets``."""

    raw_spec: str
    scheme: str
    host: str
    port: int
    path_prefix: str
    methods: frozenset[str]
    explicit_allowed_ips: frozenset[IpAddress]
    strict_ip_binding: bool


@dataclass(frozen=True)
class PinnedNetworkTarget:
    """Validated, DNS-pinned HTTP target approved for a single hop."""

    url: str
    scheme: str
    host: str
    port: int
    pinned_ip: str
    ip_version: int
    resolved_ips: tuple[str, ...]
    host_header: str
    server_hostname: str
    request_target: str
    method: str
    scope_revision: str


def _contains_forbidden_url_chars(raw: str) -> bool:
    for ch in raw:
        code = ord(ch)
        if code <= 0x20 or code == 0x7F:
            return True
    return False


def _is_unconditionally_banned_ip(ip: IpAddress) -> bool:
    """Addresses that are NEVER permitted regardless of target rule annotations."""
    if ip.is_multicast or ip.is_unspecified:
        return True
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None or ip.sixtofour is not None or ip.teredo is not None:
            return True
        if ip in _IPV6_LINK_LOCAL or ip == _IPV6_AWS_METADATA:
            return True
    else:
        if ip in _IPV4_METADATA or ip in _IPV4_ZERO:
            return True
    return False


def _is_globally_non_public_ip(ip: IpAddress) -> bool:
    """Return True if ``ip`` is non-public (loopback, RFC1918, ULA, CGNAT, reserved, etc.)."""
    if _is_unconditionally_banned_ip(ip):
        return True
    if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved:
        return True
    if isinstance(ip, ipaddress.IPv4Address):
        if ip in _IPV4_CGNAT:
            return True
    else:
        if ip in _IPV6_ULA or ip.is_site_local:
            return True
    return not ip.is_global


_NUMERIC_LABEL_RE = re.compile(r"^(?:0[xX][0-9a-fA-F]+|0[0-7]+|[0-9]+)$")


def _parse_ip_literal(host: str) -> IpAddress | None:
    """Parse canonical IPv4/IPv6 literal, rejecting non-canonical octal/hex/int tricks."""
    stripped = host
    if stripped.startswith("[") and stripped.endswith("]"):
        stripped = stripped[1:-1]
    if "%" in stripped:
        raise ScopeDeniedError(
            "IPv6 zone identifiers are forbidden in scoped URLs",
            code="ip_zone_forbidden",
        )
    try:
        return ipaddress.ip_address(stripped)
    except ValueError:
        pass

    # Reject integer, hex, and ambiguous octal/partial IPv4 shorthands (e.g., 2130706433, 0x7f000001, 0177.0.0.1, 127.1).
    if stripped.isdigit() or stripped.lower().startswith("0x"):
        raise ScopeDeniedError(
            f"Non-canonical numeric host {host!r} is forbidden",
            code="invalid_host",
        )
    parts = stripped.split(".")
    if parts and all(_NUMERIC_LABEL_RE.match(p) for p in parts if p != ""):
        raise ScopeDeniedError(
            f"Ambiguous numeric/octal IPv4 host {host!r} is forbidden",
            code="invalid_host",
        )
    return None


def _normalize_host(raw_host: str | None) -> tuple[str, IpAddress | None]:
    """Normalize host (lowercase, trailing dots stripped, IDNA ASCII, canonical IP)."""
    if not raw_host:
        raise ScopeDeniedError("Target URL is missing a host", code="invalid_url")
    candidate = raw_host.strip()
    if not candidate or candidate != raw_host:
        raise ScopeDeniedError("Target URL host contains invalid whitespace", code="invalid_url")
    if "@" in candidate or "/" in candidate or "\\" in candidate:
        raise ScopeDeniedError("Target URL host contains forbidden delimiter", code="invalid_url")

    ip_lit = _parse_ip_literal(candidate)
    if ip_lit is not None:
        if _is_unconditionally_banned_ip(ip_lit):
            raise ScopeDeniedError(
                f"Target IP literal {ip_lit} is unconditionally forbidden",
                code="ip_scope_denied",
            )
        return str(ip_lit), ip_lit

    trimmed = candidate.rstrip(".")
    if not trimmed or ".." in trimmed:
        raise ScopeDeniedError(f"Malformed domain host {raw_host!r}", code="invalid_host")
    # Re-check trimmed for numeric/octal tricks like `127.0.0.1.` or `2130706433.`
    ip_after_trim = _parse_ip_literal(trimmed)
    if ip_after_trim is not None:
        if _is_unconditionally_banned_ip(ip_after_trim):
            raise ScopeDeniedError(
                f"Target IP literal {ip_after_trim} is unconditionally forbidden",
                code="ip_scope_denied",
            )
        return str(ip_after_trim), ip_after_trim

    try:
        ascii_host = trimmed.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ScopeDeniedError(
            f"Invalid IDNA hostname {raw_host!r}: {exc}",
            code="invalid_host",
        ) from exc
    if not ascii_host or _contains_forbidden_url_chars(ascii_host):
        raise ScopeDeniedError(f"Unsafe hostname {raw_host!r}", code="invalid_host")
    return ascii_host, None


def _normalize_path(raw_path: str) -> str:
    """Normalize HTTP path and resolve dot segments safely without trailing slash confusion."""
    if "\\" in raw_path:
        raise ScopeDeniedError("Backslashes are forbidden in URL path", code="invalid_url")
    if not raw_path:
        return "/"
    had_trailing = raw_path.endswith("/")
    decoded_check = urllib.parse.unquote(raw_path)
    if "\\" in decoded_check or "\x00" in decoded_check:
        raise ScopeDeniedError("Encoded path traversal delimiter is forbidden", code="invalid_url")
    # Also check encoded dot segments like /%2e%2e/
    norm_input = raw_path.replace("/%2e%2e", "/..").replace("/%2E%2E", "/..")
    normalized = posixpath.normpath(norm_input)
    normalized = re.sub(r"/+", "/", normalized)
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    if had_trailing and normalized != "/" and not normalized.endswith("/"):
        normalized += "/"
    return normalized


def _parse_url_strict(url: str) -> tuple[str, str, IpAddress | None, int, str, str, str]:
    """Strictly parse and normalize a target URL, rejecting authority smuggling."""
    if not isinstance(url, str) or not url:
        raise ScopeDeniedError("URL must be a non-empty string", code="invalid_url")
    if _contains_forbidden_url_chars(url):
        raise ScopeDeniedError(
            "URL contains forbidden whitespace or control characters",
            code="invalid_url",
        )

    pre_query = url.split("?", 1)[0].split("#", 1)[0]
    if "\\" in pre_query:
        raise ScopeDeniedError("URL contains forbidden backslash in authority/path", code="invalid_url")

    split = urllib.parse.urlsplit(url)
    scheme = split.scheme.lower()
    if scheme not in SUPPORTED_SCHEMES:
        raise ScopeDeniedError(
            f"URL scheme {split.scheme!r} is forbidden (only http/https permitted)",
            code="scheme_denied",
        )
    if not split.netloc:
        raise ScopeDeniedError("URL missing network authority", code="invalid_url")
    if (
        "@" in split.netloc
        or "%40" in split.netloc.lower()
        or split.username is not None
        or split.password is not None
    ):
        raise ScopeDeniedError(
            "Userinfo in URL authority is unconditionally forbidden",
            code="userinfo_forbidden",
        )

    try:
        port = split.port
    except ValueError as exc:
        raise ScopeDeniedError(f"Invalid port in URL: {exc}", code="invalid_url") from exc
    resolved_port = DEFAULT_PORTS[scheme] if port is None else int(port)
    if not (1 <= resolved_port <= 65535):
        raise ScopeDeniedError(f"Port {resolved_port} out of range", code="invalid_url")

    norm_host, host_ip = _normalize_host(split.hostname)
    norm_path = _normalize_path(split.path)

    host_fmt = f"[{norm_host}]" if isinstance(host_ip, ipaddress.IPv6Address) else norm_host
    host_header = (
        host_fmt if resolved_port == DEFAULT_PORTS[scheme] else f"{host_fmt}:{resolved_port}"
    )
    request_target = f"{norm_path}?{split.query}" if split.query else norm_path
    canonical_url = f"{scheme}://{host_header}{request_target}"
    return scheme, norm_host, host_ip, resolved_port, norm_path, host_header, canonical_url


def _parse_allowed_target_rule(spec: str) -> AllowedTargetRule:
    """Parse one `ScopePolicy.allowed_targets` entry.

    Supported syntax:
      - ``http://127.0.0.1:8080/api``
      - ``http://[::1]:8080/api``
      - ``http://fixture.test:8080/api|ip=127.0.0.1|methods=GET,HEAD``
    """
    parts = [p.strip() for p in spec.split("|") if p.strip()]
    if not parts:
        raise ScopeDeniedError("Empty target rule in scope policy", code="scope_denied")
    url_part = parts[0]
    scheme, norm_host, host_ip, port, norm_path, _hh, _cu = _parse_url_strict(url_part)

    methods: frozenset[str] = DEFAULT_ALLOWED_METHODS
    explicit_ips: set[IpAddress] = set()
    if host_ip is not None:
        explicit_ips.add(host_ip)

    for attr in parts[1:]:
        if "=" not in attr:
            raise ScopeDeniedError(f"Invalid target rule modifier {attr!r}", code="scope_denied")
        key, value = attr.split("=", 1)
        key = key.strip().lower()
        value = value.strip()
        if key in {"ip", "ips"}:
            for item in value.split(","):
                ip_str = item.strip()
                if not ip_str:
                    continue
                ip_obj = _parse_ip_literal(ip_str)
                if ip_obj is None or _is_unconditionally_banned_ip(ip_obj):
                    raise ScopeDeniedError(
                        f"Invalid or forbidden explicit scope IP {ip_str!r}",
                        code="scope_denied",
                    )
                explicit_ips.add(ip_obj)
        elif key == "methods":
            parsed_methods = {m.strip().upper() for m in value.split(",") if m.strip()}
            if not parsed_methods or not parsed_methods.issubset(SUPPORTED_PROBE_METHODS):
                raise ScopeDeniedError(
                    f"Unsupported target rule HTTP methods {value!r}",
                    code="method_denied",
                )
            methods = frozenset(parsed_methods)
        else:
            raise ScopeDeniedError(
                f"Unknown target rule modifier {key!r}",
                code="scope_denied",
            )

    strict_binding = bool(explicit_ips)
    return AllowedTargetRule(
        raw_spec=spec,
        scheme=scheme,
        host=norm_host,
        port=port,
        path_prefix=norm_path,
        methods=methods,
        explicit_allowed_ips=frozenset(explicit_ips),
        strict_ip_binding=strict_binding,
    )


def _path_matches_prefix(request_path: str, prefix: str) -> bool:
    """Check HTTP path prefix on clean segment boundaries."""
    if prefix == "/":
        return request_path.startswith("/")
    clean_prefix = prefix.rstrip("/")
    clean_req = request_path.rstrip("/") or "/"
    return clean_req == clean_prefix or request_path.startswith(clean_prefix + "/")


def _extract_resolved_ips(raw_records: Sequence[Any]) -> list[IpAddress]:
    """Normalize outputs from either ``socket.getaddrinfo`` or test mock resolvers."""
    ips: list[IpAddress] = []
    seen: set[IpAddress] = set()
    for item in raw_records:
        raw_ip: str
        if isinstance(item, str):
            raw_ip = item
        elif isinstance(item, (tuple, list)) and len(item) >= 5 and isinstance(item[4], (tuple, list)):
            raw_ip = str(item[4][0])
        elif isinstance(item, (tuple, list)) and len(item) >= 1 and isinstance(item[0], str):
            raw_ip = item[0]
        else:
            raise ScopeDeniedError(
                f"Unrecognized DNS resolver record format: {item!r}",
                code="dns_resolution_failed",
            )
        ip_obj = _parse_ip_literal(raw_ip)
        if ip_obj is None:
            raise ScopeDeniedError(
                f"DNS resolver returned non-IP value {raw_ip!r}",
                code="dns_resolution_failed",
            )
        if ip_obj not in seen:
            seen.add(ip_obj)
            ips.append(ip_obj)
    return ips


class ScopedNetworkPolicyGuard:
    """Layer-2 gateway guard enforcing host/port/path/method/DNS/IP pinning & redirects."""

    def __init__(
        self,
        *,
        dns_resolver: Callable[[str, int], Sequence[Any]] | None = None,
        scope_provider: Callable[[str], ScopePolicy | None] | None = None,
        explicit_host_ips: dict[str, Sequence[str]] | None = None,
        allowed_methods: frozenset[str] = DEFAULT_ALLOWED_METHODS,
        max_redirects: int = MAX_REDIRECT_HOPS,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._dns_resolver = dns_resolver or _default_dns_resolver
        self._scope_provider = scope_provider
        self._clock = clock or _default_clock
        self._max_redirects = max(0, int(max_redirects))
        if not allowed_methods or not allowed_methods.issubset(SUPPORTED_PROBE_METHODS):
            raise ValueError(f"Unsupported allowed_methods: {allowed_methods!r}")
        self._allowed_methods = allowed_methods

        normalized_explicit: dict[str, frozenset[IpAddress]] = {}
        if explicit_host_ips:
            for host_key, ip_list in explicit_host_ips.items():
                norm_h, _ = _normalize_host(host_key)
                parsed_ips: set[IpAddress] = set()
                for ip_str in ip_list:
                    ip_obj = _parse_ip_literal(ip_str)
                    if ip_obj is None or _is_unconditionally_banned_ip(ip_obj):
                        raise ScopeDeniedError(
                            f"Forbidden IP {ip_str!r} in explicit_host_ips",
                            code="ip_scope_denied",
                        )
                    parsed_ips.add(ip_obj)
                normalized_explicit[norm_h] = frozenset(parsed_ips)
        self._explicit_host_ips = normalized_explicit

    def resolve_live_policy(
        self,
        *,
        policy: ScopePolicy | None = None,
        run_id: str | None = None,
    ) -> ScopePolicy:
        """Load the freshest live ``ScopePolicy`` available for ``run_id``."""
        if run_id is not None and self._scope_provider is not None:
            live = self._scope_provider(run_id)
            if live is not None:
                return live
        if policy is not None:
            return policy
        raise ScopeDeniedError(
            "No active ScopePolicy is available for network probe",
            code="scope_missing",
        )

    def _validate_policy_active(self, policy: ScopePolicy, *, now: datetime) -> None:
        if policy.mode not in (RunMode.SCOPED_CTF, RunMode.VDP):
            raise ScopeDeniedError(
                f"Network access is forbidden in run mode {policy.mode.value!r}",
                code="network_disabled_in_mode",
            )
        if ExecutionClass.NETWORK not in policy.allowed_execution_classes:
            raise ScopeDeniedError(
                "Scope policy does not permit NETWORK execution class",
                code="execution_class_denied",
            )
        if not policy.network_enabled:
            raise ScopeDeniedError(
                "Network access is disabled in run ScopePolicy",
                code="network_disabled",
            )
        if getattr(policy, "revoked_at", None) is not None:
            raise ScopeDeniedError(
                "Run scope has been revoked",
                code="scope_revoked",
                details={"scope_revision": policy.scope_revision},
            )
        expires_at = (
            policy.expires_at
            if policy.expires_at.tzinfo is not None
            else policy.expires_at.replace(tzinfo=UTC)
        )
        if now >= expires_at:
            raise ScopeDeniedError(
                "Run scope has expired",
                code="scope_expired",
                details={"scope_revision": policy.scope_revision},
            )
        if not policy.allowed_targets:
            raise ScopeDeniedError(
                "Scope policy specifies no allowed_targets",
                code="scope_denied",
            )

    def validate_and_resolve(
        self,
        url: str,
        *,
        method: str = "GET",
        policy: ScopePolicy | None = None,
        run_id: str | None = None,
        now: datetime | None = None,
    ) -> PinnedNetworkTarget:
        """Validate URL/method/policy and resolve+pin DNS IPs before connecting."""
        current_time = now or self._clock()
        if current_time.tzinfo is None:
            current_time = current_time.replace(tzinfo=UTC)

        active_policy = self.resolve_live_policy(policy=policy, run_id=run_id)
        self._validate_policy_active(active_policy, now=current_time)

        norm_method = str(method or "").strip().upper()
        if norm_method not in self._allowed_methods:
            raise ScopeDeniedError(
                f"HTTP method {method!r} is not permitted",
                code="method_denied",
            )

        scheme, norm_host, host_ip, port, norm_path, host_header, canonical_url = (
            _parse_url_strict(url)
        )

        # Match normalized URL against parsed ScopePolicy.allowed_targets.
        rules = [_parse_allowed_target_rule(spec) for spec in active_policy.allowed_targets]
        matching_rules = [
            rule
            for rule in rules
            if rule.scheme == scheme
            and rule.host == norm_host
            and rule.port == port
            and _path_matches_prefix(norm_path, rule.path_prefix)
        ]
        if not matching_rules:
            raise ScopeDeniedError(
                f"Target {canonical_url!r} is outside allowed_targets",
                code="target_out_of_scope",
                details={"url": canonical_url, "scope_revision": active_policy.scope_revision},
            )

        method_matched = [r for r in matching_rules if norm_method in r.methods]
        if not method_matched:
            raise ScopeDeniedError(
                f"Method {norm_method!r} is not allowed for target {canonical_url!r}",
                code="method_denied",
            )
        rule = method_matched[0]

        try:
            dns_records = self._dns_resolver(norm_host, port)
        except ScopeDeniedError:
            raise
        except OSError as exc:
            raise ScopeDeniedError(
                f"DNS resolution failed for {norm_host!r}: {exc}",
                code="dns_resolution_failed",
            ) from exc

        resolved_ips = _extract_resolved_ips(dns_records)
        if not resolved_ips:
            raise ScopeDeniedError(
                f"DNS resolution returned no addresses for {norm_host!r}",
                code="dns_resolution_empty",
            )

        extra_host_ips = self._explicit_host_ips.get(norm_host, frozenset())
        explicit_ips = rule.explicit_allowed_ips | extra_host_ips

        for ip_obj in resolved_ips:
            if _is_unconditionally_banned_ip(ip_obj):
                raise ScopeDeniedError(
                    f"Resolved IP {ip_obj} is unconditionally forbidden",
                    code="ip_scope_denied",
                    details={"ip": str(ip_obj), "host": norm_host},
                )
            if host_ip is not None and ip_obj != host_ip:
                raise ScopeDeniedError(
                    f"Resolved IP {ip_obj} mismatches literal target IP {host_ip}",
                    code="dns_rebinding_denied",
                    details={"ip": str(ip_obj), "expected_ip": str(host_ip)},
                )
            if explicit_ips:
                if ip_obj not in explicit_ips:
                    if _is_globally_non_public_ip(ip_obj):
                        raise ScopeDeniedError(
                            f"Resolved IP {ip_obj} is forbidden and not in explicit scoped IPs",
                            code="ip_scope_denied",
                            details={"ip": str(ip_obj), "host": norm_host},
                        )
                    raise ScopeDeniedError(
                        f"DNS resolved IP {ip_obj} diverges from pinned scope binding",
                        code="dns_rebinding_denied",
                        details={"ip": str(ip_obj), "host": norm_host},
                    )
            elif _is_globally_non_public_ip(ip_obj):
                raise ScopeDeniedError(
                    f"Resolved non-public IP {ip_obj} is outside allowed scope",
                    code="ip_scope_denied",
                    details={"ip": str(ip_obj), "host": norm_host},
                )

        pinned = resolved_ips[0]
        split = urllib.parse.urlsplit(canonical_url)
        request_target = f"{split.path or '/'}{'?' + split.query if split.query else ''}"
        return PinnedNetworkTarget(
            url=canonical_url,
            scheme=scheme,
            host=norm_host,
            port=port,
            pinned_ip=str(pinned),
            ip_version=pinned.version,
            resolved_ips=tuple(str(x) for x in resolved_ips),
            host_header=host_header,
            server_hostname=norm_host,
            request_target=request_target,
            method=norm_method,
            scope_revision=active_policy.scope_revision,
        )

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
        now: datetime | None = None,
    ) -> PinnedNetworkTarget:
        """Re-validate scope, URL, and DNS resolution on a single HTTP redirect hop."""
        hop_cap = self._max_redirects if max_redirects is None else int(max_redirects)
        if hop_index > hop_cap:
            raise ScopeDeniedError(
                f"Maximum redirect count ({hop_cap}) exceeded",
                code="redirect_limit_exceeded",
            )
        if not isinstance(location, str) or not location.strip():
            raise ScopeDeniedError(
                "HTTP redirect missing Location header",
                code="invalid_redirect",
            )
        cleaned_loc = location.strip()
        if _contains_forbidden_url_chars(cleaned_loc):
            raise ScopeDeniedError(
                "Redirect Location contains forbidden control/whitespace characters",
                code="invalid_redirect",
            )

        next_url = urllib.parse.urljoin(current_url, cleaned_loc)
        next_method = original_method.upper()
        if status_code in (301, 302, 303) and next_method != "HEAD":
            next_method = "GET"

        return self.validate_and_resolve(
            next_url,
            method=next_method,
            policy=policy,
            run_id=run_id,
            now=now,
        )
