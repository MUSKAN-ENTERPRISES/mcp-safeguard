"""Scan MCP server endpoints for exposed admin panels, debug routes, and misconfigurations."""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass

import httpx

from mcp_shield import __version__

from .prompt_injection import Severity

_METADATA_IPS = {"169.254.169.254", "fd00:ec2::254"}
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
]


@dataclass
class EndpointFinding:
    """A finding from endpoint/network scanning."""
    rule_id: str
    severity: Severity
    title: str
    description: str
    location: str
    evidence: str
    remediation: str
    cvss_score: float = 0.0
    status_code: int | None = None


_SENSITIVE_PATHS: list[tuple[str, Severity, str, str, float]] = [
    ("/admin", Severity.HIGH, "EP-001", "Exposed Admin Panel", 8.0),
    ("/admin/", Severity.HIGH, "EP-001", "Exposed Admin Panel", 8.0),
    ("/_admin", Severity.HIGH, "EP-001", "Exposed Admin Panel", 8.0),
    ("/debug", Severity.HIGH, "EP-002", "Exposed Debug Endpoint", 7.5),
    ("/debug/", Severity.HIGH, "EP-002", "Exposed Debug Endpoint", 7.5),
    ("/__debug__", Severity.HIGH, "EP-002", "Exposed Debug Endpoint", 7.5),
    ("/health", Severity.INFO, "EP-003", "Health Endpoint (check response content)", 2.0),
    ("/healthz", Severity.INFO, "EP-003", "Health Endpoint", 2.0),
    ("/ready", Severity.INFO, "EP-003", "Readiness Endpoint", 2.0),
    ("/metrics", Severity.MEDIUM, "EP-004", "Prometheus Metrics Exposed Publicly", 5.5),
    ("/_metrics", Severity.MEDIUM, "EP-004", "Prometheus Metrics Exposed", 5.5),
    ("/docs", Severity.LOW, "EP-005", "API Documentation Exposed", 3.5),
    ("/swagger", Severity.LOW, "EP-005", "Swagger UI Exposed", 3.5),
    ("/swagger-ui", Severity.LOW, "EP-005", "Swagger UI Exposed", 3.5),
    ("/redoc", Severity.LOW, "EP-005", "ReDoc Documentation Exposed", 3.5),
    ("/openapi.json", Severity.MEDIUM, "EP-006", "OpenAPI Schema Exposed", 4.5),
    ("/config", Severity.HIGH, "EP-007", "Configuration Endpoint Exposed", 8.5),
    ("/.env", Severity.CRITICAL, "EP-008", "Environment File Exposed", 9.5),
    ("/env", Severity.HIGH, "EP-007", "Environment Endpoint Exposed", 8.0),
    ("/mcp", Severity.INFO, "EP-009", "MCP Endpoint (verify auth required)", 2.5),
    ("/sse", Severity.MEDIUM, "EP-010", "SSE Endpoint (verify auth)", 4.5),
    ("/ws", Severity.MEDIUM, "EP-010", "WebSocket Endpoint (verify auth)", 4.5),
    ("/actuator", Severity.HIGH, "EP-011", "Spring Actuator Exposed", 8.5),
    ("/actuator/env", Severity.CRITICAL, "EP-011", "Spring Actuator Env Exposed", 9.5),
    ("/actuator/heapdump", Severity.CRITICAL, "EP-011", "Spring Actuator Heap Dump", 9.8),
    ("/version", Severity.LOW, "EP-012", "Version Disclosure", 3.0),
    ("/_version", Severity.LOW, "EP-012", "Version Disclosure", 3.0),
    ("/trace", Severity.HIGH, "EP-013", "Trace Endpoint Exposed", 7.0),
    ("/pprof", Severity.HIGH, "EP-013", "Go pprof Profiler Exposed", 7.5),
]

_RESPONSE_LEAK_PATTERNS: list[tuple[str, Severity, str, float]] = [
    (r"(?i)stack\s*trace", Severity.HIGH, "EP-RESP-001", 7.0),
    (r"(?i)(internal\s+server\s+error|traceback|exception\s+in)", Severity.HIGH, "EP-RESP-002", 7.5),
    (r"(?i)(db_pass|database_url|secret_key|api_key)\s*[=:]", Severity.CRITICAL, "EP-RESP-003", 9.5),
    (r"(?i)version\s*:\s*\d+\.\d+", Severity.LOW, "EP-RESP-004", 3.0),
    (r"(?i)(root|admin|superuser)@", Severity.HIGH, "EP-RESP-005", 7.0),
]

_DANGEROUS_PORTS: list[tuple[int, str, Severity, str, float]] = [
    (22, "SSH", Severity.MEDIUM, "EP-PORT-001", 5.0),
    (23, "Telnet", Severity.HIGH, "EP-PORT-002", 8.0),
    (2375, "Docker API (unauthenticated)", Severity.CRITICAL, "EP-PORT-003", 10.0),
    (2376, "Docker API (TLS)", Severity.HIGH, "EP-PORT-004", 7.5),
    (4040, "Ngrok Inspection UI", Severity.MEDIUM, "EP-PORT-005", 5.5),
    (5000, "Development Server", Severity.MEDIUM, "EP-PORT-006", 5.0),
    (5432, "PostgreSQL", Severity.HIGH, "EP-PORT-007", 8.0),
    (6379, "Redis (commonly unauthenticated)", Severity.HIGH, "EP-PORT-008", 9.0),
    (8080, "HTTP Alt / Dev Server", Severity.LOW, "EP-PORT-009", 3.5),
    (8443, "HTTPS Alt", Severity.LOW, "EP-PORT-010", 3.0),
    (9200, "Elasticsearch", Severity.CRITICAL, "EP-PORT-011", 9.5),
    (27017, "MongoDB", Severity.HIGH, "EP-PORT-012", 8.5),
]


def _is_ssrf_safe(host: str, allowlist: list[str] | None = None) -> bool:
    """Allow only literal IP addresses or localhost names.

    DNS names are deliberately rejected because validating a DNS answer and
    then connecting to the hostname creates a DNS-rebinding time-of-check /
    time-of-use window. Callers that need remote targets should provide the
    resolved, trusted IP address in the allowlist instead.
    """
    safe_patterns = allowlist or ["localhost", "127.0.0.1", "::1", "0.0.0.0"]
    if host not in safe_patterns:
        return False
    if host in {"localhost", "0.0.0.0"}:
        return host == "localhost" or host == "0.0.0.0"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return host == "localhost"
    if str(ip) in _METADATA_IPS or any(ip in network for network in _BLOCKED_NETWORKS):
        return False
    return True


def _resolve_safe_ip(host: str) -> str | None:
    """Resolve a literal target for validation; hostnames are not accepted."""
    if host == "localhost":
        return "127.0.0.1"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return None
    if str(ip) in _METADATA_IPS or any(ip in network for network in _BLOCKED_NETWORKS):
        return None
    return str(ip)


def _port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (TimeoutError, OSError):
        return False


async def scan_endpoints(
    host: str,
    port: int,
    use_tls: bool = False,
    timeout: float = 5.0,
    ssrf_allowlist: list[str] | None = None,
) -> list[EndpointFinding]:
    findings: list[EndpointFinding] = []

    if not _is_ssrf_safe(host, ssrf_allowlist):
        return [_ssrf_blocked_finding(host, port)]
    target_ip = _resolve_safe_ip(host)
    if not target_ip:
        return [_ssrf_blocked_finding(host, port)]

    scheme = "https" if use_tls else "http"
    base_url = f"{scheme}://{target_ip}:{port}"

    for check_port, service, severity, rule_id, cvss_score in _DANGEROUS_PORTS:
        if check_port != port and _port_open(target_ip, check_port):
            findings.append(EndpointFinding(
                rule_id=rule_id, severity=severity,
                title=f"Open Dangerous Port: {check_port} ({service})",
                description=f"Port {check_port} ({service}) is open on {target_ip}.",
                location=f"{target_ip}:{check_port}", evidence=f"TCP port {check_port} is open",
                remediation=f"Firewall port {check_port} if not needed. If {service} is required, ensure authentication is enabled.",
                cvss_score=cvss_score,
            ))

    async with httpx.AsyncClient(
        timeout=timeout,
        verify=True,
        follow_redirects=False,
        headers={"User-Agent": f"mcp-safeguard/{__version__} security-scanner"},
    ) as client:
        for path, severity, rule_id, title, cvss_score in _SENSITIVE_PATHS:
            try:
                response = await client.get(f"{base_url}{path}")
                status = response.status_code
                if status < 400:
                    body_preview = response.text[:500] if response.text else ""
                    final_severity = severity
                    for pattern, leak_sev, _leak_rule, leak_cvss in _RESPONSE_LEAK_PATTERNS:
                        if re.search(pattern, body_preview):
                            if leak_sev.value == "CRITICAL" or (leak_sev.value == "HIGH" and severity.value != "CRITICAL"):
                                final_severity = leak_sev
                                cvss_score = max(cvss_score, leak_cvss)
                    findings.append(EndpointFinding(
                        rule_id=rule_id, severity=final_severity, title=title,
                        description=f"Endpoint '{path}' returned HTTP {status} at {base_url}.",
                        location=f"{base_url}{path}", evidence=f"HTTP {status}: {body_preview[:200]}",
                        remediation=_get_endpoint_remediation(rule_id), cvss_score=cvss_score, status_code=status,
                    ))
            except (httpx.ConnectError, httpx.TimeoutException, httpx.TransportError):
                pass

    findings.sort(key=lambda f: f.cvss_score, reverse=True)
    return findings


def _ssrf_blocked_finding(host: str, port: int) -> EndpointFinding:
    return EndpointFinding(
        rule_id="EP-SSRF-001", severity=Severity.CRITICAL,
        title="SSRF Protection: Scan Target Blocked",
        description=f"Host '{host}' is not a safe literal scan target or resolves to a blocked address.",
        location=f"{host}:{port}", evidence=host,
        remediation="Only scan trusted literal IP addresses or localhost. Do not pass attacker-controlled DNS names as scan targets.",
        cvss_score=10.0,
    )


def _get_endpoint_remediation(rule_id: str) -> str:
    remediations = {
        "EP-001": "Restrict admin panel access to authenticated, authorized users only. Place behind VPN or IP allowlist.",
        "EP-002": "Disable debug endpoints in production. Set DEBUG=False and remove debug middleware.",
        "EP-003": "Ensure health endpoints don't expose sensitive configuration or internal state.",
        "EP-004": "Restrict /metrics to internal networks only. Do not expose Prometheus data publicly.",
        "EP-005": "Disable API documentation in production, or protect with authentication.",
        "EP-006": "Restrict OpenAPI schema access or remove in production deployments.",
        "EP-007": "Remove configuration endpoints. Never expose internal config over HTTP.",
        "EP-008": "Never serve .env files. Add to web server deny rules and .gitignore.",
        "EP-009": "Ensure MCP endpoint requires authentication (API key or OAuth).",
        "EP-010": "Protect SSE/WebSocket endpoints with authentication.",
        "EP-011": "Disable Spring Actuator in production or restrict to localhost only.",
        "EP-012": "Avoid exposing version information publicly; aids attacker reconnaissance.",
        "EP-013": "Disable trace/profiling endpoints in production.",
    }
    return remediations.get(rule_id, "Review this endpoint and restrict access as appropriate.")
