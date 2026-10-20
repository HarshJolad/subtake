"""HTTP prober for subdomain takeover verification."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

PROBE_TIMEOUT = 10.0        # seconds
MAX_REDIRECTS = 3
BODY_READ_BYTES = 8192      # 8 KB cap for body matching


@dataclass
class ProbeResult:
    """Result of an HTTP probe against a domain.

    Attributes:
        url: The final URL that was probed (after redirects).
        status_code: HTTP response status code, or -1 on connection failure.
        matched_fingerprint: Whether the response body matched a fingerprint.
        body_snippet: First 256 characters of the response body (sanitised).
        error: Human-readable error if the probe failed to connect.
    """

    url: str
    status_code: int
    matched_fingerprint: bool
    body_snippet: str
    error: Optional[str] = None


def _build_client() -> httpx.Client:
    """Create a shared :class:`httpx.Client` with appropriate defaults."""
    return httpx.Client(
        timeout=httpx.Timeout(PROBE_TIMEOUT),
        follow_redirects=True,
        max_redirects=MAX_REDIRECTS,
        verify=False,         # Many takeover targets have expired/invalid TLS
        headers={
            "User-Agent": (
                "Mozilla/5.0 (compatible; subtake/0.1; "
                "+https://github.com/subtake/subtake)"
            )
        },
    )


def probe_domain(domain: str, fingerprints: list[str]) -> ProbeResult:
    """Probe *domain* over HTTPS then HTTP; check body against *fingerprints*.

    The prober tries HTTPS first. If the connection fails (not a 4xx/5xx
    response—a genuine network/TLS error), it falls back to plain HTTP.

    Args:
        domain: Hostname to probe (no scheme, no trailing slash).
        fingerprints: List of case-insensitive body substrings that indicate
            the endpoint is unclaimed.

    Returns:
        A :class:`ProbeResult` with findings from the successful probe (or
        error information if both HTTPS and HTTP failed).
    """
    urls_to_try = [f"https://{domain}", f"http://{domain}"]

    with _build_client() as client:
        for url in urls_to_try:
            try:
                response = client.get(url)
                body = response.text[:BODY_READ_BYTES]
                matched = _check_fingerprints(body, fingerprints)
                snippet = _sanitise_snippet(body)
                logger.debug("Probed %s -> HTTP %d, matched=%s", url, response.status_code, matched)
                return ProbeResult(
                    url=str(response.url),
                    status_code=response.status_code,
                    matched_fingerprint=matched,
                    body_snippet=snippet,
                )
            except (httpx.ConnectError, httpx.ConnectTimeout, httpx.RemoteProtocolError) as exc:
                logger.debug("Connection error probing %s: %s", url, exc)
                # Try next URL (HTTP fallback)
                continue
            except httpx.TimeoutException as exc:
                logger.debug("Timeout probing %s: %s", url, exc)
                continue
            except httpx.TooManyRedirects as exc:
                logger.debug("Too many redirects probing %s: %s", url, exc)
                return ProbeResult(
                    url=url,
                    status_code=-1,
                    matched_fingerprint=False,
                    body_snippet="",
                    error=f"Too many redirects: {exc}",
                )
            except Exception as exc:  # noqa: BLE001
                logger.debug("Unexpected error probing %s: %s", url, exc)
                continue

    # Both HTTPS and HTTP failed
    return ProbeResult(
        url=f"https://{domain}",
        status_code=-1,
        matched_fingerprint=False,
        body_snippet="",
        error="All probe attempts failed (connection refused / timeout / TLS error)",
    )


def _check_fingerprints(body: str, fingerprints: list[str]) -> bool:
    """Return ``True`` if *body* contains any of *fingerprints* (case-insensitive)."""
    body_lower = body.lower()
    return any(fp.lower() in body_lower for fp in fingerprints)


def _sanitise_snippet(body: str, length: int = 256) -> str:
    """Return a sanitised, single-line snippet of *body* for reporting."""
    snippet = body[:length].replace("\n", " ").replace("\r", "").strip()
    return snippet
