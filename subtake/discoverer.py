"""Subdomain discovery via the crt.name Certificate Transparency API.

API reference: https://crt.name/#api

Behaviour by format:
  - Plain text (default): GET /v1/search?apex=<domain>
      Returns one subdomain per line, no dates.
  - JSON with dates:       GET /v1/search?apex=<domain>&format=json&dates=1
      Returns a JSON array of {"sub": "<subdomain>", "first_seen": "<iso-date>"}.

Notes:
  - No API token required.
  - Rate limit: 100 requests per IP per day (HTTP 429 on breach).
  - ``apex`` must be an eTLD+1 (e.g. ``example.com``, NOT ``sub.example.com``).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Optional

import httpx

log = logging.getLogger(__name__)

_CRT_API = "https://crt.name/v1/search"
_TIMEOUT = 30  # seconds — crt.name can be slow on large domains
_MAX_RETRIES = 2

# Loose hostname pattern — rejects wildcards and bare labels
_HOSTNAME_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class DiscoveryResult:
    """Outcome of a subdomain-discovery request for one apex domain.

    Attributes:
        apex: The eTLD+1 domain that was queried.
        subdomains: Deduplicated, sorted list of discovered subdomains.
        first_seen: Mapping of subdomain → ISO-date string (only populated
            when ``include_dates=True`` was passed to the query).
        error: Human-readable error message, or ``None`` on success.
        raw_count: Total lines / entries returned by the API before
            deduplication and filtering.
    """

    apex: str
    subdomains: list[str] = field(default_factory=list)
    first_seen: dict[str, str] = field(default_factory=dict)
    error: Optional[str] = None
    raw_count: int = 0


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _extract_apex(domain: str) -> str:
    """Return the eTLD+1 (apex) portion of *domain*.

    Best-effort: takes the last two dot-separated labels.  For public-suffix
    edge cases (e.g. ``co.uk``) the caller should pass the apex directly.

    Args:
        domain: Any fully-qualified domain name.

    Returns:
        The last two dot-separated labels, lower-cased.
    """
    parts = domain.strip().rstrip(".").lower().split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain.lower()


def _is_valid_name(name: str) -> bool:
    """Return ``True`` if *name* is an acceptable hostname (no wildcards)."""
    return bool(name) and not name.startswith("*") and bool(_HOSTNAME_RE.match(name))


def _http_get(url: str, params: dict[str, str], timeout: float) -> httpx.Response:
    """Perform a GET with retries on transient errors.

    Args:
        url: Endpoint URL.
        params: Query parameters.
        timeout: Per-request timeout in seconds.

    Returns:
        Successful :class:`httpx.Response`.

    Raises:
        httpx.HTTPStatusError: On a non-retryable HTTP error (including 429).
        httpx.RequestError: When all retry attempts are exhausted.
    """
    last_exc: Optional[Exception] = None
    for attempt in range(1, _MAX_RETRIES + 2):
        try:
            log.debug("GET %s params=%s attempt=%d", url, params, attempt)
            with httpx.Client(timeout=timeout, follow_redirects=True) as client:
                resp = client.get(url, params=params)
                resp.raise_for_status()
                return resp
        except httpx.HTTPStatusError:
            raise  # never retry on HTTP-level errors (429, 5xx, etc.)
        except httpx.RequestError as exc:
            last_exc = exc
            log.debug("Request error attempt %d: %s", attempt, exc)
    raise last_exc  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Core parsers
# ---------------------------------------------------------------------------

def _parse_plaintext(body: str) -> tuple[list[str], dict[str, str]]:
    """Parse a plain-text response (one subdomain per line).

    Args:
        body: Raw response text.

    Returns:
        Tuple of (subdomains, first_seen_map).  ``first_seen_map`` is always
        empty for plain-text responses since the API does not include dates.
    """
    seen: set[str] = set()
    subdomains: list[str] = []
    for raw_line in body.splitlines():
        name = raw_line.strip().lower()
        if _is_valid_name(name) and name not in seen:
            seen.add(name)
            subdomains.append(name)
    return subdomains, {}


def _parse_json(data: list) -> tuple[list[str], dict[str, str]]:
    """Parse a JSON response from the crt.name API.

    The API returns objects with a ``"sub"`` key (not ``"subdomain"``):
    ``[{"sub": "foo.example.com", "first_seen": "2020-01-01T00:00:00Z"}, ...]``

    Args:
        data: Parsed JSON list from the API.

    Returns:
        Tuple of (subdomains, first_seen_map).
    """
    seen: set[str] = set()
    subdomains: list[str] = []
    first_seen: dict[str, str] = {}

    for entry in data:
        if isinstance(entry, str):
            name = entry.strip().lower()
            date = ""
        elif isinstance(entry, dict):
            # Key is "sub" in the real API response (not "subdomain")
            name = str(entry.get("sub", "")).strip().lower()
            date = str(entry.get("first_seen", ""))
        else:
            continue

        if not _is_valid_name(name):
            log.debug("Skipping invalid/wildcard name: %r", name)
            continue

        if name not in seen:
            seen.add(name)
            subdomains.append(name)
            if date:
                first_seen[name] = date

    return subdomains, first_seen


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def discover_subdomains(
    apex: str,
    *,
    include_dates: bool = True,
    timeout: float = _TIMEOUT,
) -> DiscoveryResult:
    """Query the crt.name API and return all known subdomains for *apex*.

    When *include_dates* is ``True`` the request uses ``format=json&dates=1``
    and parses the ``{"sub": ..., "first_seen": ...}`` JSON objects returned
    by the API.  Otherwise plain text (one line per subdomain) is fetched and
    parsed, which is slightly faster.

    Args:
        apex: eTLD+1 domain to enumerate, e.g. ``"example.com"``.  Must NOT
            be a subdomain — pass the bare registered domain.
        include_dates: Request first-seen date metadata from the API.
        timeout: HTTP request timeout in seconds.

    Returns:
        A :class:`DiscoveryResult`.  On failure ``error`` is set and
        ``subdomains`` is empty.
    """
    result = DiscoveryResult(apex=apex)

    if include_dates:
        params: dict[str, str] = {"apex": apex, "format": "json", "dates": "1"}
    else:
        # Plain-text mode — no format param needed (it's the default)
        params = {"apex": apex}

    try:
        resp = _http_get(_CRT_API, params, timeout)
    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code
        if status == 429:
            result.error = "Rate-limited by crt.name API (100 requests/IP/day exceeded)"
        else:
            result.error = f"HTTP {status} from crt.name API"
        log.warning("crt.name lookup failed for %r: %s", apex, result.error)
        return result
    except httpx.RequestError as exc:
        result.error = f"Network error after {_MAX_RETRIES + 1} attempts: {exc}"
        log.warning("crt.name lookup failed for %r: %s", apex, result.error)
        return result

    # --- Parse ----------------------------------------------------------------
    if include_dates:
        try:
            data = resp.json()
        except ValueError as exc:
            result.error = f"Invalid JSON from crt.name API: {exc}"
            log.warning("JSON parse error for %r: %s", apex, exc)
            return result

        if not isinstance(data, list):
            result.error = f"Unexpected API response type: {type(data).__name__}"
            log.warning("Unexpected response for %r: %r", apex, data)
            return result

        result.raw_count = len(data)
        subdomains, first_seen = _parse_json(data)
    else:
        lines = [ln for ln in resp.text.splitlines() if ln.strip()]
        result.raw_count = len(lines)
        subdomains, first_seen = _parse_plaintext(resp.text)

    result.subdomains = sorted(subdomains)
    result.first_seen = first_seen

    log.info(
        "crt.name: %d raw → %d unique subdomains for %r",
        result.raw_count,
        len(result.subdomains),
        apex,
    )
    return result


def discover_for_domains(
    domains: list[str],
    *,
    include_dates: bool = True,
    timeout: float = _TIMEOUT,
) -> dict[str, DiscoveryResult]:
    """Run :func:`discover_subdomains` for each unique apex derived from *domains*.

    Multiple subdomains that share the same apex are deduplicated so the API
    is hit only once per apex domain.

    Args:
        domains: List of any domain/subdomain names (apexes are auto-extracted).
        include_dates: Passed through to :func:`discover_subdomains`.
        timeout: HTTP timeout in seconds.

    Returns:
        Mapping of apex domain → :class:`DiscoveryResult`.
    """
    apexes = sorted({_extract_apex(d) for d in domains})
    return {
        apex: discover_subdomains(apex, include_dates=include_dates, timeout=timeout)
        for apex in apexes
    }
