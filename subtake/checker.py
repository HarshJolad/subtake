"""Orchestrates DNS resolution, fingerprint matching, and HTTP probing."""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, Optional

from .fingerprints import FINGERPRINTS, Fingerprint, match_cname, match_http_body
from .prober import ProbeResult, probe_domain
from .resolver import DNSResult, resolve_cname_chain

logger = logging.getLogger(__name__)


@dataclass
class Finding:
    """Complete result for a single domain check.

    Attributes:
        domain: The original input domain.
        cname_chain: Ordered list of CNAME hops.
        final_cname: Last CNAME target, if present.
        service: Name of the matched hosted service, or empty string.
        confidence: Detection confidence (``"HIGH"``, ``"MEDIUM"``, ``"LOW"``).
        http_status: HTTP response status code from the probe (-1 if no probe).
        body_snippet: Short body excerpt from the HTTP probe.
        vulnerable: ``True`` when both CNAME and HTTP body matched.
        suspicious: ``True`` for NXDOMAIN + CNAME without HTTP confirmation.
        notes: Human-readable explanation of the finding.
    """

    domain: str
    cname_chain: list[str] = field(default_factory=list)
    final_cname: Optional[str] = None
    service: str = ""
    confidence: str = ""
    http_status: int = -1
    body_snippet: str = ""
    vulnerable: bool = False
    suspicious: bool = False
    notes: str = ""


def _check_single(domain: str) -> Finding:
    """Run a full check (DNS + fingerprint + HTTP probe) for one *domain*.

    Args:
        domain: The domain name to check.

    Returns:
        A populated :class:`Finding`.
    """
    domain = domain.strip().lower()
    finding = Finding(domain=domain)

    # --- DNS resolution -------------------------------------------------------
    dns_result: DNSResult = resolve_cname_chain(domain)
    finding.cname_chain = dns_result.cname_chain
    finding.final_cname = dns_result.final_cname

    if dns_result.error and not dns_result.cname_chain:
        finding.notes = f"DNS error: {dns_result.error}"
        return finding

    if not dns_result.cname_chain:
        finding.notes = "No CNAME chain found; not a CNAME-based target"
        return finding

    # --- Fingerprint matching -------------------------------------------------
    matched_fp: Optional[Fingerprint] = None
    for cname_hop in dns_result.cname_chain:
        matched_fp = match_cname(cname_hop)
        if matched_fp:
            break

    if matched_fp is None:
        finding.notes = f"CNAME chain present ({' -> '.join(dns_result.cname_chain)}) but no known service fingerprint matched"
        return finding

    finding.service = matched_fp.service
    finding.confidence = matched_fp.confidence

    # --- NXDOMAIN + CNAME heuristic ------------------------------------------
    if dns_result.nxdomain:
        finding.suspicious = True
        if matched_fp.nxdomain_vulnerable:
            finding.vulnerable = True
            finding.notes = (
                f"NXDOMAIN on CNAME target for {matched_fp.service}; "
                "domain is likely vulnerable to takeover"
            )
        else:
            finding.notes = (
                f"CNAME points to {matched_fp.service} but final target returned NXDOMAIN — suspicious"
            )
        # Still try HTTP probe on the original domain for extra evidence
        _run_http_probe(domain, matched_fp, finding, nxdomain_context=True)
        return finding

    # --- HTTP probe -----------------------------------------------------------
    _run_http_probe(domain, matched_fp, finding, nxdomain_context=False)
    return finding


def _run_http_probe(
    domain: str,
    fingerprint: Fingerprint,
    finding: Finding,
    nxdomain_context: bool,
) -> None:
    """Probe *domain* and update *finding* in-place with HTTP probe results.

    Args:
        domain: Hostname to probe.
        fingerprint: Matched :class:`Fingerprint` to test against.
        finding: :class:`Finding` to update.
        nxdomain_context: Whether the probe occurs after a NXDOMAIN result.
    """
    if not fingerprint.http_fingerprints:
        # Service has no HTTP fingerprints; rely on DNS only
        return

    probe: ProbeResult = probe_domain(domain, fingerprint.http_fingerprints)
    finding.http_status = probe.status_code
    finding.body_snippet = probe.body_snippet

    if probe.error:
        finding.notes = (
            f"CNAME matches {fingerprint.service} but HTTP probe failed: {probe.error}"
        )
        return

    if probe.matched_fingerprint:
        finding.vulnerable = True
        finding.suspicious = True
        finding.notes = (
            f"VULNERABLE — CNAME points to {fingerprint.service} and HTTP body "
            f"matches unclaimed signature (HTTP {probe.status_code})"
        )
    else:
        note_prefix = "Post-NXDOMAIN: " if nxdomain_context else ""
        finding.notes = (
            f"{note_prefix}CNAME matches {fingerprint.service} "
            f"(HTTP {probe.status_code}) but body signature not matched — may be claimed"
        )


def run_checks(
    domains: list[str],
    threads: int = 10,
    progress_callback: Optional[Callable[[Finding], None]] = None,
) -> list[Finding]:
    """Run subdomain takeover checks for all *domains* using a thread pool.

    Args:
        domains: List of domain names to check.
        threads: Number of worker threads for concurrent checks.
        progress_callback: Optional callable invoked with each :class:`Finding`
            as it completes (useful for live progress updates).

    Returns:
        List of :class:`Finding` objects, one per input domain.
    """
    findings: list[Finding] = []

    with ThreadPoolExecutor(max_workers=threads, thread_name_prefix="subtake") as executor:
        future_to_domain = {executor.submit(_check_single, d): d for d in domains}

        try:
            for future in as_completed(future_to_domain):
                domain = future_to_domain[future]
                try:
                    finding = future.result()
                except Exception as exc:  # noqa: BLE001
                    logger.exception("Unhandled error checking %r: %s", domain, exc)
                    finding = Finding(
                        domain=domain,
                        notes=f"Unhandled error: {exc}",
                    )
                findings.append(finding)
                if progress_callback:
                    progress_callback(finding)
        except KeyboardInterrupt:
            logger.warning("KeyboardInterrupt received — cancelling pending tasks")
            for future in future_to_domain:
                future.cancel()
            # Return whatever we have so far; caller handles flushing
            raise

    return findings
