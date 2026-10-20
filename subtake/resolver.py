"""DNS CNAME chain resolver for subtake."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

import dns.exception
import dns.name
import dns.rdatatype
import dns.resolver

logger = logging.getLogger(__name__)

MAX_CNAME_DEPTH = 10


@dataclass
class DNSResult:
    """Result of resolving a domain's CNAME chain.

    Attributes:
        domain: The original domain that was queried.
        cname_chain: Ordered list of CNAMEs followed during resolution.
        final_cname: The last CNAME in the chain (the dangling target), if any.
        nxdomain: True if the final target returned NXDOMAIN.
        error: Human-readable error string if resolution failed for other reasons.
    """

    domain: str
    cname_chain: list[str] = field(default_factory=list)
    final_cname: Optional[str] = None
    nxdomain: bool = False
    error: Optional[str] = None


def resolve_cname_chain(domain: str, resolver: Optional[dns.resolver.Resolver] = None) -> DNSResult:
    """Follow the full CNAME chain for *domain* up to MAX_CNAME_DEPTH hops.

    Args:
        domain: The domain name to resolve.
        resolver: Optional pre-configured :class:`dns.resolver.Resolver`. A new
            default resolver is created when *None*.

    Returns:
        A :class:`DNSResult` populated with the CNAME chain and status flags.
    """
    if resolver is None:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5.0
        resolver.lifetime = 10.0

    chain: list[str] = []
    current = domain.rstrip(".")
    nxdomain = False
    error: Optional[str] = None

    for depth in range(MAX_CNAME_DEPTH):
        try:
            answer = resolver.resolve(current, rdtype=dns.rdatatype.CNAME)
            cname_target = str(answer[0].target).rstrip(".")
            chain.append(cname_target)
            logger.debug("%s -> CNAME -> %s (depth=%d)", current, cname_target, depth)
            current = cname_target
        except dns.resolver.NXDOMAIN:
            logger.debug("%s -> NXDOMAIN (depth=%d)", current, depth)
            nxdomain = True
            break
        except dns.resolver.NoAnswer:
            # No CNAME at this level; chain ends here (could be A/AAAA record).
            logger.debug("%s -> NoAnswer for CNAME (depth=%d)", current, depth)
            break
        except dns.resolver.Timeout:
            error = f"DNS timeout resolving {current!r}"
            logger.warning(error)
            break
        except dns.resolver.NoNameservers:
            error = f"No nameservers available for {current!r}"
            logger.warning(error)
            break
        except dns.exception.DNSException as exc:
            error = f"DNS error for {current!r}: {exc}"
            logger.warning(error)
            break

    final_cname = chain[-1] if chain else None
    return DNSResult(
        domain=domain,
        cname_chain=chain,
        final_cname=final_cname,
        nxdomain=nxdomain,
        error=error,
    )
