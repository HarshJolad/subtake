"""Service fingerprint registry for subdomain takeover detection."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Fingerprint:
    """Describes a hosted service that is susceptible to subdomain takeover.

    Attributes:
        service: Human-readable service name.
        cname_patterns: List of substrings (or simple globs) that the CNAME
            target must contain for this fingerprint to match.
        http_fingerprints: List of body substrings that indicate the endpoint
            is unclaimed / not provisioned.
        confidence: Confidence level of the detection (``"HIGH"``, ``"MEDIUM"``,
            or ``"LOW"``).
        nxdomain_vulnerable: If ``True``, NXDOMAIN on the CNAME target alone is
            sufficient to flag the domain as suspicious, even without an HTTP match.
    """

    service: str
    cname_patterns: list[str] = field(default_factory=list)
    http_fingerprints: list[str] = field(default_factory=list)
    confidence: str = "HIGH"
    nxdomain_vulnerable: bool = False


# ---------------------------------------------------------------------------
# Registry — 30+ services
# ---------------------------------------------------------------------------

FINGERPRINTS: list[Fingerprint] = [
    Fingerprint(
        service="GitHub Pages",
        cname_patterns=["github.io", "github.com"],
        http_fingerprints=["There isn't a GitHub Pages site here", "github.com/404"],
        confidence="HIGH",
    ),
    Fingerprint(
        service="Heroku",
        cname_patterns=["herokuapp.com", "herokudns.com"],
        http_fingerprints=["No such app", "herokucdn.com/error-pages/no-such-app"],
        confidence="HIGH",
    ),
    Fingerprint(
        service="Amazon S3",
        cname_patterns=[
            "s3.amazonaws.com",
            "s3-website",
            "s3-accelerate.amazonaws.com",
        ],
        http_fingerprints=[
            "NoSuchBucket",
            "The specified bucket does not exist",
            "NoSuchKey",
        ],
        confidence="HIGH",
    ),
    Fingerprint(
        service="Amazon CloudFront",
        cname_patterns=["cloudfront.net"],
        http_fingerprints=[
            "Bad Request",
            "ERROR: The request could not be satisfied",
            "d3rp4kyd3che7k.cloudfront.net",
        ],
        confidence="MEDIUM",
        nxdomain_vulnerable=True,
    ),
    Fingerprint(
        service="Shopify",
        cname_patterns=["myshopify.com", "shopify.com"],
        http_fingerprints=[
            "Sorry, this shop is currently unavailable",
            "Only one step away from your new Shopify store",
        ],
        confidence="HIGH",
    ),
    Fingerprint(
        service="Fastly",
        cname_patterns=["fastly.net", "fastly.com"],
        http_fingerprints=[
            "Fastly error: unknown domain",
            "Please check that this domain has been added to a service",
        ],
        confidence="HIGH",
    ),
    Fingerprint(
        service="Zendesk",
        cname_patterns=["zendesk.com"],
        http_fingerprints=[
            "Help Center Closed",
            "Page not found",
            "Redirecting to our Help Center",
        ],
        confidence="HIGH",
    ),
    Fingerprint(
        service="Azure Websites",
        cname_patterns=["azurewebsites.net", "cloudapp.net", "trafficmanager.net"],
        http_fingerprints=[
            "404 Web Site not found",
            "Web App - Unavailable",
            "Microsoft Azure App Service",
        ],
        confidence="HIGH",
    ),
    Fingerprint(
        service="Azure Traffic Manager",
        cname_patterns=["trafficmanager.net"],
        http_fingerprints=[],
        confidence="MEDIUM",
        nxdomain_vulnerable=True,
    ),
    Fingerprint(
        service="Tumblr",
        cname_patterns=["domains.tumblr.com", "tumblr.com"],
        http_fingerprints=[
            "Whatever you were looking for doesn't live here",
            "Don't panic",
        ],
        confidence="HIGH",
    ),
    Fingerprint(
        service="WordPress.com",
        cname_patterns=["wordpress.com", "wpcomstaging.com"],
        http_fingerprints=[
            "Do you want to register",
            "WordPress.com — Get a Free Blog Here",
        ],
        confidence="HIGH",
    ),
    Fingerprint(
        service="Squarespace",
        cname_patterns=["squarespace.com", "squarespace-cdn.com"],
        http_fingerprints=[
            "No Such Account",
            "You may have followed a broken link",
        ],
        confidence="HIGH",
    ),
    Fingerprint(
        service="Cargo",
        cname_patterns=["cargocollective.com"],
        http_fingerprints=["404 Not Found", "If you're the site owner"],
        confidence="MEDIUM",
    ),
    Fingerprint(
        service="Ghost",
        cname_patterns=["ghost.io", "ghost.org"],
        http_fingerprints=[
            "The thing you were looking for is no longer here",
            "404 - Page Not Found",
        ],
        confidence="HIGH",
    ),
    Fingerprint(
        service="Helpjuice",
        cname_patterns=["helpjuice.com"],
        http_fingerprints=[
            "We could not find what you're looking for",
            "404",
        ],
        confidence="MEDIUM",
    ),
    Fingerprint(
        service="HelpScout",
        cname_patterns=["helpscoutdocs.com", "helpscout.net"],
        http_fingerprints=[
            "No settings were found for this company",
            "Help Center",
        ],
        confidence="HIGH",
    ),
    Fingerprint(
        service="Intercom",
        cname_patterns=["custom.intercom.help", "intercom.io"],
        http_fingerprints=[
            "This page is reserved for artistic ateliers",
            "Uh oh. That page doesn't exist",
        ],
        confidence="HIGH",
    ),
    Fingerprint(
        service="Kajabi",
        cname_patterns=["kajabi.com"],
        http_fingerprints=[
            "The page you were looking for doesn't exist",
            "404 — That page doesn't exist",
        ],
        confidence="HIGH",
    ),
    Fingerprint(
        service="Launchrock",
        cname_patterns=["launchrock.com"],
        http_fingerprints=[
            "It looks like you may have taken a wrong turn somewhere",
            "Page Not Found",
        ],
        confidence="MEDIUM",
    ),
    Fingerprint(
        service="Pantheon",
        cname_patterns=["pantheonsite.io", "pantheon.io"],
        http_fingerprints=[
            "404 error unknown site",
            "The gods are wise, but do not know of the site",
        ],
        confidence="HIGH",
    ),
    Fingerprint(
        service="Pingdom",
        cname_patterns=["pingdom.com"],
        http_fingerprints=[
            "This public report page has not been activated",
            "No uptime check is assigned",
        ],
        confidence="HIGH",
    ),
    Fingerprint(
        service="Readme.io",
        cname_patterns=["readme.io", "readmessl.com"],
        http_fingerprints=[
            "Project doesnt exist... yet",
            "Project doesn't exist",
        ],
        confidence="HIGH",
    ),
    Fingerprint(
        service="Statuspage",
        cname_patterns=["statuspage.io"],
        http_fingerprints=[
            "Better Uptime",
            "is not a valid page",
            "Status page not found",
        ],
        confidence="HIGH",
    ),
    Fingerprint(
        service="Surge.sh",
        cname_patterns=["surge.sh"],
        http_fingerprints=[
            "project not found",
            "surge.sh project not found",
        ],
        confidence="HIGH",
    ),
    Fingerprint(
        service="Tilda",
        cname_patterns=["tilda.ws", "tildacdn.com"],
        http_fingerprints=[
            "Please renew your subscription",
            "Domain is not connected",
        ],
        confidence="HIGH",
    ),
    Fingerprint(
        service="Unbounce",
        cname_patterns=["unbouncepages.com", "unbounce.com"],
        http_fingerprints=[
            "The requested URL was not found on this server",
            "The page you are looking for could not be found",
        ],
        confidence="HIGH",
    ),
    Fingerprint(
        service="UptimeRobot",
        cname_patterns=["stats.uptimerobot.com"],
        http_fingerprints=[
            "page not found",
            "This status page does not seem to exist",
        ],
        confidence="HIGH",
    ),
    Fingerprint(
        service="Webflow",
        cname_patterns=["webflow.io", "webflow.com"],
        http_fingerprints=[
            "The page you are looking for doesn't exist",
            "Page Not Found",
        ],
        confidence="HIGH",
    ),
    Fingerprint(
        service="WP Engine",
        cname_patterns=["wpengine.com"],
        http_fingerprints=[
            "The site you were looking for couldn't be found",
            "This site has not been configured yet",
        ],
        confidence="HIGH",
    ),
    Fingerprint(
        service="Kinsta",
        cname_patterns=["kinsta.cloud", "kinsta.com"],
        http_fingerprints=[
            "No site found",
            "No WordPress site was found at this address",
        ],
        confidence="HIGH",
    ),
    Fingerprint(
        service="Netlify",
        cname_patterns=["netlify.app", "netlify.com"],
        http_fingerprints=[
            "Not Found - Request ID",
            "Page Not Found",
        ],
        confidence="HIGH",
    ),
    Fingerprint(
        service="Bitbucket",
        cname_patterns=["bitbucket.io"],
        http_fingerprints=[
            "Repository not found",
            "The page you are looking for doesn't exist",
        ],
        confidence="HIGH",
    ),
    Fingerprint(
        service="Fly.io",
        cname_patterns=["fly.dev", "fly.io"],
        http_fingerprints=[
            "404 - Unknown Application",
            "App not found",
        ],
        confidence="MEDIUM",
    ),
    Fingerprint(
        service="Vercel",
        cname_patterns=["vercel.app", "vercel-infra.com", "now.sh"],
        http_fingerprints=[
            "The deployment you are trying to reach doesn't exist",
            "DEPLOYMENT_NOT_FOUND",
        ],
        confidence="HIGH",
    ),
]


def match_cname(cname: str) -> Optional[Fingerprint]:
    """Return the first :class:`Fingerprint` whose CNAME patterns match *cname*.

    Pattern matching is case-insensitive substring search.

    Args:
        cname: The final (or intermediate) CNAME target to test.

    Returns:
        The matching :class:`Fingerprint`, or ``None`` if no match is found.
    """
    cname_lower = cname.lower()
    for fp in FINGERPRINTS:
        for pattern in fp.cname_patterns:
            if pattern.lower() in cname_lower:
                return fp
    return None


def match_http_body(fingerprint: Fingerprint, body: str) -> bool:
    """Return ``True`` if *body* contains any of *fingerprint*'s HTTP signatures.

    Args:
        fingerprint: The :class:`Fingerprint` to test against.
        body: The HTTP response body (first 8 KB recommended).

    Returns:
        ``True`` when at least one HTTP fingerprint is found in *body*.
    """
    body_lower = body.lower()
    return any(sig.lower() in body_lower for sig in fingerprint.http_fingerprints)
