"""Utility helpers: logging setup and domain sanitisation."""

from __future__ import annotations

import logging
import re
import sys
from pathlib import Path
from typing import Iterator


# Regex that loosely validates a domain/subdomain token.
_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


def setup_logging(verbose: bool = False) -> None:
    """Configure root logger for the application.

    Args:
        verbose: If ``True``, set level to ``DEBUG``; otherwise ``WARNING``.
    """
    level = logging.DEBUG if verbose else logging.WARNING
    fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    datefmt = "%H:%M:%S"

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(fmt, datefmt=datefmt))

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)

    # Quiet noisy third-party loggers
    for noisy in ("httpx", "httpcore", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def read_domains(path: str | Path) -> list[str]:
    """Read and sanitise a domain list from a text file.

    Lines starting with ``#`` and blank lines are skipped.  Each remaining
    line is stripped and lowercased.

    Args:
        path: Path to the input file.

    Returns:
        Deduplicated list of valid domain strings (preserving order).
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Input file not found: {path}")

    seen: set[str] = set()
    domains: list[str] = []

    for raw in path.read_text(encoding="utf-8").splitlines():
        domain = sanitise_domain(raw)
        if domain and domain not in seen:
            seen.add(domain)
            domains.append(domain)

    return domains


def sanitise_domain(raw: str) -> str:
    """Sanitise and validate a single domain string.

    Args:
        raw: Raw line from input (may include comments, whitespace, schemes).

    Returns:
        Lowercased domain string, or empty string if invalid/should be skipped.
    """
    line = raw.strip()

    # Skip comments and blank lines
    if not line or line.startswith("#"):
        return ""

    # Strip scheme if accidentally included (http://, https://)
    line = re.sub(r"^https?://", "", line, flags=re.IGNORECASE)

    # Strip trailing path/query/fragment
    line = line.split("/")[0].split("?")[0].split("#")[0]

    # Strip port
    line = re.sub(r":\d+$", "", line)

    line = line.strip().lower()

    if not _DOMAIN_RE.match(line):
        return ""

    return line


def iter_chunks(lst: list, size: int) -> Iterator[list]:
    """Yield successive *size*-element chunks from *lst*.

    Args:
        lst: List to split.
        size: Maximum chunk length.

    Yields:
        Sub-lists of at most *size* elements.
    """
    for i in range(0, len(lst), size):
        yield lst[i : i + size]


def print_banner() -> None:
    """Print the subtake ASCII art banner to stdout."""
    banner = r"""
  ___ _   _ ___ _____ _   _  _____
 / __| | | | _ \_   _/_\ | |/ / __|
 \__ \ |_| | _/ | |/ _ \| ' <| _|
 |___/\___/|_|   |_/_/ \_\_|\_\___|

  Subdomain Takeover Checker v0.1.0
  ──────────────────────────────────
"""
    print(banner)


def format_summary_table(total: int, vulnerable: int, suspicious: int, clean: int) -> str:
    """Return a simple aligned summary table string.

    Args:
        total: Total number of domains checked.
        vulnerable: Count of vulnerable findings.
        suspicious: Count of suspicious (but unconfirmed) findings.
        clean: Count of clean findings.

    Returns:
        Multi-line string with a formatted summary table.
    """
    col_w = 14
    lines = [
        "",
        "  ┌──────────────────────┬────────┐",
        "  │ Category             │ Count  │",
        "  ├──────────────────────┼────────┤",
        f"  │ Total checked        │ {str(total).ljust(6)} │",
        f"  │ ✗ Vulnerable         │ {str(vulnerable).ljust(6)} │",
        f"  │ ⚠ Suspicious         │ {str(suspicious).ljust(6)} │",
        f"  │ ✓ Clean              │ {str(clean).ljust(6)} │",
        "  └──────────────────────┴────────┘",
        "",
    ]
    return "\n".join(lines)
