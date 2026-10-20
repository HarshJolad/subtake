"""Entry point for the subtake CLI."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .checker import Finding, run_checks
from .discoverer import DiscoveryResult, discover_for_domains
from .reporter import write_csv, write_html, write_markdown
from .utils import format_summary_table, print_banner, read_domains, setup_logging


def _build_parser() -> argparse.ArgumentParser:
    """Build and return the argument parser for subtake."""
    parser = argparse.ArgumentParser(
        prog="subtake",
        description="Dangling DNS / subdomain takeover checker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  subtake --input domains.txt
  subtake --input domains.txt --output results.csv --threads 20 --verbose
  subtake --input domains.txt --report-md report.md --report-html report.html
  subtake --input domains.txt --all --output all_results.csv

  # Discover subdomains first, then check them all:
  subtake --input apex.txt --discover --output results.csv

  # Only enumerate subdomains, save list, skip takeover checks:
  subtake --input apex.txt --discover-only --discovered-out found.txt
""",
    )

    parser.add_argument(
        "--input", "-i",
        required=True,
        metavar="FILE",
        help="Path to newline-separated list of domains/subdomains to check",
    )
    parser.add_argument(
        "--output", "-o",
        default="reports/results.csv",
        metavar="FILE",
        help="Path for CSV output (default: reports/results.csv)",
    )
    parser.add_argument(
        "--threads", "-t",
        type=int,
        default=10,
        metavar="N",
        help="Number of concurrent worker threads (default: 10)",
    )
    parser.add_argument(
        "--report-md",
        metavar="FILE",
        default="reports/report.md",
        help="Path for Markdown report output (default: reports/report.md)",
    )
    parser.add_argument(
        "--report-html",
        metavar="FILE",
        default="reports/report.html",
        help="Path for HTML report output (default: reports/report.html)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        dest="all_findings",
        help="Include all findings (not just vulnerable/suspicious) in CSV output",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose/debug logging",
    )
    parser.add_argument(
        "--version", "-V",
        action="version",
        version=f"subtake {__version__}",
    )

    # --- Discovery flags -------------------------------------------------------
    disc = parser.add_argument_group(
        "discovery",
        "Subdomain enumeration via the crt.name Certificate Transparency API",
    )
    disc.add_argument(
        "--discover", "-d",
        action="store_true",
        help=(
            "Enumerate subdomains for each apex domain in --input using crt.name, "
            "then run takeover checks on all discovered subdomains (merges with "
            "any subdomains already in --input)"
        ),
    )
    disc.add_argument(
        "--discover-only",
        action="store_true",
        help=(
            "Enumerate subdomains only — skip takeover checks. "
            "Use --discovered-out to save the list."
        ),
    )
    disc.add_argument(
        "--discovered-out",
        metavar="FILE",
        default="reports/discovered.txt",
        help=(
            "Save discovered subdomains to this file (one per line). "
            "Works with both --discover and --discover-only. "
            "(default: reports/discovered.txt)"
        ),
    )
    disc.add_argument(
        "--no-dates",
        action="store_true",
        help="Do not request first-seen dates from the crt.name API (slightly faster).",
    )

    return parser


def _ensure_dir(path: str | Path) -> Path:
    """Create parent directories of *path* if they do not already exist.

    Args:
        path: File path whose parent directory should be created.

    Returns:
        The resolved :class:`~pathlib.Path` object.
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _flush_results(
    findings: list[Finding],
    args: argparse.Namespace,
) -> None:
    """Write all requested output files from *findings*.

    Parent directories are created automatically.

    Args:
        findings: List of :class:`Finding` objects to report.
        args: Parsed CLI arguments.
    """
    if findings:
        _ensure_dir(args.output)
        csv_count = write_csv(findings, args.output, all_findings=args.all_findings)
        print(f"\n  CSV written  -> {args.output} ({csv_count} rows)")

        if args.report_md:
            _ensure_dir(args.report_md)
            write_markdown(findings, args.report_md)
            print(f"  MD  written  -> {args.report_md}")

        if args.report_html:
            _ensure_dir(args.report_html)
            write_html(findings, args.report_html)
            print(f"  HTML written -> {args.report_html}")
    else:
        print("\n  No findings to write.")


def _run_discovery(args: argparse.Namespace, domains: list[str]) -> list[str]:
    """Enumerate subdomains via crt.name and return the merged domain list.

    Args:
        args: Parsed CLI arguments.
        domains: Domains loaded from --input (used to derive apex domains).

    Returns:
        Merged, deduplicated list of domains to check.
    """
    print("  ┌─────────────────────────────────────────────┐")
    print("  │  Subdomain Discovery  (crt.name CT API)     │")
    print("  └─────────────────────────────────────────────┘")

    try:
        from tqdm import tqdm  # type: ignore[import-untyped]
        _tqdm_available = True
    except ImportError:
        _tqdm_available = False

    # Collect unique apex domains from the input list
    from .discoverer import _extract_apex  # noqa: PLC0415
    apexes = sorted({_extract_apex(d) for d in domains})
    print(f"  Querying crt.name for {len(apexes)} apex domain(s)…\n")

    disc_results = {}
    bar = (
        tqdm(apexes, unit="apex", ncols=80, colour="yellow")  # type: ignore[assignment]
        if _tqdm_available
        else apexes
    )

    from .discoverer import discover_subdomains  # noqa: PLC0415

    for apex in bar:
        if _tqdm_available:
            bar.set_postfix_str(apex, refresh=False)  # type: ignore[union-attr]
        disc_results[apex] = discover_subdomains(
            apex,
            include_dates=not args.no_dates,
        )

    if _tqdm_available:
        bar.close()  # type: ignore[union-attr]

    # Print per-apex summary
    print()
    all_discovered: list[str] = []
    for apex, res in disc_results.items():
        if res.error:
            print(f"  ✗ {apex:40s}  ERROR: {res.error}")
        else:
            print(
                f"  ✓ {apex:40s}  {len(res.subdomains):>5d} subdomains"
                f"  (raw: {res.raw_count})"
            )
            all_discovered.extend(res.subdomains)

    # Optionally save discovered list
    if args.discovered_out and all_discovered:
        out_path = _ensure_dir(args.discovered_out)
        out_path.write_text("\n".join(sorted(set(all_discovered))), encoding="utf-8")
        print(f"\n  Discovered list saved -> {args.discovered_out}")

    # Merge with original input, preserving order, deduplicating
    merged: list[str] = list(dict.fromkeys(domains + all_discovered))
    print(
        f"\n  Discovery complete: {len(all_discovered)} subdomain(s) found, "
        f"{len(merged)} total after merge.\n"
    )
    return merged


def main() -> None:
    """Main entry point for the subtake CLI."""
    parser = _build_parser()
    args = parser.parse_args()

    setup_logging(verbose=args.verbose)
    print_banner()

    # --- Load domains ---------------------------------------------------------
    try:
        domains = read_domains(args.input)
    except FileNotFoundError as exc:
        print(f"  ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    if not domains:
        print("  No valid domains found in input file. Exiting.")
        sys.exit(0)

    print(f"  Loaded {len(domains)} domain(s) from {args.input!r}")

    # --- Discovery phase (optional) -------------------------------------------
    if args.discover or args.discover_only:
        try:
            domains = _run_discovery(args, domains)
        except KeyboardInterrupt:
            print("\n\n  Discovery interrupted by user.")
            sys.exit(130)

        if args.discover_only:
            print("  --discover-only flag set — skipping takeover checks.")
            if not args.discovered_out:
                # Still print them to stdout so the user gets something useful
                print(f"\n  Discovered {len(domains)} domain(s):\n")
                for d in domains:
                    print(f"    {d}")
            sys.exit(0)

    print(f"  Threads: {args.threads} | Reports folder: {Path(args.output).parent}")
    print()

    # --- Progress bar via tqdm ------------------------------------------------
    try:
        from tqdm import tqdm  # type: ignore[import-untyped]
        pbar = tqdm(total=len(domains), unit="domain", ncols=80, colour="cyan")
    except ImportError:
        pbar = None  # type: ignore[assignment]

    findings: list[Finding] = []

    def on_progress(finding: Finding) -> None:
        findings.append(finding)
        if pbar is not None:
            status = "VULN" if finding.vulnerable else ("SUSP" if finding.suspicious else "ok")
            pbar.set_postfix_str(f"{finding.domain[:30]} [{status}]", refresh=False)
            pbar.update(1)

    # --- Run checks -----------------------------------------------------------
    try:
        findings = run_checks(domains, threads=args.threads, progress_callback=on_progress)
    except KeyboardInterrupt:
        print("\n\n  Interrupted by user — flushing partial results…")
        if pbar:
            pbar.close()
        _flush_results(findings, args)
        sys.exit(130)
    finally:
        if pbar:
            pbar.close()

    # --- Summary --------------------------------------------------------------
    vuln_count = sum(1 for f in findings if f.vulnerable)
    susp_count = sum(1 for f in findings if f.suspicious and not f.vulnerable)
    clean_count = sum(1 for f in findings if not f.vulnerable and not f.suspicious)

    print(format_summary_table(len(findings), vuln_count, susp_count, clean_count))
    print(f"  {vuln_count} vulnerable, {susp_count} suspicious, {clean_count} clean")

    # --- Write reports --------------------------------------------------------
    _flush_results(findings, args)

    print()


if __name__ == "__main__":
    main()
