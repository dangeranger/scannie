from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .doctor import check_tools, doctor_text
from .explain import format_cli_text
from .models import VERDICT_ERROR, VERDICT_HIGH, ScanOptions
from .report import ReportWriter
from .scanner import scan_document
from .utils import parse_size


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="scannie")
    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser("scan", help="scan a PDF or EPUB")
    scan.add_argument("path", type=Path)
    scan.add_argument("--out", type=Path, default=None, help="base directory for report output")
    scan.add_argument("--rules", type=Path, action="append", default=[], help="additional YARA rules")
    scan.add_argument("--max-expanded-size", default="250MB")
    scan.add_argument("--force-type", choices=["pdf", "epub"], default=None)
    scan.add_argument("--vt", action="store_true", help="enrich report with a VirusTotal hash lookup")
    scan.add_argument("--url-reputation", action="store_true", help="enrich PDF URLs with reputation lookups")
    scan.add_argument("--json", action="store_true", help="print summary JSON to stdout")

    subparsers.add_parser("doctor", help="check local scanner toolchain")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "doctor":
        sys.stdout.write(doctor_text(check_tools()))
        return 0

    if args.command == "scan":
        return _scan(args)

    parser.print_help()
    return 0


def _scan(args: argparse.Namespace) -> int:
    writer = ReportWriter()
    try:
        report_dir = writer.create_report_dir(args.path, args.out)
        max_expanded_size = parse_size(args.max_expanded_size)
    except Exception as exc:
        sys.stderr.write(f"scannie: {exc}\n")
        return 2

    options = ScanOptions(
        out_dir=args.out,
        report_dir=report_dir,
        rules=args.rules,
        max_expanded_size=max_expanded_size,
        force_type=args.force_type,
        vt_enabled=args.vt,
        vt_api_key=os.environ.get("VT_API_KEY"),
        url_reputation_enabled=args.url_reputation,
        safe_browsing_api_key=os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY"),
    )
    result = scan_document(args.path, options)
    writer.write(result, report_dir)

    if args.json:
        sys.stdout.write(json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n")
    else:
        sys.stdout.write(format_cli_text(result))

    if result.verdict == VERDICT_HIGH:
        return 1
    if result.verdict == VERDICT_ERROR:
        return 2
    return 0
