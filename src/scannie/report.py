from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from .artifacts import artifact_text
from .explain import format_analysis_detail, tool_status_label
from .models import Artifact, ScanResult, ToolResult
from .pdf import PDF_RISK_NAMES, has_pdf_name
from .url_reputation import extract_url_inventory, inventory_from_json, url_inventory_summary_text
from .yara import YaraRuleMatch, packaged_rule_details, parse_yara_output


def _safe_report_name(file_name: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in file_name)


class ReportWriter:
    def __init__(self, clock: Callable[[], datetime] | None = None) -> None:
        self._clock = clock or datetime.now

    def create_report_dir(self, input_path: Path, out_dir: Path | None = None) -> Path:
        base = out_dir or Path.cwd()
        timestamp = self._clock().strftime("%Y%m%d-%H%M%S")
        report_dir = base / f"triage-{_safe_report_name(input_path.name)}-{timestamp}"
        report_dir.mkdir(parents=True, exist_ok=False)
        return report_dir

    def write(self, result: ScanResult, report_dir: Path | None = None) -> ScanResult:
        target_dir = report_dir or Path(result.report_dir or self.create_report_dir(Path(result.input_path)))
        target_dir.mkdir(parents=True, exist_ok=True)
        result.report_dir = str(target_dir)

        self._add_derived_artifacts(result)
        self._populate_content_sizes(result)
        self._add_artifact_index(result)
        # Recalculate after adding the index so its own entry gets a size too.
        self._populate_content_sizes(result)

        for artifact in result.artifacts:
            self._write_artifact(target_dir, artifact)

        (target_dir / "summary.json").write_text(
            json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        (target_dir / "summary.txt").write_text(self._summary_text(result), encoding="utf-8")
        return result

    def _write_artifact(self, report_dir: Path, artifact: Artifact) -> None:
        if artifact.content is None:
            path = report_dir / artifact.relative_path
            if path.exists():
                artifact.size_bytes = path.stat().st_size
            return
        path = report_dir / artifact.relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(artifact.content, bytes):
            path.write_bytes(artifact.content)
        else:
            path.write_text(artifact.content, encoding="utf-8", errors="replace")
        artifact.size_bytes = path.stat().st_size

    def _add_derived_artifacts(self, result: ScanResult) -> None:
        self._add_artifact_once(
            result,
            "tool-status",
            "tool-status.txt",
            _tool_status_text(result.tools),
            "External tool status summary",
        )
        self._add_artifact_once(
            result,
            "yara-summary",
            "yara-summary.txt",
            _yara_summary_text(result.tools),
            "YARA match summary",
        )
        if result.file_type == "pdf":
            self._add_pdf_summaries(result)

    def _add_pdf_summaries(self, result: ScanResult) -> None:
        self._add_artifact_once(
            result,
            "pdf-structure-summary",
            "pdf-structure-summary.txt",
            _pdf_structure_summary(artifact_text(result, "qpdf.json")),
            "PDF structure summary derived from qPDF JSON",
        )
        risky_text = artifact_text(result, "pdf-risky-strings.txt")
        self._add_artifact_once(
            result,
            "pdf-risk-summary",
            "pdf-risk-summary.txt",
            _pdf_risk_summary(risky_text),
            "PDF risky indicator summary",
        )
        self._add_artifact_once(
            result,
            "pdf-url-summary",
            "pdf-url-summary.txt",
            _pdf_url_summary(risky_text, artifact_text(result, "url-inventory.json")),
            "PDF URL and domain summary",
        )

    def _add_artifact_index(self, result: ScanResult) -> None:
        self._add_artifact_once(
            result,
            "artifact-index",
            "artifact-index.txt",
            _artifact_index_text(result.artifacts),
            "Report artifact index",
        )

    def _add_artifact_once(
        self,
        result: ScanResult,
        name: str,
        relative_path: str,
        content: str,
        description: str,
    ) -> None:
        if any(artifact.relative_path == relative_path for artifact in result.artifacts):
            return
        result.add_artifact(
            name,
            relative_path,
            content,
            description=description,
            role="summary",
        )

    def _populate_content_sizes(self, result: ScanResult) -> None:
        for artifact in result.artifacts:
            if artifact.content is None:
                continue
            if isinstance(artifact.content, bytes):
                artifact.size_bytes = len(artifact.content)
            else:
                artifact.size_bytes = len(artifact.content.encode("utf-8", errors="replace"))

    def _summary_text(self, result: ScanResult) -> str:
        lines = [
            f"Input: {result.input_path}",
            f"Type: {result.file_type or 'unknown'}",
            f"SHA-256: {result.sha256 or 'unknown'}",
            f"Size: {result.size_bytes if result.size_bytes is not None else 'unknown'} bytes",
            f"Verdict: {result.verdict}",
            "",
            format_analysis_detail(result).rstrip(),
        ]

        if result.errors:
            lines.extend(["", "Errors:"])
            lines.extend(f"- {error}" for error in result.errors)

        return "\n".join(lines) + "\n"


def _artifact_index_text(artifacts: list[Artifact]) -> str:
    lines = ["Artifact Index", ""]
    for artifact in sorted(artifacts, key=lambda item: item.relative_path):
        size = artifact.size_bytes if artifact.size_bytes is not None else "unknown"
        description = artifact.description or artifact.name
        if artifact.relative_path == "qdf.pdf":
            description = f"{description}; large raw normalized analysis artifact; not intended for casual opening"
        lines.append(f"{artifact.relative_path}\trole={artifact.role}\tsize={size}\tdescription={description}")
    return "\n".join(lines) + "\n"


def _tool_status_text(tools: list[ToolResult]) -> str:
    lines = ["Tool Status", ""]
    if not tools:
        lines.append("No external tools were recorded.")
        return "\n".join(lines) + "\n"

    for tool in tools:
        status = tool_status_label(tool)
        artifact = f" -> {tool.stdout_artifact}" if tool.stdout_artifact else ""
        lines.append(f"{tool.name}: {status}{artifact}")
    return "\n".join(lines) + "\n"


def _yara_summary_text(tools: list[ToolResult]) -> str:
    packaged: list[tuple[ToolResult, YaraRuleMatch]] = []
    custom: list[tuple[ToolResult, YaraRuleMatch]] = []
    for tool in tools:
        if tool.name != "yara" or not tool.stdout.strip():
            continue
        is_packaged = any(arg.endswith(("pdf-risk.yar", "epub-risk.yar")) for arg in tool.argv)
        parsed = parse_yara_output(tool.stdout)
        if parsed:
            target = packaged if is_packaged else custom
            target.extend((tool, match) for match in parsed)

    lines = ["YARA Summary", "", "Packaged heuristic matches:"]
    if packaged:
        for tool, match in packaged:
            lines.extend(_format_yara_rule_match(match, "packaged heuristic", tool.stdout_artifact))
    else:
        lines.append("- none")
    lines.append("")
    lines.append("Custom rule matches:")
    if custom:
        for tool, match in custom:
            lines.extend(_format_yara_rule_match(match, "custom rule", tool.stdout_artifact))
    else:
        lines.append("- none")
    return "\n".join(lines) + "\n"


def _format_yara_rule_match(match: YaraRuleMatch, source: str, artifact: str | None) -> list[str]:
    details = packaged_rule_details(match.name) if source == "packaged heuristic" else {}
    lines = [
        f"Rule: {match.name}",
        f"Source: {source}",
        f"Target: {match.target}",
    ]
    if artifact:
        lines.append(f"Raw artifact: {artifact}")
    if match.metadata:
        lines.append("Metadata:")
        for key, value in sorted(match.metadata.items()):
            lines.append(f"- {key}: {value}")
    if details:
        lines.extend(
            [
                f"Purpose: {details['purpose']}",
                f"Risk posture: {details['risk']}",
                f"Why this matched: {details['why']}",
            ]
        )
    if match.strings:
        lines.append("Matched strings:")
        for string in match.strings[:20]:
            length = f" length={string.length}" if string.length is not None else ""
            lines.append(f"- {string.identifier} at {string.offset}{length}: {string.value}")
        if len(match.strings) > 20:
            lines.append(f"- ... {len(match.strings) - 20} additional matched strings in {artifact or 'raw output'}")
    else:
        lines.append("Matched strings: not captured; rerun with a scanner version that enables YARA string output.")
    lines.append("")
    return lines


def _pdf_structure_summary(qpdf_json: str) -> str:
    lines = ["PDF Structure Summary", ""]
    if not qpdf_json.strip():
        lines.append("qpdf.json was not available.")
        return "\n".join(lines) + "\n"

    try:
        data = json.loads(qpdf_json)
    except json.JSONDecodeError as exc:
        lines.append(f"qpdf.json could not be parsed: {exc}")
        return "\n".join(lines) + "\n"

    attachments = data.get("attachments")
    acroform = data.get("acroform")
    outlines = data.get("outlines")
    encrypt = data.get("encrypt")
    encrypted = encrypt.get("encrypted") if isinstance(encrypt, dict) else bool(encrypt)
    has_acroform = (
        acroform.get("hasacroform") if isinstance(acroform, dict) and "hasacroform" in acroform else bool(acroform)
    )
    lines.extend(
        [
            f"PDF version: {data.get('version', 'unknown')}",
            f"Pages: {len(data.get('pages') or [])}",
            f"Encrypted: {'yes' if encrypted else 'no'}",
            f"Attachments: {_count_mapping_or_list(attachments)}",
            f"AcroForm: {'present' if has_acroform else 'not present'}",
            f"Outlines: {_count_mapping_or_list(outlines)}",
        ]
    )
    return "\n".join(lines) + "\n"


def _pdf_risk_summary(risky_text: str) -> str:
    lines = ["PDF Risk Summary", ""]
    if not risky_text.strip():
        lines.append("No risky string matches were recorded.")
        return "\n".join(lines) + "\n"

    counts = Counter()
    ignored_near_matches = 0
    examples: dict[str, str] = {}
    for line in _analyst_lines(risky_text):
        for indicator in PDF_RISK_NAMES:
            if has_pdf_name(line, indicator):
                counts[indicator] += 1
                examples.setdefault(indicator, line[:220])
            elif re.search(re.escape(indicator), line, re.IGNORECASE):
                ignored_near_matches += 1

    if not counts:
        lines.append("No recognized PDF risk indicators were found in risky string output.")
    else:
        active = [name for name in ("/JavaScript", "/JS", "/Launch") if counts[name]]
        review_only = [name for name in PDF_RISK_NAMES if counts[name] and name not in active]
        lines.append(f"Confirmed active behavior indicators: {', '.join(active) if active else 'none'}")
        lines.append(f"Review-only indicators: {', '.join(review_only) if review_only else 'none'}")
        lines.append("")
        for indicator in PDF_RISK_NAMES:
            if counts[indicator]:
                lines.append(f"{indicator}: {counts[indicator]}")
                lines.append(f"  example: {examples[indicator]}")
    if ignored_near_matches:
        lines.append(f"Ignored noisy near-matches: {ignored_near_matches}")
    return "\n".join(lines) + "\n"


def _pdf_url_summary(risky_text: str, inventory_json: str = "") -> str:
    inventory = inventory_from_json(inventory_json) or extract_url_inventory(risky_text)
    return url_inventory_summary_text(inventory)


def _analyst_lines(text: str) -> list[str]:
    lines: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or "\x00" in stripped:
            continue
        if len(stripped) > 1000:
            stripped = stripped[:1000]
        lines.append(stripped)
    return lines


def _count_mapping_or_list(value: object) -> int:
    if isinstance(value, dict | list | tuple | set):
        return len(value)
    return 0
