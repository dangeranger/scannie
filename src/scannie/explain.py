from __future__ import annotations

from collections import Counter

from .detections import clamav_detected
from .models import Finding, ScanResult, ToolResult
from .yara import parse_yara_output

_SEVERITY_ORDER = {"error": 0, "high": 1, "review": 2, "info": 3}


def format_cli_text(result: ScanResult) -> str:
    lines = [
        f"Verdict: {result.verdict}",
        f"Report: {result.report_dir or 'unknown'}",
        "",
        *format_analysis_detail(result).splitlines(),
    ]
    return "\n".join(lines).rstrip() + "\n"


def format_analysis_detail(result: ScanResult) -> str:
    sections = [
        _format_why(result),
        _format_tool_status(result),
        _format_start_here(result),
    ]
    return "\n\n".join(section for section in sections if section).rstrip() + "\n"


def _format_why(result: ScanResult) -> str:
    lines = ["Why this verdict:"]
    if not result.findings:
        lines.append("- No high or review findings were produced.")
        return "\n".join(lines)

    findings = sorted(
        result.findings,
        key=lambda finding: (_SEVERITY_ORDER.get(finding.severity, 99), finding.category, finding.message),
    )
    for finding in findings[:10]:
        artifact = f" ({finding.artifact})" if finding.artifact else ""
        lines.append(f"- {finding.severity.upper()}: {finding.message}{artifact}")
    if len(findings) > 10:
        lines.append(f"- ... {len(findings) - 10} additional findings in summary.json")
    return "\n".join(lines)


def _format_tool_status(result: ScanResult) -> str:
    lines = ["Tool status:"]
    if not result.tools:
        lines.append("- No external tools were recorded.")
        return "\n".join(lines)

    for tool in result.tools:
        status = tool_status_label(tool)
        artifact = f" -> {tool.stdout_artifact}" if tool.stdout_artifact else ""
        lines.append(f"- {tool.name}: {status}{artifact}")
    return "\n".join(lines)


def tool_status_label(tool: ToolResult) -> str:
    if tool.missing:
        return "missing"
    if tool.timed_out:
        return "timeout"
    if (tool.name == "clamscan" or (tool.argv and tool.argv[0] == "clamscan")) and clamav_detected(tool):
        return "detection"
    if tool.name == "yara" and tool.stdout.strip():
        matches = parse_yara_output(tool.stdout)
        if matches:
            count = len(matches)
            return f"{count} rule match{'es' if count != 1 else ''}"
    if tool.status == "nonzero":
        return f"nonzero exit {tool.returncode}"
    return tool.status


def _format_start_here(result: ScanResult) -> str:
    lines = ["Start here:"]
    candidates = ["summary.txt", "artifact-index.txt", "tool-status.txt", "yara-summary.txt"]
    artifact_paths = {artifact.relative_path for artifact in result.artifacts}
    if result.file_type == "pdf":
        candidates.extend(["pdf-structure-summary.txt", "pdf-risk-summary.txt", "pdf-url-summary.txt"])
        if "url-reputation-summary.txt" in artifact_paths:
            candidates.append("url-reputation-summary.txt")
    elif result.file_type == "epub":
        candidates.append("epub-risky-content.txt")
    if "virustotal-summary.txt" in artifact_paths:
        candidates.append("virustotal-summary.txt")

    referenced = [finding.artifact for finding in result.findings if finding.artifact]
    for artifact in referenced:
        if artifact not in candidates:
            candidates.append(artifact)

    for name in candidates[:8]:
        lines.append(f"- {name}")
    return "\n".join(lines)


def finding_counts(findings: list[Finding]) -> Counter[str]:
    return Counter(finding.severity for finding in findings)
