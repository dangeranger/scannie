from __future__ import annotations

import json
import re
from collections.abc import Callable
from pathlib import Path

from .models import SEVERITY_HIGH, SEVERITY_REVIEW, ScanOptions, ScanResult, ToolResult
from .url_reputation import extract_url_inventory

PDF_RISK_NAMES = [
    "/JS",
    "/JavaScript",
    "/AA",
    "/OpenAction",
    "/Launch",
    "/EmbeddedFile",
    "/RichMedia",
    "/URI",
    "/SubmitForm",
    "/GoToE",
    "/AcroForm",
    "/XFA",
    "/Encrypt",
    "/ObjStm",
]

# Markers with dedicated classifiers are intentionally absent here: actions,
# attachments, and URI/link indicators get more specific findings.
PDF_REVIEW_MARKERS = {
    "/RichMedia": "PDF contains rich media content",
    "/SubmitForm": "PDF contains form submission behavior",
    "/GoToE": "PDF contains embedded go-to actions",
    "/AcroForm": "PDF contains interactive form content",
    "/XFA": "PDF contains XFA form content",
    "/Encrypt": "PDF is encrypted or contains encryption markers",
    "/ObjStm": "PDF uses object streams, which can obscure structure",
}

# PDF attachments model local extracted filenames, so this intentionally differs
# from URL executable-path suffixes used for remote links.
EXECUTABLE_ATTACHMENT_SUFFIXES = {
    ".app",
    ".bat",
    ".cmd",
    ".com",
    ".command",
    ".dll",
    ".dmg",
    ".dylib",
    ".exe",
    ".jar",
    ".msi",
    ".pkg",
    ".scr",
    ".sh",
}
PDF_TEXT_READ_LIMIT = 25 * 1024 * 1024
RecordedToolRunner = Callable[[str, list[str], str], ToolResult]
YaraRunner = Callable[..., ToolResult]


def has_pdf_name(text: str, name: str) -> bool:
    bare = name[1:] if name.startswith("/") else name
    return re.search(rf"/{re.escape(bare)}(?=$|[\s<>\[\]\(\)\{{\}}/%])", text, re.IGNORECASE) is not None


def scan_pdf(
    path: Path,
    result: ScanResult,
    options: ScanOptions,
    run_recorded_tool: RecordedToolRunner,
    run_yara: YaraRunner,
) -> None:
    qpdf_check = run_recorded_tool("qpdf-check", ["qpdf", "--check", str(path)], "qpdf-check.txt")
    attachments = run_recorded_tool(
        "qpdf-attachments",
        ["qpdf", "--list-attachments", str(path)],
        "qpdf-attachments.txt",
    )
    qpdf_json = run_recorded_tool("qpdf-json", ["qpdf", "--json", str(path)], "qpdf.json")

    parser_output = qpdf_check.stdout + qpdf_check.stderr + attachments.stdout + attachments.stderr + qpdf_json.stderr
    if _has_parser_warning(parser_output):
        result.add_finding(
            SEVERITY_REVIEW,
            "pdf-parser",
            "PDF parser warnings were reported",
            source="qpdf",
            artifact="qpdf-check.txt",
        )

    attachment_names = _attachment_listing_entries(attachments.stdout)
    if attachment_names:
        executable_names = [name for name in attachment_names if _is_executable_attachment(name)]
        severity = SEVERITY_HIGH if executable_names else SEVERITY_REVIEW
        message = (
            "qPDF listed one or more executable-looking attachments"
            if executable_names
            else "qPDF listed one or more non-executable attachments"
        )
        result.add_finding(
            severity,
            "pdf-attachment",
            message,
            source="qpdf",
            artifact="qpdf-attachments.txt",
        )

    # The direct text pass does not inflate arbitrary compressed streams; qPDF's
    # QDF output is the static normalization pass that can expose hidden actions.
    qdf_path = _artifact_root(options) / "qdf.pdf"
    qdf = run_recorded_tool(
        "qpdf-qdf",
        ["qpdf", "--qdf", "--object-streams=disable", str(path), str(qdf_path)],
        "qpdf-qdf.txt",
    )
    if qdf.returncode == 0 and qdf_path.exists():
        result.add_artifact(
            "qdf-pdf",
            "qdf.pdf",
            qdf_path.read_bytes(),
            description="qPDF normalized PDF",
            binary=True,
        )
        run_yara(qdf_path, "yara-qdf-pdf.txt", recursive=False)

    strings_result = run_recorded_tool("strings", ["strings", "-a", str(path)], "pdf-strings.txt")
    search_text = _read_pdf_text(path)
    if qdf_path.exists():
        search_text += "\n" + _read_pdf_text(qdf_path)
    if strings_result.stdout:
        search_text += "\n" + strings_result.stdout

    risky_lines = _risk_lines(search_text)
    if risky_lines:
        result.add_artifact(
            "pdf-risky-strings",
            "pdf-risky-strings.txt",
            "\n".join(risky_lines) + "\n",
            description="PDF risky indicator matches",
        )
    inventory = extract_url_inventory(search_text)
    if inventory.urls or inventory.discarded_count:
        result.add_artifact(
            "url-inventory",
            "url-inventory.json",
            json.dumps(inventory.to_dict(), indent=2, sort_keys=True) + "\n",
            description="Structured URL inventory",
            role="summary",
        )
    _classify_pdf_indicators(result, search_text)


def _artifact_root(options: ScanOptions) -> Path:
    if options.report_dir:
        options.report_dir.mkdir(parents=True, exist_ok=True)
        return options.report_dir
    return Path.cwd()


def _read_pdf_text(path: Path, limit: int = PDF_TEXT_READ_LIMIT) -> str:
    try:
        with path.open("rb") as file:
            return file.read(limit).decode("latin-1", errors="ignore")
    except OSError:
        return ""


def _risk_lines(text: str) -> list[str]:
    matches: list[str] = []
    for number, line in enumerate(text.splitlines(), start=1):
        if any(has_pdf_name(line, name) for name in PDF_RISK_NAMES) or re.search(r"https?://", line, re.IGNORECASE):
            matches.append(f"{number}:{line[:500]}")
    return matches


def _classify_pdf_indicators(result: ScanResult, text: str) -> None:
    action_risks = _classify_pdf_actions(text)
    if "javascript" in action_risks:
        result.add_finding(
            SEVERITY_HIGH,
            "pdf-javascript-action",
            "PDF contains an OpenAction or additional action that resolves to JavaScript",
            source="static-pdf",
            artifact="pdf-risky-strings.txt",
        )
    if "launch" in action_risks or has_pdf_name(text, "/Launch"):
        result.add_finding(
            SEVERITY_HIGH,
            "pdf-launch-action",
            "PDF contains a Launch action",
            source="static-pdf",
            artifact="pdf-risky-strings.txt",
        )
    if "navigation" in action_risks:
        result.add_finding(
            SEVERITY_REVIEW,
            "pdf-openaction-navigation",
            "PDF contains an OpenAction that appears to navigate to an initial view",
            source="static-pdf",
            artifact="pdf-risky-strings.txt",
        )
    elif has_pdf_name(text, "/OpenAction"):
        result.add_finding(
            SEVERITY_REVIEW,
            "pdf-openaction-navigation",
            "PDF contains an OpenAction without confirmed JavaScript or Launch behavior",
            source="static-pdf",
            artifact="pdf-risky-strings.txt",
        )

    if has_pdf_name(text, "/EmbeddedFile"):
        result.add_finding(
            SEVERITY_REVIEW,
            "pdf-attachment",
            "PDF contains embedded-file markers",
            source="static-pdf",
            artifact="pdf-risky-strings.txt",
        )

    if has_pdf_name(text, "/URI") or re.search(r"https?://", text, re.IGNORECASE):
        result.add_finding(
            SEVERITY_REVIEW,
            "pdf-link-indicators",
            "PDF contains URI actions or remote URLs",
            source="static-pdf",
            artifact="pdf-risky-strings.txt",
        )

    for marker, message in PDF_REVIEW_MARKERS.items():
        if has_pdf_name(text, marker):
            result.add_finding(
                SEVERITY_REVIEW,
                "pdf-risk-indicator",
                message,
                source="static-pdf",
                artifact="pdf-risky-strings.txt",
            )


def _has_parser_warning(output: str) -> bool:
    return bool(re.search(r"\b(warning|error|damaged|xref)\b", output, re.IGNORECASE))


def _attachment_listing_entries(output: str) -> list[str]:
    stripped = output.strip()
    if not stripped:
        return []
    lowered = stripped.lower()
    if "no attachments" in lowered or "no embedded files" in lowered:
        return []
    return [line.strip() for line in stripped.splitlines() if line.strip()]


def _is_executable_attachment(name: str) -> bool:
    lowered = name.lower()
    return any(lowered.endswith(suffix) for suffix in EXECUTABLE_ATTACHMENT_SUFFIXES)


def _classify_pdf_actions(text: str) -> set[str]:
    risks: set[str] = set()
    objects = _pdf_objects(text)
    for segment in _action_segments(text, objects):
        if has_pdf_name(segment, "/Launch"):
            risks.add("launch")
        if has_pdf_name(segment, "/JavaScript") or has_pdf_name(segment, "/JS"):
            risks.add("javascript")
        if segment.lstrip().startswith("[") and has_pdf_name(segment, "/XYZ"):
            risks.add("navigation")
    return risks


def _pdf_objects(text: str) -> dict[str, str]:
    objects: dict[str, str] = {}
    for match in re.finditer(r"(?ms)\b(\d+)\s+\d+\s+obj\b(.*?)\bendobj\b", text):
        objects[match.group(1)] = match.group(2)
    return objects


def _action_segments(text: str, objects: dict[str, str]) -> list[str]:
    segments: list[str] = []
    for marker in ("/OpenAction", "/AA"):
        for ref in re.finditer(rf"{re.escape(marker)}\s+(\d+)\s+\d+\s+R\b", text, re.IGNORECASE):
            body = objects.get(ref.group(1))
            if body:
                segments.extend(_expand_action_segment(body, objects))
        for dictionary in re.finditer(rf"{re.escape(marker)}\s*(<<.*?>>)", text, re.IGNORECASE | re.DOTALL):
            segments.extend(_expand_action_segment(dictionary.group(1), objects))
        for array in re.finditer(rf"{re.escape(marker)}\s*(\[[^\]]+\])", text, re.IGNORECASE | re.DOTALL):
            segments.extend(_expand_action_segment(array.group(1), objects))
    return segments


def _expand_action_segment(segment: str, objects: dict[str, str], depth: int = 1) -> list[str]:
    segments = [segment]
    if depth <= 0:
        return segments
    for ref in re.finditer(r"\b(\d+)\s+\d+\s+R\b", segment):
        body = objects.get(ref.group(1))
        if body:
            segments.extend(_expand_action_segment(body, objects, depth - 1))
    return segments
