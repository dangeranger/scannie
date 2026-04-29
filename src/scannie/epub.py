from __future__ import annotations

import os
import re
import zipfile
from collections.abc import Callable
from pathlib import Path

from .detections import clamav_detected
from .models import SEVERITY_ERROR, SEVERITY_HIGH, SEVERITY_REVIEW, ScanOptions, ScanResult, ToolResult

EPUB_RISK_PATTERN = re.compile(
    r"(<script|javascript:|onload=|onclick=|onerror=|eval\(|fetch\(|"
    r"XMLHttpRequest|WebSocket|localStorage|sessionStorage|<iframe|<object|"
    r"<embed|@import|url\(|https?://|data:)",
    re.IGNORECASE,
)

EPUB_REVIEW_MARKERS = {
    "<script": "EPUB contains script tags",
    "javascript:": "EPUB contains javascript: URLs",
    "onload=": "EPUB contains event handlers",
    "onclick=": "EPUB contains event handlers",
    "onerror=": "EPUB contains event handlers",
    "eval(": "EPUB contains dynamic JavaScript evaluation",
    "fetch(": "EPUB contains network fetch calls",
    "XMLHttpRequest": "EPUB contains XMLHttpRequest usage",
    "WebSocket": "EPUB contains WebSocket usage",
    "localStorage": "EPUB contains localStorage usage",
    "sessionStorage": "EPUB contains sessionStorage usage",
    "<iframe": "EPUB contains iframe content",
    "<object": "EPUB contains object embeds",
    "<embed": "EPUB contains embedded content tags",
    "@import": "EPUB contains CSS imports",
    "url(": "EPUB contains CSS URL references",
}

EXECUTABLE_MAGIC = {
    b"\x7fELF": "ELF executable",
    b"MZ": "Windows PE executable",
    b"\xfe\xed\xfa\xce": "Mach-O executable",
    b"\xfe\xed\xfa\xcf": "Mach-O executable",
    b"\xce\xfa\xed\xfe": "Mach-O executable",
    b"\xcf\xfa\xed\xfe": "Mach-O executable",
}
BINARY_RESOURCE_MAGIC = (
    b"\x89PNG\r\n\x1a\n",
    b"\xff\xd8\xff",
    b"GIF87a",
    b"GIF89a",
    b"OTTO",
    b"PK\x03\x04",
    b"%PDF-",
    b"\x1f\x8b",
    b"wOFF",
    b"wOF2",
)
EXTRACT_CHUNK_SIZE = 1024 * 1024
TEXT_READ_LIMIT = 2_000_000
RecordedToolRunner = Callable[[str, list[str], str], ToolResult]
YaraRunner = Callable[..., ToolResult]


class UnsafeArchiveError(Exception):
    pass


def safe_extract_epub(epub: Path, out: Path, max_total: int) -> None:
    out = out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    total = 0
    with zipfile.ZipFile(epub) as archive:
        for info in archive.infolist():
            target = (out / info.filename).resolve()
            if os.path.commonpath([str(out), str(target)]) != str(out):
                raise UnsafeArchiveError(f"Refusing path traversal entry: {info.filename}")
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as source, target.open("wb") as destination:
                while chunk := source.read(EXTRACT_CHUNK_SIZE):
                    next_total = total + len(chunk)
                    if next_total > max_total:
                        raise UnsafeArchiveError(f"Refusing large expanded EPUB: {next_total} bytes")
                    destination.write(chunk)
                    total = next_total


def scan_epub(
    path: Path,
    result: ScanResult,
    options: ScanOptions,
    run_recorded_tool: RecordedToolRunner,
    run_yara: YaraRunner,
) -> None:
    run_recorded_tool("epubcheck", ["epubcheck", str(path)], "epubcheck.txt")
    run_recorded_tool("zipinfo", ["zipinfo", "-1", str(path)], "epub-file-list.txt")

    expanded = _artifact_root(options) / "expanded-epub"
    try:
        safe_extract_epub(path, expanded, options.max_expanded_size)
    except UnsafeArchiveError as exc:
        result.add_finding(
            SEVERITY_HIGH,
            "epub-archive",
            str(exc),
            source="safe-extract",
        )
        return
    except zipfile.BadZipFile as exc:
        result.add_finding(
            SEVERITY_ERROR,
            "epub-archive",
            f"EPUB is not a valid ZIP container: {exc}",
            source="safe-extract",
        )
        result.errors.append(str(exc))
        return

    files = [file for file in expanded.rglob("*") if file.is_file()]
    if files:
        run_recorded_tool("file-expanded-epub", ["file", *map(str, files)], "epub-file-types.txt")
        run_recorded_tool(
            "rg-epub-risky-content",
            ["rg", "-n", "-i", EPUB_RISK_PATTERN.pattern, str(expanded)],
            "epub-risky-content.txt",
        )

    clamscan = run_recorded_tool(
        "clamscan-expanded-epub",
        ["clamscan", "--recursive", "--infected", "--alert-encrypted=yes", str(expanded)],
        "epub-expanded-clamscan.txt",
    )
    if clamav_detected(clamscan):
        result.add_finding(
            SEVERITY_HIGH,
            "av-detection",
            "ClamAV reported a detection inside the expanded EPUB",
            source="clamscan",
            artifact="epub-expanded-clamscan.txt",
        )
    run_yara(expanded, "yara-expanded-epub.txt", recursive=True)

    _classify_epub_files(result, files, expanded)


def _artifact_root(options: ScanOptions) -> Path:
    if options.report_dir:
        options.report_dir.mkdir(parents=True, exist_ok=True)
        return options.report_dir
    return Path.cwd()


def _classify_epub_files(result: ScanResult, files: list[Path], root: Path) -> None:
    risky_lines: list[str] = []
    for file in files:
        executable = _detect_executable(file)
        rel = str(file.relative_to(root))
        if executable:
            result.add_finding(
                SEVERITY_HIGH,
                "epub-executable",
                f"EPUB contains {executable}: {rel}",
                source="static-epub",
                artifact="epub-file-types.txt",
            )
            continue

        text = _read_textish(file)
        if not text:
            continue
        for number, line in enumerate(text.splitlines(), start=1):
            if EPUB_RISK_PATTERN.search(line):
                risky_lines.append(f"{rel}:{number}:{line[:500]}")
        _classify_epub_text(result, text)

    if risky_lines:
        result.add_artifact(
            "epub-risky-content",
            "epub-risky-content.txt",
            "\n".join(risky_lines) + "\n",
            description="EPUB active content and remote reference matches",
        )


def _detect_executable(path: Path) -> str | None:
    try:
        head = path.read_bytes()[:256]
    except OSError:
        return None
    for magic, label in EXECUTABLE_MAGIC.items():
        if head.startswith(magic):
            return label
    if head.startswith(b"#!") and any(shell in head for shell in (b"/bin/sh", b"/bin/bash", b"/usr/bin/env sh")):
        return "shell script"
    return None


def _read_textish(path: Path) -> str:
    try:
        data = path.read_bytes()[:TEXT_READ_LIMIT]
    except OSError:
        return ""
    if any(data.startswith(magic) for magic in BINARY_RESOURCE_MAGIC):
        return ""
    return data.replace(b"\x00", b"\n").decode("utf-8", errors="ignore")


def _classify_epub_text(result: ScanResult, text: str) -> None:
    seen: set[str] = set()
    for marker, message in EPUB_REVIEW_MARKERS.items():
        if marker in seen:
            continue
        if re.search(re.escape(marker), text, re.IGNORECASE):
            seen.add(marker)
            result.add_finding(
                SEVERITY_REVIEW,
                "epub-active-content",
                message,
                source="static-epub",
                artifact="epub-risky-content.txt",
            )

    if re.search(r"https?://", text, re.IGNORECASE):
        result.add_finding(
            SEVERITY_REVIEW,
            "epub-remote-resource",
            "EPUB contains one or more remote HTTP resources",
            source="static-epub",
            artifact="epub-risky-content.txt",
        )

    if re.search(r"\bdata:", text, re.IGNORECASE):
        result.add_finding(
            SEVERITY_REVIEW,
            "epub-embedded-data",
            "EPUB contains data: URLs",
            source="static-epub",
            artifact="epub-risky-content.txt",
        )
