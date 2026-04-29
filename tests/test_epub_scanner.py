from __future__ import annotations

import io
import zipfile
from pathlib import Path
from typing import ClassVar

from scannie.epub import UnsafeArchiveError, safe_extract_epub
from scannie.models import ScanOptions, ToolResult
from scannie.scanner import scan_document

from .fakes import empty_runner, mapping_runner


def test_safe_extract_rejects_path_traversal(tmp_path: Path) -> None:
    path = tmp_path / "traversal.epub"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("../evil", "bad")
    try:
        safe_extract_epub(path, tmp_path / "out", 1024)
    except UnsafeArchiveError as exc:
        assert "path traversal" in str(exc)
    else:
        raise AssertionError("expected UnsafeArchiveError")


def test_safe_extract_rejects_large_expanded_size(tmp_path: Path) -> None:
    path = tmp_path / "large.epub"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("mimetype", "application/epub+zip")
        archive.writestr("big.txt", "x" * 20)
    try:
        safe_extract_epub(path, tmp_path / "out", 10)
    except UnsafeArchiveError as exc:
        assert "large expanded EPUB" in str(exc)
    else:
        raise AssertionError("expected UnsafeArchiveError")


def test_safe_extract_counts_actual_decompressed_bytes(monkeypatch, tmp_path: Path) -> None:
    class FakeInfo:
        def __init__(self, filename: str, file_size: int) -> None:
            self.filename = filename
            self.file_size = file_size

        def is_dir(self) -> bool:
            return False

    class FakeArchive:
        data: ClassVar[dict[str, bytes]] = {
            "mimetype": b"application/epub+zip",
            "big.txt": b"x" * 20,
        }

        def __enter__(self) -> FakeArchive:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def infolist(self) -> list[FakeInfo]:
            return [FakeInfo("mimetype", 1), FakeInfo("big.txt", 1)]

        def open(self, info: FakeInfo) -> io.BytesIO:
            return io.BytesIO(self.data[info.filename])

        def extractall(self, out: Path) -> None:
            for filename, content in self.data.items():
                target = out / filename
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)

    monkeypatch.setattr("scannie.epub.zipfile.ZipFile", lambda path: FakeArchive())

    try:
        safe_extract_epub(tmp_path / "lying.epub", tmp_path / "out", 10)
    except UnsafeArchiveError as exc:
        assert "large expanded EPUB" in str(exc)
    else:
        raise AssertionError("expected UnsafeArchiveError")


def test_clean_epub_returns_low(clean_epub: Path, tmp_path: Path) -> None:
    result = scan_document(clean_epub, ScanOptions(report_dir=tmp_path / "report"), runner=empty_runner)
    assert result.verdict == "low"
    assert (tmp_path / "report" / "expanded-epub").exists()


def test_epub_active_content_returns_review(risky_epub: Path, tmp_path: Path) -> None:
    result = scan_document(risky_epub, ScanOptions(report_dir=tmp_path / "report"), runner=empty_runner)
    assert result.verdict == "review"
    assert any(finding.category == "epub-active-content" for finding in result.findings)


def test_epub_active_content_after_null_padding_returns_review(tmp_path: Path) -> None:
    path = tmp_path / "nul-padded.epub"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("mimetype", "application/epub+zip")
        archive.writestr(
            "OEBPS/content.xhtml",
            b"\x00" * 256 + b"<html><script>fetch('https://example.test')</script></html>",
        )

    result = scan_document(path, ScanOptions(report_dir=tmp_path / "report"), runner=empty_runner)

    assert result.verdict == "review"
    assert any(finding.category == "epub-active-content" for finding in result.findings)


def test_recursive_epub_clamav_detection_forces_high(clean_epub: Path, tmp_path: Path) -> None:
    runner = mapping_runner(
        {
            "clamscan --recursive": ToolResult(
                "clamscan",
                ["clamscan"],
                "nonzero",
                returncode=1,
                stdout=f"{tmp_path}/report/expanded-epub/OEBPS/payload: Eicar-Test-Signature FOUND\n",
            )
        }
    )

    result = scan_document(clean_epub, ScanOptions(report_dir=tmp_path / "report"), runner=runner)

    assert result.verdict == "high"
    assert any(finding.category == "av-detection" for finding in result.findings)


def test_epub_executable_returns_high(tmp_path: Path) -> None:
    path = tmp_path / "exe.epub"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("mimetype", "application/epub+zip")
        archive.writestr("OEBPS/payload", b"\x7fELF" + b"\x00" * 20)
    result = scan_document(path, ScanOptions(report_dir=tmp_path / "report"), runner=empty_runner)
    assert result.verdict == "high"
    assert any(finding.category == "epub-executable" for finding in result.findings)
