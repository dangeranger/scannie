from __future__ import annotations

import zipfile
from pathlib import Path

from scannie.models import ScanOptions, ToolResult
from scannie.scanner import detect_document_type, scan_document

from .fakes import empty_runner, mapping_runner


def test_detect_document_type_from_extension(clean_pdf: Path, clean_epub: Path) -> None:
    assert detect_document_type(clean_pdf) == "pdf"
    assert detect_document_type(clean_epub) == "epub"
    assert detect_document_type(clean_pdf, force_type="epub") == "epub"


def test_detect_document_type_prefers_content_over_extension(clean_epub: Path, tmp_path: Path) -> None:
    epub_named_pdf = tmp_path / "book.pdf"
    epub_named_pdf.write_bytes(clean_epub.read_bytes())
    pdf_named_epub = tmp_path / "book.epub"
    pdf_named_epub.write_bytes(b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF\n")

    assert detect_document_type(epub_named_pdf) == "epub"
    assert detect_document_type(pdf_named_epub) == "pdf"


def test_detect_document_type_ignores_encrypted_zip_mimetype_runtime_error(
    monkeypatch,
    tmp_path: Path,  # type: ignore[no-untyped-def]
) -> None:
    class FakeArchive:
        def __enter__(self) -> FakeArchive:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def read(self, name: str, pwd: None = None) -> bytes:
            raise RuntimeError("password required")

    path = tmp_path / "encrypted.zip"
    path.write_bytes(b"PK\x03\x04")
    monkeypatch.setattr(zipfile, "is_zipfile", lambda candidate: True)
    monkeypatch.setattr(zipfile, "ZipFile", lambda candidate: FakeArchive())

    assert detect_document_type(path) is None


def test_unsupported_file_returns_error(tmp_path: Path) -> None:
    path = tmp_path / "note.txt"
    path.write_text("hello")
    result = scan_document(path, ScanOptions(report_dir=tmp_path / "report"), runner=empty_runner)
    assert result.verdict == "error"
    assert result.errors == ["Unsupported file type"]


def test_missing_optional_tools_are_recorded_but_do_not_fail_clean_scan(clean_pdf: Path, tmp_path: Path) -> None:
    result = scan_document(clean_pdf, ScanOptions(report_dir=tmp_path / "report"), runner=empty_runner)
    assert result.file_type == "pdf"
    assert result.sha256 is not None
    assert result.verdict == "low"
    assert any("Missing optional tool" in error for error in result.errors)


def test_clamav_hit_forces_high(clean_pdf: Path, tmp_path: Path) -> None:
    runner = mapping_runner(
        {
            "clamscan --infected": ToolResult(
                "clamscan",
                ["clamscan"],
                "nonzero",
                returncode=1,
                stdout="/tmp/doc.pdf: Eicar-Test-Signature FOUND\n",
            )
        }
    )
    result = scan_document(clean_pdf, ScanOptions(report_dir=tmp_path / "report"), runner=runner)
    assert result.verdict == "high"
    assert any(finding.category == "av-detection" for finding in result.findings)


def test_clamav_found_in_path_without_detection_does_not_force_high(tmp_path: Path) -> None:
    directory = tmp_path / "FOUND"
    directory.mkdir()
    path = directory / "doc.pdf"
    path.write_bytes(b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF\n")
    runner = mapping_runner(
        {
            "clamscan --infected": ToolResult(
                "clamscan",
                ["clamscan"],
                "ok",
                returncode=0,
                stdout=f"{path}: OK\n",
            )
        }
    )

    result = scan_document(path, ScanOptions(report_dir=tmp_path / "report"), runner=runner)

    assert result.verdict == "low"
    assert not any(finding.category == "av-detection" for finding in result.findings)


def test_clamav_error_text_found_does_not_force_high(clean_pdf: Path, tmp_path: Path) -> None:
    runner = mapping_runner(
        {
            "clamscan --infected": ToolResult(
                "clamscan",
                ["clamscan"],
                "nonzero",
                returncode=2,
                stderr="LibClamAV Error: parser failed before FOUND marker\n",
            )
        }
    )

    result = scan_document(clean_pdf, ScanOptions(report_dir=tmp_path / "report"), runner=runner)

    assert result.verdict == "low"
    assert not any(finding.category == "av-detection" for finding in result.findings)


def test_packaged_yara_match_is_review_not_high(clean_pdf: Path, tmp_path: Path) -> None:
    def runner(argv: list[str], timeout: int) -> ToolResult:
        if argv[0] == "yara":
            return ToolResult(
                "yara",
                argv,
                "ok",
                returncode=0,
                stdout=f"PDF_Risky_Actions {clean_pdf}\n",
            )
        return empty_runner(argv, timeout)

    result = scan_document(clean_pdf, ScanOptions(report_dir=tmp_path / "report"), runner=runner)
    assert result.verdict == "review"
    assert any(finding.category == "heuristic-yara-match" for finding in result.findings)
    assert not any(finding.category == "yara-detection" for finding in result.findings)


def test_yara_stdout_warning_does_not_create_match(clean_pdf: Path, tmp_path: Path) -> None:
    def runner(argv: list[str], timeout: int) -> ToolResult:
        if argv[0] == "yara":
            return ToolResult("yara", argv, "ok", returncode=0, stdout="warning: slow scan mode enabled\n")
        return empty_runner(argv, timeout)

    result = scan_document(clean_pdf, ScanOptions(report_dir=tmp_path / "report"), runner=runner)

    assert result.verdict == "low"
    assert not any(finding.category == "heuristic-yara-match" for finding in result.findings)


def test_pdf_scan_uses_pdf_packaged_yara_rules_only(clean_pdf: Path, tmp_path: Path) -> None:
    seen_yara_argvs: list[list[str]] = []

    def runner(argv: list[str], timeout: int) -> ToolResult:
        if argv[0] == "yara":
            seen_yara_argvs.append(argv)
            return ToolResult("yara", argv, "ok", returncode=0, stdout="")
        return empty_runner(argv, timeout)

    scan_document(clean_pdf, ScanOptions(report_dir=tmp_path / "report"), runner=runner)
    assert seen_yara_argvs
    assert all(any("pdf-risk.yar" in part for part in argv) for argv in seen_yara_argvs)
    assert not any(any("epub-risk.yar" in part for part in argv) for argv in seen_yara_argvs)


def test_yara_scans_print_rule_metadata_and_matching_strings(clean_pdf: Path, tmp_path: Path) -> None:
    seen_yara_argvs: list[list[str]] = []

    def runner(argv: list[str], timeout: int) -> ToolResult:
        if argv[0] == "yara":
            seen_yara_argvs.append(argv)
            return ToolResult("yara", argv, "ok", returncode=0, stdout="")
        return empty_runner(argv, timeout)

    scan_document(clean_pdf, ScanOptions(report_dir=tmp_path / "report"), runner=runner)
    assert seen_yara_argvs
    assert all("--print-meta" in argv for argv in seen_yara_argvs)
    assert all("--print-strings" in argv for argv in seen_yara_argvs)
    assert all("--print-string-length" in argv for argv in seen_yara_argvs)


def test_custom_yara_match_is_high(clean_pdf: Path, tmp_path: Path) -> None:
    custom_rules = tmp_path / "custom.yar"
    custom_rules.write_text("rule Custom { condition: true }\n")

    def runner(argv: list[str], timeout: int) -> ToolResult:
        if argv[0] == "yara" and str(custom_rules) in argv:
            return ToolResult(
                "yara",
                argv,
                "ok",
                returncode=0,
                stdout=f"Custom {clean_pdf}\n",
            )
        return empty_runner(argv, timeout)

    result = scan_document(
        clean_pdf,
        ScanOptions(report_dir=tmp_path / "report", rules=[custom_rules]),
        runner=runner,
    )
    assert result.verdict == "high"
    assert any(finding.category == "custom-yara-match" for finding in result.findings)


def test_yara_artifact_names_identify_packaged_and_custom_rules(clean_pdf: Path, tmp_path: Path) -> None:
    custom_rules = tmp_path / "custom.yar"
    custom_rules.write_text("rule Custom { condition: true }\n")

    result = scan_document(
        clean_pdf,
        ScanOptions(report_dir=tmp_path / "report", rules=[custom_rules]),
        runner=empty_runner,
    )

    artifact_paths = {artifact.relative_path for artifact in result.artifacts}
    assert "yara-packaged.txt" in artifact_paths
    assert "yara-rule-1.txt" in artifact_paths
    assert "yara-original.txt" not in artifact_paths
