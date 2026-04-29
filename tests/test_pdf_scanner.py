from __future__ import annotations

from pathlib import Path

from scannie.models import ScanOptions, ToolResult
from scannie.pdf import _read_pdf_text, has_pdf_name
from scannie.scanner import scan_document

from .fakes import empty_runner, mapping_runner


def test_clean_pdf_writes_low_verdict(clean_pdf: Path, tmp_path: Path) -> None:
    result = scan_document(clean_pdf, ScanOptions(report_dir=tmp_path / "report"), runner=empty_runner)
    assert result.verdict == "low"
    assert any(artifact.relative_path == "pdf-strings.txt" for artifact in result.artifacts)


def test_pdf_name_matching_rejects_substring_false_positives() -> None:
    assert has_pdf_name("<< /JS (app.alert(1)) >>", "/JS")
    assert has_pdf_name("<< /AA << /O 2 0 R >> >>", "/AA")
    assert not has_pdf_name("https://www.json.org/json-en.html", "/JS")
    assert not has_pdf_name("<</BaseFont /AAAAAB+DejaVuSans>>", "/AA")


def test_pdf_text_reader_respects_byte_limit(tmp_path: Path) -> None:
    path = tmp_path / "large.pdf"
    path.write_bytes(b"%PDF-1.4\n" + b"x" * 100)

    assert _read_pdf_text(path, limit=8) == "%PDF-1.4"


def test_pdf_open_action_with_javascript_is_high(risky_pdf: Path, tmp_path: Path) -> None:
    result = scan_document(risky_pdf, ScanOptions(report_dir=tmp_path / "report"), runner=empty_runner)
    assert result.verdict == "high"
    assert any(finding.category == "pdf-javascript-action" for finding in result.findings)


def test_pdf_navigation_open_action_with_links_is_review_not_high(tmp_path: Path) -> None:
    path = tmp_path / "book.pdf"
    path.write_bytes(
        b"%PDF-1.4\n"
        b"1 0 obj\n"
        b"<< /Type /Catalog /OpenAction [108 0 R /XYZ 0 648 0] >>\n"
        b"endobj\n"
        b"2 0 obj\n"
        b"<< /BaseFont /AAAAAB+DejaVuSans >>\n"
        b"endobj\n"
        b"3 0 obj\n"
        b"<< /Subtype/Link /A << /S /URI /URI (https://www.json.org/json-en.html) >> >>\n"
        b"endobj\n%%EOF\n"
    )
    result = scan_document(path, ScanOptions(report_dir=tmp_path / "report"), runner=empty_runner)
    assert result.verdict == "review"
    assert any(finding.category == "pdf-openaction-navigation" for finding in result.findings)
    assert any(finding.category == "pdf-link-indicators" for finding in result.findings)
    assert not any(finding.category == "pdf-javascript-action" for finding in result.findings)


def test_pdf_referenced_open_action_javascript_is_high(tmp_path: Path) -> None:
    path = tmp_path / "referenced-js.pdf"
    path.write_bytes(
        b"%PDF-1.4\n"
        b"1 0 obj\n"
        b"<< /Type /Catalog /OpenAction 2 0 R >>\n"
        b"endobj\n"
        b"2 0 obj\n"
        b"<< /S /JavaScript /JS (app.alert('x')) >>\n"
        b"endobj\n%%EOF\n"
    )
    result = scan_document(path, ScanOptions(report_dir=tmp_path / "report"), runner=empty_runner)
    assert result.verdict == "high"
    assert any(finding.category == "pdf-javascript-action" for finding in result.findings)


def test_pdf_indirect_page_additional_action_javascript_is_high(tmp_path: Path) -> None:
    path = tmp_path / "page-aa-js.pdf"
    path.write_bytes(
        b"%PDF-1.4\n"
        b"1 0 obj\n"
        b"<< /Type /Catalog /Pages 2 0 R >>\n"
        b"endobj\n"
        b"2 0 obj\n"
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>\n"
        b"endobj\n"
        b"3 0 obj\n"
        b"<< /Type /Page /Parent 2 0 R /AA << /O 4 0 R >> >>\n"
        b"endobj\n"
        b"4 0 obj\n"
        b"<< /S /JavaScript /JS (app.alert('x')) >>\n"
        b"endobj\n%%EOF\n"
    )

    result = scan_document(path, ScanOptions(report_dir=tmp_path / "report"), runner=empty_runner)

    assert result.verdict == "high"
    assert any(finding.category == "pdf-javascript-action" for finding in result.findings)


def test_pdf_launch_action_is_high(tmp_path: Path) -> None:
    path = tmp_path / "launch.pdf"
    path.write_bytes(b"%PDF-1.4\n1 0 obj\n<< /OpenAction << /S /Launch /F (calc.exe) >> >>\nendobj\n%%EOF\n")
    result = scan_document(path, ScanOptions(report_dir=tmp_path / "report"), runner=empty_runner)
    assert result.verdict == "high"
    assert any(finding.category == "pdf-launch-action" for finding in result.findings)


def test_pdf_attachment_listing_for_non_executable_is_review(clean_pdf: Path, tmp_path: Path) -> None:
    runner = mapping_runner(
        {
            "qpdf --list-attachments": ToolResult(
                "qpdf",
                ["qpdf"],
                "ok",
                returncode=0,
                stdout="notes.txt\n",
            )
        }
    )
    result = scan_document(clean_pdf, ScanOptions(report_dir=tmp_path / "report"), runner=runner)
    assert result.verdict == "review"
    assert any(finding.category == "pdf-attachment" for finding in result.findings)


def test_pdf_executable_attachment_listing_is_high(clean_pdf: Path, tmp_path: Path) -> None:
    runner = mapping_runner(
        {
            "qpdf --list-attachments": ToolResult(
                "qpdf",
                ["qpdf"],
                "ok",
                returncode=0,
                stdout="payload.exe\n",
            )
        }
    )
    result = scan_document(clean_pdf, ScanOptions(report_dir=tmp_path / "report"), runner=runner)
    assert result.verdict == "high"
    assert any(finding.category == "pdf-attachment" for finding in result.findings)


def test_pdf_no_embedded_files_message_is_not_high(clean_pdf: Path, tmp_path: Path) -> None:
    runner = mapping_runner(
        {
            "qpdf --list-attachments": ToolResult(
                "qpdf",
                ["qpdf"],
                "ok",
                returncode=0,
                stdout=f"{clean_pdf} has no embedded files\n",
            )
        }
    )
    result = scan_document(clean_pdf, ScanOptions(report_dir=tmp_path / "report"), runner=runner)
    assert result.verdict == "low"
    assert not any(finding.category == "pdf-embedded-file" for finding in result.findings)


def test_pdf_encrypt_marker_is_review(tmp_path: Path) -> None:
    path = tmp_path / "encrypted.pdf"
    path.write_bytes(b"%PDF-1.7\n<< /Encrypt 3 0 R >>\n%%EOF\n")
    result = scan_document(path, ScanOptions(report_dir=tmp_path / "report"), runner=empty_runner)
    assert result.verdict == "review"
    assert any(finding.category == "pdf-risk-indicator" for finding in result.findings)


def test_pdf_embedded_file_marker_alone_is_review(tmp_path: Path) -> None:
    path = tmp_path / "embedded-marker.pdf"
    path.write_bytes(b"%PDF-1.4\n1 0 obj\n<< /EmbeddedFile 2 0 R >>\nendobj\n%%EOF\n")
    result = scan_document(path, ScanOptions(report_dir=tmp_path / "report"), runner=empty_runner)
    assert result.verdict == "review"
    assert any(finding.category == "pdf-attachment" for finding in result.findings)
