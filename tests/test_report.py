from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from scannie.models import ScanResult, ToolResult
from scannie.report import ReportWriter


def test_report_writer_creates_timestamped_directory_and_required_files(tmp_path: Path) -> None:
    writer = ReportWriter(clock=lambda: datetime(2026, 4, 29, 12, 30, 0))
    result = ScanResult(input_path=str(tmp_path / "doc.pdf"), file_name="doc.pdf", verdict="low")
    result.add_artifact("file", "file.txt", "PDF document\n")

    report_dir = writer.create_report_dir(Path("doc.pdf"), tmp_path)
    writer.write(result, report_dir)

    assert report_dir.name == "triage-doc.pdf-20260429-123000"
    assert (report_dir / "file.txt").read_text() == "PDF document\n"
    assert (report_dir / "summary.txt").exists()
    payload = json.loads((report_dir / "summary.json").read_text())
    assert payload["verdict"] == "low"
    assert payload["artifacts"][0]["path"] == "file.txt"


def test_summary_text_uses_analyst_explanation(tmp_path: Path) -> None:
    writer = ReportWriter(clock=lambda: datetime(2026, 4, 29, 12, 30, 0))
    result = ScanResult(input_path=str(tmp_path / "doc.pdf"), file_name="doc.pdf", verdict="review")
    result.add_finding(
        "review",
        "pdf-risk-indicator",
        "PDF contains JavaScript indicators",
        artifact="pdf-risk-summary.txt",
    )
    result.tools.append(ToolResult("qpdf-check", ["qpdf", "--check", "doc.pdf"], "ok", returncode=0))

    report_dir = writer.create_report_dir(Path("doc.pdf"), tmp_path)
    writer.write(result, report_dir)

    summary = (report_dir / "summary.txt").read_text()
    assert "Why this verdict:" in summary
    assert "Tool status:" in summary
    assert "Start here:" in summary
    assert "PDF contains JavaScript indicators" in summary


def test_report_writer_adds_artifact_metadata_and_generic_summaries(tmp_path: Path) -> None:
    writer = ReportWriter(clock=lambda: datetime(2026, 4, 29, 12, 30, 0))
    result = ScanResult(input_path=str(tmp_path / "doc.pdf"), file_name="doc.pdf", verdict="review")
    result.add_finding(
        "review",
        "heuristic-yara-match",
        "Packaged heuristic YARA rule matched risky document content",
        artifact="yara-packaged.txt",
    )
    result.tools.append(
        ToolResult(
            "yara",
            ["yara", "doc-risk.yar", "doc.pdf"],
            "ok",
            returncode=0,
            stdout=(
                'PDF_Risky_Actions [description="Flags PDF active content indicators", severity="review"] doc.pdf\n'
                "0x0:5:$pdf: %PDF-\n"
                "0x80:11:$open: /OpenAction\n"
            ),
            stdout_artifact="yara-packaged.txt",
        )
    )
    result.add_artifact(
        "yara",
        "yara-packaged.txt",
        'PDF_Risky_Actions [description="Flags PDF active content indicators", severity="review"] doc.pdf\n'
        "0x0:5:$pdf: %PDF-\n"
        "0x80:11:$open: /OpenAction\n",
        role="raw",
    )

    report_dir = writer.create_report_dir(Path("doc.pdf"), tmp_path)
    writer.write(result, report_dir)

    assert (report_dir / "artifact-index.txt").exists()
    assert (report_dir / "tool-status.txt").exists()
    assert (report_dir / "yara-summary.txt").exists()
    assert "yara-packaged.txt" in (report_dir / "artifact-index.txt").read_text()
    assert "yara: 1 rule match" in (report_dir / "tool-status.txt").read_text()
    assert "PDF_Risky_Actions" in (report_dir / "yara-summary.txt").read_text()

    payload = json.loads((report_dir / "summary.json").read_text())
    artifact = next(item for item in payload["artifacts"] if item["path"] == "yara-packaged.txt")
    assert artifact["role"] == "raw"
    assert artifact["size_bytes"] > 0


def test_yara_summary_explains_rule_source_purpose_and_matched_strings(tmp_path: Path) -> None:
    writer = ReportWriter(clock=lambda: datetime(2026, 4, 29, 12, 30, 0))
    result = ScanResult(input_path=str(tmp_path / "doc.pdf"), file_name="doc.pdf", verdict="review")
    result.tools.append(
        ToolResult(
            "yara",
            ["yara", "--print-meta", "--print-strings", "--print-string-length", "pdf-risk.yar", "doc.pdf"],
            "ok",
            returncode=0,
            stdout=(
                'PDF_Risky_Actions [description="Flags PDF active content indicators", severity="review"] doc.pdf\n'
                "0x0:5:$pdf: %PDF-\n"
                "0x80:11:$open: /OpenAction\n"
                "0x90:3:$js1: /JS\n"
            ),
            stdout_artifact="yara-packaged.txt",
        )
    )

    report_dir = writer.create_report_dir(Path("doc.pdf"), tmp_path)
    writer.write(result, report_dir)

    summary = (report_dir / "yara-summary.txt").read_text()
    assert "Rule: PDF_Risky_Actions" in summary
    assert "Source: packaged heuristic" in summary
    assert "Purpose:" in summary
    assert "Why this matched:" in summary
    assert "Matched strings:" in summary
    assert "$open" in summary
    assert "/OpenAction" in summary
    assert "$js1" in summary


def test_report_writer_indexes_and_surfaces_virustotal_artifacts(tmp_path: Path) -> None:
    writer = ReportWriter(clock=lambda: datetime(2026, 4, 29, 12, 30, 0))
    result = ScanResult(input_path=str(tmp_path / "doc.pdf"), file_name="doc.pdf", verdict="review")
    result.add_finding(
        "review",
        "virustotal-suspicious",
        "VirusTotal reported 1 suspicious engine detection",
        artifact="virustotal-summary.txt",
    )
    result.add_artifact(
        "virustotal-json",
        "virustotal.json",
        '{"data":{"id":"abc"}}\n',
        description="Raw VirusTotal hash lookup response",
        role="raw",
    )
    result.add_artifact(
        "virustotal-summary",
        "virustotal-summary.txt",
        "VirusTotal Summary\n\nKnown to VirusTotal: yes\nsuspicious: 1\n",
        description="VirusTotal hash lookup summary",
        role="summary",
    )

    report_dir = writer.create_report_dir(Path("doc.pdf"), tmp_path)
    writer.write(result, report_dir)

    summary = (report_dir / "summary.txt").read_text()
    index = (report_dir / "artifact-index.txt").read_text()
    payload = json.loads((report_dir / "summary.json").read_text())

    assert "VirusTotal reported 1 suspicious engine detection" in summary
    assert "virustotal-summary.txt" in summary
    assert "virustotal.json" in index
    assert "virustotal-summary.txt" in index
    assert any(item["path"] == "virustotal-summary.txt" for item in payload["artifacts"])


def test_report_writer_indexes_and_surfaces_url_reputation_artifacts(tmp_path: Path) -> None:
    writer = ReportWriter(clock=lambda: datetime(2026, 4, 29, 12, 30, 0))
    result = ScanResult(input_path=str(tmp_path / "doc.pdf"), file_name="doc.pdf", verdict="high")
    result.add_finding(
        "high",
        "url-reputation-malicious",
        "URL reputation provider reported a malicious exact URL match",
        artifact="url-reputation-summary.txt",
    )
    result.add_artifact(
        "url-inventory",
        "url-inventory.json",
        '{"urls":[{"url":"https://bad.example.test/","host":"bad.example.test"}]}\n',
        description="Structured URL inventory",
        role="summary",
    )
    result.add_artifact(
        "url-reputation-json",
        "url-reputation.json",
        '{"providers":{"safe_browsing":{"status":"ok"}}}\n',
        description="Raw URL reputation provider responses",
        role="raw",
    )
    result.add_artifact(
        "url-reputation-summary",
        "url-reputation-summary.txt",
        "URL Reputation Summary\n\nSafe Browsing: 1 match\n",
        description="URL reputation summary",
        role="summary",
    )

    report_dir = writer.create_report_dir(Path("doc.pdf"), tmp_path)
    writer.write(result, report_dir)

    summary = (report_dir / "summary.txt").read_text()
    index = (report_dir / "artifact-index.txt").read_text()
    payload = json.loads((report_dir / "summary.json").read_text())

    assert "URL reputation provider reported a malicious exact URL match" in summary
    assert "url-reputation-summary.txt" in summary
    assert "url-inventory.json" in index
    assert "url-reputation.json" in index
    assert "url-reputation-summary.txt" in index
    assert any(item["path"] == "url-reputation-summary.txt" for item in payload["artifacts"])


def test_report_writer_adds_pdf_analyst_summaries(tmp_path: Path) -> None:
    writer = ReportWriter(clock=lambda: datetime(2026, 4, 29, 12, 30, 0))
    result = ScanResult(
        input_path=str(tmp_path / "doc.pdf"),
        file_name="doc.pdf",
        verdict="review",
        file_type="pdf",
    )
    result.add_artifact(
        "qpdf-json",
        "qpdf.json",
        json.dumps(
            {
                "pages": [{}, {}],
                "attachments": {},
                "encrypt": {"encrypted": False},
                "acroform": {"hasacroform": False, "fields": []},
                "outlines": [],
                "version": "1.7",
            }
        ),
        role="raw",
    )
    result.add_artifact(
        "pdf-risky-strings",
        "pdf-risky-strings.txt",
        "\n".join(
            [
                "1:<</OpenAction 2 0 R /S /JavaScript /JS (app.alert(1))>>",
                "2:<</Subtype/Link/A<</S/URI/URI (https://example.test/path)>>",
                "3:<</Subtype/Link/A<</S/URI/URI (https://example.test/path)>>",
            ]
        )
        + "\n",
        role="raw",
    )

    report_dir = writer.create_report_dir(Path("doc.pdf"), tmp_path)
    writer.write(result, report_dir)

    structure = (report_dir / "pdf-structure-summary.txt").read_text()
    risk = (report_dir / "pdf-risk-summary.txt").read_text()
    urls = (report_dir / "pdf-url-summary.txt").read_text()

    assert "Pages: 2" in structure
    assert "Encrypted: no" in structure
    assert "AcroForm: not present" in structure
    assert "Attachments: 0" in structure
    assert "/OpenAction: 1" in risk
    assert "/JavaScript: 1" in risk
    assert "https://example.test/path" in urls
    assert "example.test" in urls


def test_pdf_summaries_filter_noise_and_group_pragprog_domains(tmp_path: Path) -> None:
    writer = ReportWriter(clock=lambda: datetime(2026, 4, 29, 12, 30, 0))
    result = ScanResult(
        input_path=str(tmp_path / "doc.pdf"),
        file_name="doc.pdf",
        verdict="review",
        file_type="pdf",
    )
    result.add_artifact(
        "qpdf-json",
        "qpdf.json",
        json.dumps(
            {
                "pages": [{}],
                "attachments": {},
                "encrypt": {"encrypted": False},
                "acroform": {"hasacroform": False},
                "outlines": [],
                "version": "1.4",
            }
        ),
        role="raw",
    )
    result.add_artifact(
        "pdf-risky-strings",
        "pdf-risky-strings.txt",
        "\n".join(
            [
                "1:<</BaseFont /AAAAAB+DejaVuSans>>",
                "2:<</Subtype/Link/A<</S/URI/URI (https://www.json.org/json-en.html)>>",
                "3:<</Subtype/Link/A<</S/URI/URI (https://pragprog.com/titles/liveview)>>",
                "4:http://bad.example.test/\x00binary",
            ]
        )
        + "\n",
        role="raw",
    )

    report_dir = writer.create_report_dir(Path("doc.pdf"), tmp_path)
    writer.write(result, report_dir)

    risk = (report_dir / "pdf-risk-summary.txt").read_text()
    urls = (report_dir / "pdf-url-summary.txt").read_text()

    assert "/AA:" not in risk
    assert "/JS:" not in risk
    assert "/URI: 2" in risk
    assert "PragProg domains:" in urls
    assert "- pragprog.com: 1" in urls
    assert "Other domains:" in urls
    assert "- www.json.org: 1" in urls
    assert "Discarded noisy URL-like matches: 1" in urls
    assert "bad.example.test" not in urls


def test_artifact_index_labels_qdf_as_large_raw_analysis_artifact(tmp_path: Path) -> None:
    writer = ReportWriter(clock=lambda: datetime(2026, 4, 29, 12, 30, 0))
    result = ScanResult(input_path=str(tmp_path / "doc.pdf"), file_name="doc.pdf", verdict="low")
    result.add_artifact(
        "qdf-pdf",
        "qdf.pdf",
        b"%PDF-1.4\n",
        description="qPDF normalized PDF",
        binary=True,
        role="raw",
    )

    report_dir = writer.create_report_dir(Path("doc.pdf"), tmp_path)
    writer.write(result, report_dir)

    index = (report_dir / "artifact-index.txt").read_text()
    assert "qdf.pdf" in index
    assert "large raw normalized analysis artifact" in index
