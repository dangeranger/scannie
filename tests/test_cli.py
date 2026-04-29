from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from scannie.cli import main
from scannie.models import ScanResult, ToolResult


def test_python_module_help_runs() -> None:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(Path.cwd() / "src")
    completed = subprocess.run(
        [sys.executable, "-m", "scannie", "--help"],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0
    assert "scan" in completed.stdout
    assert "doctor" in completed.stdout


def test_doctor_runs(capsys) -> None:  # type: ignore[no-untyped-def]
    assert main(["doctor"]) == 0
    assert "scannie doctor" in capsys.readouterr().out


def test_scan_invalid_path_returns_two(tmp_path: Path) -> None:
    code = main(["scan", str(tmp_path / "missing.pdf"), "--out", str(tmp_path)])
    assert code == 2


def test_scan_json_prints_summary(clean_pdf: Path, tmp_path: Path, capsys, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def fake_scan_document(path, options):  # type: ignore[no-untyped-def]
        result = ScanResult(
            input_path=str(path),
            file_name=Path(path).name,
            file_type="pdf",
            verdict="low",
            report_dir=str(options.report_dir),
        )
        return result

    monkeypatch.setattr("scannie.cli.scan_document", fake_scan_document)
    code = main(["scan", str(clean_pdf), "--out", str(tmp_path), "--json"])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["file_type"] == "pdf"
    assert payload["report_dir"]


def test_scan_passes_virustotal_options(clean_pdf: Path, tmp_path: Path, capsys, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    seen_options = {}

    def fake_scan_document(path, options):  # type: ignore[no-untyped-def]
        seen_options["vt_enabled"] = options.vt_enabled
        seen_options["vt_api_key"] = options.vt_api_key
        seen_options["vt_timeout_seconds"] = options.vt_timeout_seconds
        return ScanResult(
            input_path=str(path),
            file_name=Path(path).name,
            file_type="pdf",
            verdict="low",
            report_dir=str(options.report_dir),
        )

    monkeypatch.setenv("VT_API_KEY", "env-secret")
    monkeypatch.setattr("scannie.cli.scan_document", fake_scan_document)

    code = main(["scan", str(clean_pdf), "--out", str(tmp_path), "--vt", "--json"])

    assert code == 0
    json.loads(capsys.readouterr().out)
    assert seen_options == {
        "vt_enabled": True,
        "vt_api_key": "env-secret",
        "vt_timeout_seconds": 15,
    }


def test_scan_passes_url_reputation_options(clean_pdf: Path, tmp_path: Path, capsys, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    seen_options = {}

    def fake_scan_document(path, options):  # type: ignore[no-untyped-def]
        seen_options["url_reputation_enabled"] = options.url_reputation_enabled
        seen_options["safe_browsing_api_key"] = options.safe_browsing_api_key
        seen_options["url_reputation_timeout_seconds"] = options.url_reputation_timeout_seconds
        seen_options["url_reputation_max_urls"] = options.url_reputation_max_urls
        return ScanResult(
            input_path=str(path),
            file_name=Path(path).name,
            file_type="pdf",
            verdict="low",
            report_dir=str(options.report_dir),
        )

    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "safe-key")
    monkeypatch.setattr("scannie.cli.scan_document", fake_scan_document)

    code = main(["scan", str(clean_pdf), "--out", str(tmp_path), "--url-reputation", "--json"])

    assert code == 0
    json.loads(capsys.readouterr().out)
    assert seen_options == {
        "url_reputation_enabled": True,
        "safe_browsing_api_key": "safe-key",
        "url_reputation_timeout_seconds": 15,
        "url_reputation_max_urls": 500,
    }


def test_scan_passes_rules_and_max_expanded_size(clean_pdf: Path, tmp_path: Path, capsys, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    custom_rules = tmp_path / "custom.yar"
    seen_options = {}

    def fake_scan_document(path, options):  # type: ignore[no-untyped-def]
        seen_options["rules"] = options.rules
        seen_options["max_expanded_size"] = options.max_expanded_size
        return ScanResult(
            input_path=str(path),
            file_name=Path(path).name,
            file_type="pdf",
            verdict="low",
            report_dir=str(options.report_dir),
        )

    monkeypatch.setattr("scannie.cli.scan_document", fake_scan_document)

    code = main(
        [
            "scan",
            str(clean_pdf),
            "--out",
            str(tmp_path),
            "--rules",
            str(custom_rules),
            "--max-expanded-size",
            "5MB",
            "--json",
        ]
    )

    assert code == 0
    json.loads(capsys.readouterr().out)
    assert seen_options == {"rules": [custom_rules], "max_expanded_size": 5 * 1024 * 1024}


def test_scan_malformed_max_expanded_size_returns_two(clean_pdf: Path, tmp_path: Path) -> None:
    code = main(["scan", str(clean_pdf), "--out", str(tmp_path), "--max-expanded-size", "abc"])
    assert code == 2


def test_scan_high_verdict_returns_one(clean_pdf: Path, tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def fake_scan_document(path, options):  # type: ignore[no-untyped-def]
        return ScanResult(
            input_path=str(path),
            file_name=Path(path).name,
            file_type="pdf",
            verdict="high",
            report_dir=str(options.report_dir),
        )

    monkeypatch.setattr("scannie.cli.scan_document", fake_scan_document)

    assert main(["scan", str(clean_pdf), "--out", str(tmp_path)]) == 1


def test_scan_error_verdict_returns_two(clean_pdf: Path, tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def fake_scan_document(path, options):  # type: ignore[no-untyped-def]
        return ScanResult(
            input_path=str(path),
            file_name=Path(path).name,
            file_type=None,
            verdict="error",
            report_dir=str(options.report_dir),
        )

    monkeypatch.setattr("scannie.cli.scan_document", fake_scan_document)

    assert main(["scan", str(clean_pdf), "--out", str(tmp_path)]) == 2


def test_scan_text_prints_analyst_explanation(clean_pdf: Path, tmp_path: Path, capsys, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def fake_scan_document(path, options):  # type: ignore[no-untyped-def]
        result = ScanResult(
            input_path=str(path),
            file_name=Path(path).name,
            file_type="pdf",
            verdict="review",
            report_dir=str(options.report_dir),
        )
        result.add_finding(
            "review",
            "pdf-risk-indicator",
            "PDF contains JavaScript indicators",
            artifact="pdf-risk-summary.txt",
        )
        result.tools.append(ToolResult("qpdf-check", ["qpdf", "--check", str(path)], "ok", returncode=0))
        return result

    monkeypatch.setattr("scannie.cli.scan_document", fake_scan_document)
    code = main(["scan", str(clean_pdf), "--out", str(tmp_path)])
    output = capsys.readouterr().out
    assert code == 0
    assert "Verdict: review" in output
    assert "Report:" in output
    assert "Why this verdict:" in output
    assert "Tool status:" in output
    assert "Start here:" in output
    assert "PDF contains JavaScript indicators" in output
