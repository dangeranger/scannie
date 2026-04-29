from __future__ import annotations

import io
import json
from email.message import Message
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request

from scannie.models import ScanOptions
from scannie.scanner import scan_document
from scannie.virustotal import lookup_file_hash, virustotal_summary_text

from .fakes import empty_runner

SHA256 = "a5c13cc885aaf99703d451c98af6ec62dcbb19fee4825760ea97881e80339a0d"


class FakeResponse(io.BytesIO):
    def __init__(self, payload: str, status: int = 200) -> None:
        super().__init__(payload.encode("utf-8"))
        self.status = status


def file_report(
    *,
    malicious: int = 0,
    suspicious: int = 0,
    threat_verdict: str | None = None,
    sandbox_category: str | None = None,
    crowdsourced_yara: bool = False,
) -> dict[str, object]:
    attributes: dict[str, object] = {
        "sha256": SHA256,
        "md5": "md5-value",
        "sha1": "sha1-value",
        "meaningful_name": "document.pdf",
        "type_description": "PDF",
        "size": 1234,
        "first_submission_date": 1_700_000_000,
        "last_submission_date": 1_700_010_000,
        "last_analysis_date": 1_700_020_000,
        "last_analysis_stats": {
            "malicious": malicious,
            "suspicious": suspicious,
            "undetected": 60,
            "harmless": 1,
            "timeout": 0,
        },
        "last_analysis_results": {},
        "tags": ["pdf"],
        "times_submitted": 3,
        "total_votes": {"harmless": 2, "malicious": 0},
        "reputation": 0,
    }
    if threat_verdict is not None:
        attributes["threat_verdict"] = threat_verdict
    if sandbox_category is not None:
        attributes["sandbox_verdicts"] = {
            "sandbox": {"category": sandbox_category, "malware_classification": ["trojan"]}
        }
    if crowdsourced_yara:
        attributes["crowdsourced_yara_results"] = [{"rule_name": "SuspiciousPdf"}]
    return {"data": {"id": SHA256, "type": "file", "attributes": attributes}}


def test_vt_client_parses_successful_file_report() -> None:
    seen: list[tuple[str, str | None, float]] = []

    def opener(request: Request, timeout: float) -> FakeResponse:
        seen.append((request.full_url, request.get_header("X-apikey"), timeout))
        return FakeResponse(json.dumps(file_report(malicious=1)))

    result = lookup_file_hash(SHA256, "secret-key", timeout=7, opener=opener)

    assert result.status == "found"
    assert result.http_status == 200
    assert result.data is not None
    assert result.data["data"]["id"] == SHA256
    assert result.raw_json is not None
    assert seen == [(f"https://www.virustotal.com/api/v3/files/{SHA256}", "secret-key", 7)]


def test_vt_client_maps_not_found() -> None:
    def opener(request: Request, timeout: float) -> FakeResponse:
        raise HTTPError(
            request.full_url,
            404,
            "Not Found",
            hdrs=Message(),
            fp=FakeResponse('{"error":{"code":"NotFoundError","message":"not found"}}'),
        )

    result = lookup_file_hash(SHA256, "secret-key", opener=opener)

    assert result.status == "not_found"
    assert result.http_status == 404
    assert result.error == "not found"


def test_vt_client_handles_auth_quota_timeout_network_and_invalid_json() -> None:
    def http_error(code: int, body: str):
        def opener(request: Request, timeout: float) -> FakeResponse:
            raise HTTPError(request.full_url, code, "error", hdrs=Message(), fp=FakeResponse(body))

        return opener

    assert lookup_file_hash(SHA256, "key", opener=http_error(401, '{"error":{"message":"bad key"}}')).status == "error"
    assert lookup_file_hash(SHA256, "key", opener=http_error(429, '{"error":{"message":"quota"}}')).status == "error"

    def timeout_opener(request: Request, timeout: float) -> FakeResponse:
        raise TimeoutError("timed out")

    def network_opener(request: Request, timeout: float) -> FakeResponse:
        raise URLError("dns failed")

    def invalid_json_opener(request: Request, timeout: float) -> FakeResponse:
        return FakeResponse("{not json")

    assert lookup_file_hash(SHA256, "key", opener=timeout_opener).status == "error"
    assert lookup_file_hash(SHA256, "key", opener=network_opener).status == "error"
    invalid = lookup_file_hash(SHA256, "key", opener=invalid_json_opener)
    assert invalid.status == "error"
    assert invalid.raw_json == "{not json"


def test_vt_summary_formats_key_analysis_fields() -> None:
    summary = virustotal_summary_text("found", SHA256, data=file_report(crowdsourced_yara=True))

    assert "Lookup mode: hash only; file was not uploaded" in summary
    assert f"https://www.virustotal.com/gui/file/{SHA256}" in summary
    assert "Known to VirusTotal: yes" in summary
    assert "malicious: 0" in summary
    assert "suspicious: 0" in summary
    assert "document.pdf" in summary
    assert "SuspiciousPdf" in summary


def test_vt_disabled_performs_no_lookup(clean_pdf: Path, tmp_path: Path) -> None:
    def fail_lookup(*args: object, **kwargs: object):
        raise AssertionError("VT lookup should not run")

    result = scan_document(
        clean_pdf,
        ScanOptions(report_dir=tmp_path / "report"),
        runner=empty_runner,
        vt_lookup=fail_lookup,
    )

    assert result.verdict == "low"
    assert not any(artifact.relative_path.startswith("virustotal") for artifact in result.artifacts)


def test_missing_vt_api_key_is_recoverable(clean_pdf: Path, tmp_path: Path) -> None:
    result = scan_document(
        clean_pdf,
        ScanOptions(report_dir=tmp_path / "report", vt_enabled=True, vt_api_key=None),
        runner=empty_runner,
    )

    assert result.verdict == "low"
    assert "VirusTotal lookup requested but VT_API_KEY is not set" in result.errors
    assert any(artifact.relative_path == "virustotal-summary.txt" for artifact in result.artifacts)


def test_vt_malicious_response_forces_high(clean_pdf: Path, tmp_path: Path) -> None:
    def vt_lookup(sha256: str, api_key: str, timeout: int):
        return lookup_file_hash_result("found", sha256, data=file_report(malicious=1))

    result = scan_document(
        clean_pdf,
        ScanOptions(report_dir=tmp_path / "report", vt_enabled=True, vt_api_key="secret"),
        runner=empty_runner,
        vt_lookup=vt_lookup,
    )

    assert result.verdict == "high"
    assert any(finding.category == "virustotal-malicious" for finding in result.findings)


def test_vt_suspicious_response_returns_review(clean_pdf: Path, tmp_path: Path) -> None:
    def vt_lookup(sha256: str, api_key: str, timeout: int):
        return lookup_file_hash_result("found", sha256, data=file_report(suspicious=1))

    result = scan_document(
        clean_pdf,
        ScanOptions(report_dir=tmp_path / "report", vt_enabled=True, vt_api_key="secret"),
        runner=empty_runner,
        vt_lookup=vt_lookup,
    )

    assert result.verdict == "review"
    assert any(finding.category == "virustotal-suspicious" for finding in result.findings)


def test_vt_reputation_signals_map_without_engine_counts(clean_pdf: Path, tmp_path: Path) -> None:
    def malicious_lookup(sha256: str, api_key: str, timeout: int):
        return lookup_file_hash_result(
            "found",
            sha256,
            data=file_report(threat_verdict="VERDICT_MALICIOUS", sandbox_category="malicious"),
        )

    malicious_result = scan_document(
        clean_pdf,
        ScanOptions(report_dir=tmp_path / "malicious-report", vt_enabled=True, vt_api_key="secret"),
        runner=empty_runner,
        vt_lookup=malicious_lookup,
    )

    def suspicious_lookup(sha256: str, api_key: str, timeout: int):
        return lookup_file_hash_result(
            "found",
            sha256,
            data=file_report(threat_verdict="VERDICT_SUSPICIOUS", crowdsourced_yara=True),
        )

    suspicious_result = scan_document(
        clean_pdf,
        ScanOptions(report_dir=tmp_path / "suspicious-report", vt_enabled=True, vt_api_key="secret"),
        runner=empty_runner,
        vt_lookup=suspicious_lookup,
    )

    assert malicious_result.verdict == "high"
    assert any(finding.category == "virustotal-malicious" for finding in malicious_result.findings)
    assert suspicious_result.verdict == "review"
    assert any(finding.category == "virustotal-suspicious" for finding in suspicious_result.findings)


def test_vt_clean_and_not_found_are_info_only(clean_pdf: Path, tmp_path: Path) -> None:
    def clean_lookup(sha256: str, api_key: str, timeout: int):
        return lookup_file_hash_result("found", sha256, data=file_report())

    clean_result = scan_document(
        clean_pdf,
        ScanOptions(report_dir=tmp_path / "clean-report", vt_enabled=True, vt_api_key="secret"),
        runner=empty_runner,
        vt_lookup=clean_lookup,
    )

    def not_found_lookup(sha256: str, api_key: str, timeout: int):
        return lookup_file_hash_result("not_found", sha256, http_status=404, error="not found")

    missing_result = scan_document(
        clean_pdf,
        ScanOptions(report_dir=tmp_path / "missing-report", vt_enabled=True, vt_api_key="secret"),
        runner=empty_runner,
        vt_lookup=not_found_lookup,
    )

    assert clean_result.verdict == "low"
    assert missing_result.verdict == "low"
    assert any(finding.severity == "info" for finding in clean_result.findings)
    assert any(finding.severity == "info" for finding in missing_result.findings)


def test_vt_api_key_is_not_serialized(clean_pdf: Path, tmp_path: Path) -> None:
    secret = "secret-api-key"

    def vt_lookup(sha256: str, api_key: str, timeout: int):
        assert api_key == secret
        return lookup_file_hash_result("found", sha256, data=file_report())

    result = scan_document(
        clean_pdf,
        ScanOptions(report_dir=tmp_path / "report", vt_enabled=True, vt_api_key=secret),
        runner=empty_runner,
        vt_lookup=vt_lookup,
    )

    serialized = json.dumps(result.to_dict())
    artifact_content = "\n".join(str(artifact.content) for artifact in result.artifacts)

    assert secret not in serialized
    assert secret not in artifact_content


def test_vt_clean_never_downgrades_local_high(clean_pdf: Path, tmp_path: Path) -> None:
    def vt_lookup(sha256: str, api_key: str, timeout: int):
        return lookup_file_hash_result("found", sha256, data=file_report())

    def runner(argv: list[str], timeout: int):
        if argv[0] == "clamscan":
            return type(empty_runner(argv, timeout))(
                "clamscan",
                argv,
                "nonzero",
                returncode=1,
                stdout=f"{clean_pdf}: Eicar-Test-Signature FOUND\n",
            )
        return empty_runner(argv, timeout)

    result = scan_document(
        clean_pdf,
        ScanOptions(report_dir=tmp_path / "report", vt_enabled=True, vt_api_key="secret"),
        runner=runner,
        vt_lookup=vt_lookup,
    )

    assert result.verdict == "high"
    assert any(finding.category == "av-detection" for finding in result.findings)
    assert any(finding.category == "virustotal-clean" for finding in result.findings)


def lookup_file_hash_result(
    status: str,
    sha256: str,
    *,
    data: dict[str, object] | None = None,
    http_status: int | None = 200,
    error: str | None = None,
):
    from scannie.virustotal import VirusTotalLookupResult

    raw_json = json.dumps(data) if data is not None else None
    return VirusTotalLookupResult(
        status=status,
        sha256=sha256,
        data=data,
        raw_json=raw_json,
        http_status=http_status,
        error=error,
    )
