from __future__ import annotations

import io
import json
from email.message import Message
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs
from urllib.request import Request

from scannie.models import ScanOptions
from scannie.scanner import scan_document
from scannie.url_reputation import (
    SafeBrowsingResult,
    UrlhausResult,
    extract_url_inventory,
    lookup_safe_browsing,
    lookup_urlhaus,
    url_inventory_summary_text,
    url_reputation_summary_text,
)

from .fakes import empty_runner


class FakeResponse(io.BytesIO):
    def __init__(self, payload: str, status: int = 200) -> None:
        super().__init__(payload.encode("utf-8"))
        self.status = status


def request_body(request: Request) -> bytes:
    data = request.data
    return data if isinstance(data, bytes) else b""


def pdf_with_url(tmp_path: Path, url: str = "https://bad.example.test/payload.exe") -> Path:
    path = tmp_path / "url.pdf"
    path.write_bytes(f"%PDF-1.4\n1 0 obj\n({url})\nendobj\n%%EOF\n".encode())
    return path


def test_url_inventory_dedupes_counts_discards_noise_and_flags() -> None:
    inventory = extract_url_inventory(
        "\n".join(
            [
                "https://example.test/a",
                "https://example.test/a",
                "http://192.0.2.1/drop.exe?token=secret",
                "https://bit.ly/abc",
                "https://xn--pple-43d.example/login",
                "http://bad.example.test/\x00binary",
            ]
        )
    )

    payload = inventory.to_dict()
    urls = {item["url"]: item for item in payload["urls"]}

    assert payload["discarded_count"] == 1
    assert urls["https://example.test/a"]["count"] == 2
    assert urls["https://example.test/a"]["host"] == "example.test"
    assert urls["https://example.test/a"]["domain"] == "example.test"
    assert urls["http://192.0.2.1/drop.exe?token=secret"]["flags"] == [
        "plain-http",
        "ip-literal",
        "executable-path",
        "query-token",
    ]
    assert "url-shortener" in urls["https://bit.ly/abc"]["flags"]
    assert "punycode" in urls["https://xn--pple-43d.example/login"]["flags"]


def test_url_inventory_accepts_ipv6_literals() -> None:
    inventory = extract_url_inventory("http://[2001:db8::1]/drop.exe")

    payload = inventory.to_dict()
    item = payload["urls"][0]
    assert payload["discarded_count"] == 0
    assert item["host"] == "2001:db8::1"
    assert item["domain"] == "2001:db8::1"
    assert item["flags"] == ["plain-http", "ip-literal", "executable-path"]


def test_url_inventory_summary_uses_structured_inventory() -> None:
    inventory = extract_url_inventory("https://pragprog.com/book\nhttps://example.test/path\n")

    summary = url_inventory_summary_text(inventory)

    assert "Unique URLs: 2" in summary
    assert "Unique domains: 2" in summary
    assert "PragProg domains:" in summary
    assert "- pragprog.com: 1" in summary
    assert "Other domains:" in summary
    assert "- example.test: 1" in summary


def test_safe_browsing_batches_urls_and_maps_matches() -> None:
    seen_batches: list[list[str]] = []

    def opener(request: Request, timeout: float) -> FakeResponse:
        payload = json.loads((request_body(request) or b"{}").decode())
        urls = [entry["url"] for entry in payload["threatInfo"]["threatEntries"]]
        seen_batches.append(urls)
        matches = []
        if "https://bad.example.test/" in urls:
            matches.append(
                {
                    "threatType": "MALWARE",
                    "platformType": "ANY_PLATFORM",
                    "threatEntryType": "URL",
                    "threat": {"url": "https://bad.example.test/"},
                }
            )
        return FakeResponse(json.dumps({"matches": matches}))

    urls = [f"https://example.test/{index}" for index in range(500)] + ["https://bad.example.test/"]
    result = lookup_safe_browsing(urls, "safe-key", timeout=9, opener=opener)

    assert result.status == "ok"
    assert len(seen_batches) == 2
    assert len(seen_batches[0]) == 500
    assert seen_batches[1] == ["https://bad.example.test/"]
    assert result.matches[0]["threatType"] == "MALWARE"


def test_safe_browsing_error_keeps_prior_batch_matches() -> None:
    def opener(request: Request, timeout: float) -> FakeResponse:
        payload = json.loads((request_body(request) or b"{}").decode())
        urls = [entry["url"] for entry in payload["threatInfo"]["threatEntries"]]
        if "https://bad.example.test/" in urls:
            return FakeResponse(
                json.dumps(
                    {
                        "matches": [
                            {
                                "threatType": "MALWARE",
                                "platformType": "ANY_PLATFORM",
                                "threatEntryType": "URL",
                                "threat": {"url": "https://bad.example.test/"},
                            }
                        ]
                    }
                )
            )
        raise HTTPError(
            request.full_url,
            429,
            "quota",
            hdrs=Message(),
            fp=FakeResponse('{"error":{"message":"quota"}}'),
        )

    urls = ["https://bad.example.test/"] + [f"https://example.test/{index}" for index in range(500)]
    result = lookup_safe_browsing(urls, "safe-key", timeout=9, opener=opener)

    assert result.status == "error"
    assert result.matches[0]["threatType"] == "MALWARE"
    assert result.http_status == 429


def test_safe_browsing_handles_http_timeout_network_and_invalid_json() -> None:
    def http_error(request: Request, timeout: float) -> FakeResponse:
        raise HTTPError(
            request.full_url,
            429,
            "quota",
            hdrs=Message(),
            fp=FakeResponse('{"error":{"message":"quota"}}'),
        )

    def timeout_error(request: Request, timeout: float) -> FakeResponse:
        raise TimeoutError("timed out")

    def network_error(request: Request, timeout: float) -> FakeResponse:
        raise URLError("dns failed")

    def invalid_json(request: Request, timeout: float) -> FakeResponse:
        return FakeResponse("{not json")

    assert lookup_safe_browsing(["https://example.test"], "key", opener=http_error).status == "error"
    assert lookup_safe_browsing(["https://example.test"], "key", opener=timeout_error).status == "error"
    assert lookup_safe_browsing(["https://example.test"], "key", opener=network_error).status == "error"
    assert lookup_safe_browsing(["https://example.test"], "key", opener=invalid_json).status == "error"


def test_urlhaus_maps_exact_url_hits_host_hits_no_results_and_errors() -> None:
    exact_url = "https://bad.example.test/payload.exe"
    seen: list[tuple[str, dict[str, list[str]]]] = []

    def opener(request: Request, timeout: float) -> FakeResponse:
        form = parse_qs(request_body(request).decode())
        seen.append((request.full_url, form))
        if request.full_url.endswith("/url/") and form.get("url") == [exact_url]:
            return FakeResponse(
                json.dumps(
                    {
                        "query_status": "ok",
                        "url": exact_url,
                        "url_status": "online",
                        "threat": "malware_download",
                        "tags": ["loader"],
                    }
                )
            )
        if request.full_url.endswith("/host/") and form.get("host") == ["bad.example.test"]:
            return FakeResponse(
                json.dumps(
                    {
                        "query_status": "ok",
                        "urls": [{"url": exact_url, "url_status": "online", "threat": "malware_download"}],
                    }
                )
            )
        return FakeResponse('{"query_status":"no_results"}')

    result = lookup_urlhaus([exact_url, "https://clean.example.test/"], ["bad.example.test"], opener=opener)

    assert result.status == "ok"
    assert result.url_matches[0]["url"] == exact_url
    assert result.host_matches[0]["host"] == "bad.example.test"
    assert any(url.endswith("/url/") for url, _ in seen)
    assert any(url.endswith("/host/") for url, _ in seen)

    def bad_status(request: Request, timeout: float) -> FakeResponse:
        raise HTTPError(request.full_url, 429, "rate limited", hdrs=Message(), fp=FakeResponse("rate limited"))

    assert lookup_urlhaus([exact_url], ["bad.example.test"], opener=bad_status).status == "error"


def test_url_reputation_summary_formats_provider_results() -> None:
    inventory = extract_url_inventory("https://bad.example.test/payload.exe")
    safe = SafeBrowsingResult(
        status="ok",
        matches=[{"threatType": "MALWARE", "threat": {"url": "https://bad.example.test/payload.exe"}}],
    )
    urlhaus = UrlhausResult(status="ok", url_matches=[], host_matches=[])

    summary = url_reputation_summary_text(inventory, safe, urlhaus)

    assert "URL Reputation Summary" in summary
    assert "URLs checked: 1" in summary
    assert "Safe Browsing: 1 match" in summary
    assert "URLhaus: no matches" in summary
    assert "https://bad.example.test/payload.exe" in summary


def test_url_reputation_summary_reports_discarded_noise() -> None:
    inventory = extract_url_inventory("https://example.test/\nhttp://bad.example.test/\x00binary\n")

    summary = url_reputation_summary_text(
        inventory,
        SafeBrowsingResult(status="ok"),
        UrlhausResult(status="ok"),
    )

    assert "Discarded noisy URL-like matches: 1" in summary


def test_url_reputation_disabled_performs_no_provider_lookup(tmp_path: Path) -> None:
    path = pdf_with_url(tmp_path)

    def fail_safe(*args: object, **kwargs: object) -> SafeBrowsingResult:
        raise AssertionError("Safe Browsing lookup should not run")

    def fail_urlhaus(*args: object, **kwargs: object) -> UrlhausResult:
        raise AssertionError("URLhaus lookup should not run")

    result = scan_document(
        path,
        ScanOptions(report_dir=tmp_path / "report"),
        runner=empty_runner,
        safe_browsing_lookup=fail_safe,
        urlhaus_lookup=fail_urlhaus,
    )

    assert result.verdict == "review"
    assert any(artifact.relative_path == "url-inventory.json" for artifact in result.artifacts)
    assert not any(artifact.relative_path.startswith("url-reputation") for artifact in result.artifacts)


def test_missing_safe_browsing_key_is_recoverable_and_urlhaus_still_runs(tmp_path: Path) -> None:
    path = pdf_with_url(tmp_path)
    calls = {"urlhaus": 0}

    def urlhaus_lookup(urls: list[str], hosts: list[str], timeout: int) -> UrlhausResult:
        calls["urlhaus"] += 1
        return UrlhausResult(status="ok")

    result = scan_document(
        path,
        ScanOptions(report_dir=tmp_path / "report", url_reputation_enabled=True),
        runner=empty_runner,
        urlhaus_lookup=urlhaus_lookup,
    )

    assert result.verdict == "review"
    assert calls["urlhaus"] == 1
    assert any(finding.category == "safe-browsing-not-configured" for finding in result.findings)
    assert any(artifact.relative_path == "url-reputation-summary.txt" for artifact in result.artifacts)


def test_safe_browsing_exact_match_forces_high(tmp_path: Path) -> None:
    path = pdf_with_url(tmp_path)

    def safe_lookup(urls: list[str], api_key: str, timeout: int) -> SafeBrowsingResult:
        return SafeBrowsingResult(
            status="ok",
            matches=[{"threatType": "MALWARE", "threat": {"url": "https://bad.example.test/payload.exe"}}],
        )

    result = scan_document(
        path,
        ScanOptions(
            report_dir=tmp_path / "report",
            url_reputation_enabled=True,
            safe_browsing_api_key="safe-key",
        ),
        runner=empty_runner,
        safe_browsing_lookup=safe_lookup,
        urlhaus_lookup=lambda urls, hosts, timeout: UrlhausResult(status="ok"),
    )

    assert result.verdict == "high"
    assert any(finding.category == "url-reputation-malicious" for finding in result.findings)


def test_urlhaus_exact_match_forces_high_and_host_match_returns_review(tmp_path: Path) -> None:
    path = pdf_with_url(tmp_path)

    exact_result = scan_document(
        path,
        ScanOptions(report_dir=tmp_path / "exact", url_reputation_enabled=True),
        runner=empty_runner,
        safe_browsing_lookup=lambda urls, api_key, timeout: SafeBrowsingResult(status="not_configured"),
        urlhaus_lookup=lambda urls, hosts, timeout: UrlhausResult(
            status="ok",
            url_matches=[{"url": "https://bad.example.test/payload.exe", "threat": "malware_download"}],
        ),
    )

    host_result = scan_document(
        path,
        ScanOptions(report_dir=tmp_path / "host", url_reputation_enabled=True),
        runner=empty_runner,
        safe_browsing_lookup=lambda urls, api_key, timeout: SafeBrowsingResult(status="not_configured"),
        urlhaus_lookup=lambda urls, hosts, timeout: UrlhausResult(
            status="ok",
            host_matches=[{"host": "bad.example.test", "urls": [{"url": "https://bad.example.test/other"}]}],
        ),
    )

    assert exact_result.verdict == "high"
    assert any(finding.category == "url-reputation-malicious" for finding in exact_result.findings)
    assert host_result.verdict == "review"
    assert any(finding.category == "url-reputation-host-match" for finding in host_result.findings)


def test_clean_url_reputation_does_not_raise_clean_pdf(clean_pdf: Path, tmp_path: Path) -> None:
    result = scan_document(
        clean_pdf,
        ScanOptions(
            report_dir=tmp_path / "report",
            url_reputation_enabled=True,
            safe_browsing_api_key="safe-key",
        ),
        runner=empty_runner,
        safe_browsing_lookup=lambda urls, api_key, timeout: SafeBrowsingResult(status="ok"),
        urlhaus_lookup=lambda urls, hosts, timeout: UrlhausResult(status="ok"),
    )

    assert result.verdict == "low"
    assert any(finding.category == "url-reputation-no-urls" for finding in result.findings)


def test_provider_failure_is_recoverable_review_not_error(tmp_path: Path) -> None:
    path = pdf_with_url(tmp_path)

    result = scan_document(
        path,
        ScanOptions(
            report_dir=tmp_path / "report",
            url_reputation_enabled=True,
            safe_browsing_api_key="safe-key",
        ),
        runner=empty_runner,
        safe_browsing_lookup=lambda urls, api_key, timeout: SafeBrowsingResult(status="error", error="quota"),
        urlhaus_lookup=lambda urls, hosts, timeout: UrlhausResult(status="ok"),
    )

    assert result.verdict == "review"
    assert any(finding.category == "url-reputation-provider-error" for finding in result.findings)
    assert not any(finding.severity == "error" for finding in result.findings)


def test_url_reputation_artifacts_do_not_serialize_api_keys(tmp_path: Path) -> None:
    path = pdf_with_url(tmp_path)
    secret = "safe-secret"

    result = scan_document(
        path,
        ScanOptions(
            report_dir=tmp_path / "report",
            url_reputation_enabled=True,
            safe_browsing_api_key=secret,
        ),
        runner=empty_runner,
        safe_browsing_lookup=lambda urls, api_key, timeout: SafeBrowsingResult(status="ok"),
        urlhaus_lookup=lambda urls, hosts, timeout: UrlhausResult(status="ok"),
    )

    serialized = json.dumps(result.to_dict())
    artifact_content = "\n".join(str(artifact.content) for artifact in result.artifacts)

    assert secret not in serialized
    assert secret not in artifact_content


def test_safe_browsing_hook_exception_redacts_api_key(tmp_path: Path) -> None:
    path = pdf_with_url(tmp_path)
    secret = "safe-secret"

    def safe_lookup(urls: list[str], api_key: str, timeout: int) -> SafeBrowsingResult:
        raise RuntimeError(f"boom {api_key}")

    result = scan_document(
        path,
        ScanOptions(
            report_dir=tmp_path / "report",
            url_reputation_enabled=True,
            safe_browsing_api_key=secret,
        ),
        runner=empty_runner,
        safe_browsing_lookup=safe_lookup,
        urlhaus_lookup=lambda urls, hosts, timeout: UrlhausResult(status="ok"),
    )

    serialized = json.dumps(result.to_dict())
    artifact_content = "\n".join(str(artifact.content) for artifact in result.artifacts)

    assert secret not in serialized
    assert secret not in artifact_content


def test_url_reputation_provider_payloads_redact_api_key(tmp_path: Path) -> None:
    path = pdf_with_url(tmp_path)
    secret = "safe-secret"

    def safe_lookup(urls: list[str], api_key: str, timeout: int) -> SafeBrowsingResult:
        return SafeBrowsingResult(
            status="ok",
            matches=[{"threatType": "MALWARE", "threat": {"url": f"https://example.test/{api_key}"}}],
        )

    def urlhaus_lookup(urls: list[str], hosts: list[str], timeout: int) -> UrlhausResult:
        return UrlhausResult(
            status="ok",
            url_matches=[{"url": f"https://bad.example.test/{secret}", "threat": secret}],
            host_matches=[{"host": "bad.example.test", "urls": [{"url": f"https://x.test/{secret}"}]}],
            raw_responses=[{"kind": "url", "response": {"nested": [secret]}}],
            error=f"provider returned {secret}",
        )

    result = scan_document(
        path,
        ScanOptions(
            report_dir=tmp_path / "report",
            url_reputation_enabled=True,
            safe_browsing_api_key=secret,
        ),
        runner=empty_runner,
        safe_browsing_lookup=safe_lookup,
        urlhaus_lookup=urlhaus_lookup,
    )

    artifact_content = "\n".join(str(artifact.content) for artifact in result.artifacts)

    assert secret not in artifact_content
    assert "[REDACTED]" in artifact_content
