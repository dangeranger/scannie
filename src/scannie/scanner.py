from __future__ import annotations

import json
import tempfile
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

from .artifacts import artifact_text
from .command import run_tool
from .detections import clamav_detected, yara_detected
from .epub import scan_epub
from .models import (
    SEVERITY_ERROR,
    SEVERITY_HIGH,
    SEVERITY_INFO,
    SEVERITY_REVIEW,
    ScanOptions,
    ScanResult,
    ToolResult,
    make_result,
)
from .pdf import scan_pdf
from .rules import active_rules, packaged_rules_path
from .url_reputation import (
    SafeBrowsingResult,
    UrlhausResult,
    UrlInventory,
    has_suspicious_local_flags,
    inventory_from_json,
    lookup_safe_browsing,
    lookup_urlhaus,
    url_reputation_payload,
    url_reputation_summary_text,
)
from .utils import hash_file
from .verdict import calculate_verdict
from .virustotal import (
    VirusTotalLookupResult,
    lookup_file_hash,
    virustotal_summary_text,
    vt_detection_counts,
    vt_has_malicious_signal,
    vt_has_suspicious_signal,
)

Runner = Callable[[list[str], int], ToolResult]
VTLookup = Callable[[str, str, int], VirusTotalLookupResult]
SafeBrowsingLookup = Callable[[list[str], str, int], SafeBrowsingResult]
UrlhausLookup = Callable[[list[str], list[str], int], UrlhausResult]


def detect_document_type(path: Path, force_type: str | None = None) -> str | None:
    if force_type:
        normalized = force_type.lower()
        return normalized if normalized in {"pdf", "epub"} else None

    try:
        with path.open("rb") as file:
            head = file.read(16)
    except OSError:
        return None

    if head.startswith(b"%PDF-"):
        return "pdf"
    if zipfile.is_zipfile(path):
        try:
            with zipfile.ZipFile(path) as archive:
                if archive.read("mimetype", pwd=None) == b"application/epub+zip":
                    return "epub"
        except (KeyError, OSError, RuntimeError, zipfile.BadZipFile):
            pass

    suffix = path.suffix.lower()
    if suffix == ".pdf":
        return "pdf"
    if suffix == ".epub":
        return "epub"
    return None


def scan_document(
    path: str | Path,
    options: ScanOptions | None = None,
    *,
    runner: Runner = run_tool,
    vt_lookup: VTLookup = lookup_file_hash,
    safe_browsing_lookup: SafeBrowsingLookup = lookup_safe_browsing,
    urlhaus_lookup: UrlhausLookup = lookup_urlhaus,
) -> ScanResult:
    options = options or ScanOptions()
    input_path = Path(path)
    result = make_result(input_path)

    if options.report_dir is None:
        options.report_dir = Path(tempfile.mkdtemp(prefix="scannie-"))
    result.report_dir = str(options.report_dir)

    if not input_path.exists() or not input_path.is_file():
        result.add_finding(
            SEVERITY_ERROR,
            "input",
            "Input path must be a readable regular file",
            source="scanner",
        )
        result.errors.append("Input path must be a readable regular file")
        result.verdict = calculate_verdict(result.findings)
        return result

    result.size_bytes = input_path.stat().st_size
    result.sha256 = hash_file(input_path)
    result.add_artifact("sha256", "sha256.txt", f"{result.sha256}  {input_path.name}\n", role="metadata")
    result.add_artifact("size", "size.txt", f"{result.size_bytes} bytes\n", role="metadata")

    doc_type = detect_document_type(input_path, options.force_type)
    result.file_type = doc_type
    if doc_type is None:
        result.add_finding(
            SEVERITY_ERROR,
            "input",
            "Unsupported file type; only PDF and EPUB are supported",
            source="scanner",
        )
        result.errors.append("Unsupported file type")
        result.verdict = calculate_verdict(result.findings)
        return result

    _run_virustotal_enrichment(result, options, vt_lookup)

    tool_recorder = _ToolRecorder(result, runner, options.timeout_seconds, doc_type)
    _run_common_scan(input_path, result, options, tool_recorder, doc_type)

    if doc_type == "pdf":
        scan_pdf(input_path, result, options, tool_recorder.run, tool_recorder.run_yara)
        _run_url_reputation_enrichment(result, options, safe_browsing_lookup, urlhaus_lookup)
    elif doc_type == "epub":
        scan_epub(input_path, result, options, tool_recorder.run, tool_recorder.run_yara)

    result.verdict = calculate_verdict(result.findings)
    return result


def _run_url_reputation_enrichment(
    result: ScanResult,
    options: ScanOptions,
    safe_browsing_lookup: SafeBrowsingLookup,
    urlhaus_lookup: UrlhausLookup,
) -> None:
    if not options.url_reputation_enabled:
        return

    inventory = _url_inventory_from_result(result) or UrlInventory()
    checked_inventory = UrlInventory(
        urls=inventory.urls[: options.url_reputation_max_urls],
        discarded_count=inventory.discarded_count,
        discarded_examples=inventory.discarded_examples,
    )
    urls = [item.url for item in checked_inventory.urls]
    hosts = sorted({item.host for item in checked_inventory.urls if item.host})

    if not urls:
        safe_browsing = SafeBrowsingResult("no_urls")
        urlhaus = UrlhausResult("ok")
        _add_url_reputation_artifacts(result, checked_inventory, safe_browsing, urlhaus)
        result.add_finding(
            SEVERITY_INFO,
            "url-reputation-no-urls",
            "URL reputation lookup found no extracted PDF URLs to check",
            source="url-reputation",
            artifact="url-reputation-summary.txt",
        )
        return

    if options.safe_browsing_api_key:
        try:
            safe_browsing = safe_browsing_lookup(
                urls,
                options.safe_browsing_api_key,
                options.url_reputation_timeout_seconds,
            )
        except Exception as exc:  # pragma: no cover - defensive guard around caller-provided hooks
            safe_browsing = SafeBrowsingResult(
                "error",
                error=_redact_secrets(
                    f"Safe Browsing lookup failed: {exc}",
                    options.safe_browsing_api_key,
                ),
            )
        else:
            safe_browsing.error = _redact_secrets(safe_browsing.error, options.safe_browsing_api_key)
    else:
        safe_browsing = SafeBrowsingResult(
            "not_configured",
            error="GOOGLE_SAFE_BROWSING_API_KEY is not set",
        )
        result.add_finding(
            SEVERITY_INFO,
            "safe-browsing-not-configured",
            "Safe Browsing URL reputation lookup skipped because GOOGLE_SAFE_BROWSING_API_KEY is not set",
            source="safe-browsing",
            artifact="url-reputation-summary.txt",
        )

    try:
        urlhaus = urlhaus_lookup(urls, hosts, options.url_reputation_timeout_seconds)
    except Exception as exc:  # pragma: no cover - defensive guard around caller-provided hooks
        urlhaus = UrlhausResult(
            "error",
            error=_redact_secrets(f"URLhaus lookup failed: {exc}", options.safe_browsing_api_key),
        )
    else:
        urlhaus.error = _redact_secrets(urlhaus.error, options.safe_browsing_api_key)

    _redact_url_reputation_payloads(safe_browsing, urlhaus, options.safe_browsing_api_key)
    _add_url_reputation_artifacts(result, checked_inventory, safe_browsing, urlhaus)

    if safe_browsing.status == "error" or urlhaus.status == "error":
        message = (
            "; ".join(error for error in (safe_browsing.error, urlhaus.error) if error)
            or "One or more URL reputation providers failed"
        )
        result.add_finding(
            SEVERITY_REVIEW,
            "url-reputation-provider-error",
            message,
            source="url-reputation",
            artifact="url-reputation-summary.txt",
        )

    if safe_browsing.matches or urlhaus.url_matches:
        result.add_finding(
            SEVERITY_HIGH,
            "url-reputation-malicious",
            "URL reputation provider reported a malicious exact URL match",
            source="url-reputation",
            artifact="url-reputation-summary.txt",
        )
    if urlhaus.host_matches:
        result.add_finding(
            SEVERITY_REVIEW,
            "url-reputation-host-match",
            "URLhaus reported malware URLs for one or more extracted hosts",
            source="urlhaus",
            artifact="url-reputation-summary.txt",
        )
    if has_suspicious_local_flags(checked_inventory):
        result.add_finding(
            SEVERITY_REVIEW,
            "url-local-risk-flags",
            "One or more extracted URLs have suspicious local URL characteristics",
            source="url-reputation",
            artifact="url-reputation-summary.txt",
        )
    if (
        not safe_browsing.matches
        and not urlhaus.url_matches
        and not urlhaus.host_matches
        and safe_browsing.status not in {"error", "not_configured"}
        and urlhaus.status != "error"
        and not has_suspicious_local_flags(checked_inventory)
    ):
        result.add_finding(
            SEVERITY_INFO,
            "url-reputation-clean",
            "URL reputation providers did not report malicious or suspicious URL signals",
            source="url-reputation",
            artifact="url-reputation-summary.txt",
        )


def _add_url_reputation_artifacts(
    result: ScanResult,
    inventory: UrlInventory,
    safe_browsing: SafeBrowsingResult,
    urlhaus: UrlhausResult,
) -> None:
    result.add_artifact(
        "url-reputation-json",
        "url-reputation.json",
        json.dumps(
            url_reputation_payload(inventory, safe_browsing, urlhaus),
            indent=2,
            sort_keys=True,
        )
        + "\n",
        description="Sanitized URL reputation provider responses",
        role="raw",
    )
    result.add_artifact(
        "url-reputation-summary",
        "url-reputation-summary.txt",
        url_reputation_summary_text(inventory, safe_browsing, urlhaus),
        description="URL reputation summary",
        role="summary",
    )


def _url_inventory_from_result(result: ScanResult) -> UrlInventory | None:
    return inventory_from_json(artifact_text(result, "url-inventory.json"))


def _run_virustotal_enrichment(
    result: ScanResult,
    options: ScanOptions,
    vt_lookup: VTLookup,
) -> None:
    if not options.vt_enabled:
        return
    if not result.sha256:
        return

    if not options.vt_api_key:
        message = "VirusTotal lookup requested but VT_API_KEY is not set"
        result.errors.append(message)
        _add_virustotal_summary(result, "not_configured", error=message)
        result.add_finding(
            SEVERITY_INFO,
            "virustotal-not-configured",
            message,
            source="virustotal",
            artifact="virustotal-summary.txt",
        )
        return

    try:
        lookup = vt_lookup(result.sha256, options.vt_api_key, options.vt_timeout_seconds)
    except Exception as exc:  # pragma: no cover - defensive guard around caller-provided hooks
        lookup = VirusTotalLookupResult(
            "error",
            result.sha256,
            error=_redact_secrets(f"VirusTotal lookup failed: {exc}", options.vt_api_key),
        )
    else:
        lookup.error = _redact_secrets(lookup.error, options.vt_api_key)

    if lookup.raw_json is not None:
        content = lookup.raw_json if lookup.raw_json.endswith("\n") else lookup.raw_json + "\n"
        result.add_artifact(
            "virustotal-json",
            "virustotal.json",
            content,
            description="Raw VirusTotal hash lookup response",
            role="raw",
        )

    _add_virustotal_summary(
        result,
        lookup.status,
        data=lookup.data,
        error=lookup.error,
        http_status=lookup.http_status,
    )

    if lookup.status == "not_found":
        result.add_finding(
            SEVERITY_INFO,
            "virustotal-not-found",
            "VirusTotal has no prior analysis for this SHA-256 hash",
            source="virustotal",
            artifact="virustotal-summary.txt",
        )
        return

    if lookup.status == "error":
        message = lookup.error or "VirusTotal lookup failed"
        result.errors.append(message)
        result.add_finding(
            SEVERITY_INFO,
            "virustotal-error",
            message,
            source="virustotal",
            artifact="virustotal-summary.txt",
        )
        return

    malicious, suspicious = vt_detection_counts(lookup.data)
    if vt_has_malicious_signal(lookup.data):
        message = (
            f"VirusTotal reported {malicious} malicious engine detection{'s' if malicious != 1 else ''}"
            if malicious
            else "VirusTotal reported malicious reputation signals"
        )
        result.add_finding(
            SEVERITY_HIGH,
            "virustotal-malicious",
            message,
            source="virustotal",
            artifact="virustotal-summary.txt",
        )
    elif vt_has_suspicious_signal(lookup.data):
        message = (
            f"VirusTotal reported {suspicious} suspicious engine detection{'s' if suspicious != 1 else ''}"
            if suspicious
            else "VirusTotal reported suspicious reputation signals"
        )
        result.add_finding(
            SEVERITY_REVIEW,
            "virustotal-suspicious",
            message,
            source="virustotal",
            artifact="virustotal-summary.txt",
        )
    else:
        result.add_finding(
            SEVERITY_INFO,
            "virustotal-clean",
            "VirusTotal did not report malicious or suspicious signals for this hash",
            source="virustotal",
            artifact="virustotal-summary.txt",
        )


def _add_virustotal_summary(
    result: ScanResult,
    status: str,
    *,
    data: dict | None = None,
    error: str | None = None,
    http_status: int | None = None,
) -> None:
    if not result.sha256:
        return
    result.add_artifact(
        "virustotal-summary",
        "virustotal-summary.txt",
        virustotal_summary_text(
            status,
            result.sha256,
            data=data,
            error=error,
            http_status=http_status,
        ),
        description="VirusTotal hash lookup summary",
        role="summary",
    )


def _run_common_scan(
    path: Path,
    result: ScanResult,
    options: ScanOptions,
    recorder: _ToolRecorder,
    document_type: str,
) -> None:
    recorder.run("file", ["file", str(path)], "file.txt")
    recorder.run("xattr", ["xattr", "-l", str(path)], "xattr.txt")
    recorder.run("exiftool", ["exiftool", "-a", "-G1", "-s", str(path)], "exiftool.txt")

    clamscan = recorder.run(
        "clamscan",
        ["clamscan", "--infected", "--alert-encrypted=yes", "--heuristic-alerts=yes", str(path)],
        "clamscan.txt",
    )
    if clamav_detected(clamscan):
        result.add_finding(
            SEVERITY_HIGH,
            "av-detection",
            "ClamAV reported a detection",
            source="clamscan",
            artifact="clamscan.txt",
        )

    packaged_rule = packaged_rules_path(document_type)
    custom_rule_index = 0
    for rule in active_rules(document_type, options.rules):
        if rule == packaged_rule:
            recorder.run_yara(
                path,
                "yara-packaged.txt",
                rules_path=rule,
                recursive=False,
                finding_severity=SEVERITY_REVIEW,
                finding_category="heuristic-yara-match",
                finding_message="Packaged heuristic YARA rule matched risky document content",
            )
        else:
            custom_rule_index += 1
            recorder.run_yara(
                path,
                f"yara-rule-{custom_rule_index}.txt",
                rules_path=rule,
                recursive=False,
                finding_severity=SEVERITY_HIGH,
                finding_category="custom-yara-match",
                finding_message="Custom YARA rule reported one or more matches",
            )


def _redact_secrets(text: str | None, *secrets: str | None) -> str | None:
    if text is None:
        return None
    redacted = text
    for secret in secrets:
        if secret:
            redacted = redacted.replace(secret, "[REDACTED]")
    return redacted


def _redact_url_reputation_payloads(
    safe_browsing: SafeBrowsingResult,
    urlhaus: UrlhausResult,
    *secrets: str | None,
) -> None:
    safe_browsing.matches = cast(list[dict[str, Any]], _redact_payload(safe_browsing.matches, *secrets))
    safe_browsing.raw_json = _redact_secrets(safe_browsing.raw_json, *secrets)
    safe_browsing.error = _redact_secrets(safe_browsing.error, *secrets)
    urlhaus.url_matches = cast(list[dict[str, Any]], _redact_payload(urlhaus.url_matches, *secrets))
    urlhaus.host_matches = cast(list[dict[str, Any]], _redact_payload(urlhaus.host_matches, *secrets))
    urlhaus.raw_responses = cast(list[dict[str, Any]], _redact_payload(urlhaus.raw_responses, *secrets))
    urlhaus.error = _redact_secrets(urlhaus.error, *secrets)


def _redact_payload(value: Any, *secrets: str | None) -> Any:
    if isinstance(value, str):
        return _redact_secrets(value, *secrets) or ""
    if isinstance(value, list):
        return [_redact_payload(item, *secrets) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact_payload(item, *secrets) for item in value)
    if isinstance(value, dict):
        return {
            _redact_payload(key, *secrets) if isinstance(key, str) else key: _redact_payload(item, *secrets)
            for key, item in value.items()
        }
    return value


class _ToolRecorder:
    def __init__(self, result: ScanResult, runner: Runner, timeout: int, document_type: str) -> None:
        self.result = result
        self.runner = runner
        self.timeout = timeout
        self.document_type = document_type

    def run(self, logical_name: str, argv: list[str], stdout_artifact: str) -> ToolResult:
        tool = self.runner(argv, self.timeout)
        tool.name = logical_name
        tool.stdout_artifact = stdout_artifact
        if tool.stderr:
            tool.stderr_artifact = f"{stdout_artifact}.stderr"
        self.result.tools.append(tool)
        self.result.add_artifact(logical_name, stdout_artifact, tool.stdout)
        if tool.stderr:
            self.result.add_artifact(f"{logical_name}-stderr", f"{stdout_artifact}.stderr", tool.stderr)
        if tool.missing:
            self.result.errors.append(f"Missing optional tool: {argv[0]}")
        if tool.timed_out:
            self.result.errors.append(f"Tool timed out: {' '.join(argv)}")
        return tool

    def run_yara(
        self,
        target: Path,
        stdout_artifact: str,
        *,
        rules_path: Path | None = None,
        recursive: bool = False,
        finding_severity: str = SEVERITY_REVIEW,
        finding_category: str = "heuristic-yara-match",
        finding_message: str = "Packaged heuristic YARA rule matched risky document content",
    ) -> ToolResult:
        rule = rules_path or packaged_rules_path(self.document_type)
        argv = ["yara", "--print-meta", "--print-strings", "--print-string-length"]
        if recursive:
            argv.append("-r")
        argv.extend([str(rule), str(target)])
        tool = self.run("yara", argv, stdout_artifact)
        if yara_detected(tool):
            self.result.add_finding(
                finding_severity,
                finding_category,
                finding_message,
                source="yara",
                artifact=stdout_artifact,
            )
        return tool
