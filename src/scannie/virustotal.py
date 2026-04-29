from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

VT_FILE_URL = "https://www.virustotal.com/api/v3/files"
VT_GUI_URL = "https://www.virustotal.com/gui/file"


@dataclass(slots=True)
class VirusTotalLookupResult:
    status: str
    sha256: str
    data: dict[str, Any] | None = None
    raw_json: str | None = None
    http_status: int | None = None
    error: str | None = None


VirusTotalOpener = Callable[..., Any]


def lookup_file_hash(
    sha256: str,
    api_key: str,
    timeout: int | float = 15,
    *,
    opener: VirusTotalOpener = urlopen,
) -> VirusTotalLookupResult:
    request = Request(f"{VT_FILE_URL}/{sha256}")
    request.add_header("Accept", "application/json")
    request.add_header("x-apikey", api_key)

    try:
        with opener(request, timeout=timeout) as response:
            raw = _read_response(response)
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError as exc:
                return VirusTotalLookupResult(
                    "error",
                    sha256,
                    raw_json=raw,
                    http_status=getattr(response, "status", 200),
                    error=f"VirusTotal returned malformed JSON: {exc}",
                )
            return VirusTotalLookupResult(
                "found",
                sha256,
                data=payload,
                raw_json=raw,
                http_status=getattr(response, "status", 200),
            )
    except HTTPError as exc:
        raw = _read_response(exc)
        message = _error_message(raw) or exc.reason or f"HTTP {exc.code}"
        if exc.code == 404:
            return VirusTotalLookupResult(
                "not_found",
                sha256,
                raw_json=raw or None,
                http_status=exc.code,
                error=message,
            )
        return VirusTotalLookupResult(
            "error",
            sha256,
            raw_json=raw or None,
            http_status=exc.code,
            error=f"VirusTotal HTTP {exc.code}: {message}",
        )
    except TimeoutError as exc:
        return VirusTotalLookupResult("error", sha256, error=f"VirusTotal lookup timed out: {exc}")
    except URLError as exc:
        return VirusTotalLookupResult("error", sha256, error=f"VirusTotal network error: {exc.reason}")
    except OSError as exc:
        return VirusTotalLookupResult("error", sha256, error=f"VirusTotal lookup failed: {exc}")


def virustotal_summary_text(
    status: str,
    sha256: str,
    *,
    data: dict[str, Any] | None = None,
    error: str | None = None,
    http_status: int | None = None,
) -> str:
    lines = [
        "VirusTotal Summary",
        "",
        "Lookup mode: hash only; file was not uploaded",
        f"VT link: {VT_GUI_URL}/{sha256}",
    ]

    if status == "not_configured":
        lines.extend(["Known to VirusTotal: not checked", f"Status: {error or 'VT_API_KEY is not set'}"])
        return "\n".join(lines) + "\n"

    if status == "not_found":
        lines.extend(["Known to VirusTotal: no", f"Status: {error or 'hash was not found'}"])
        return "\n".join(lines) + "\n"

    if status == "error":
        status_line = f"Status: {error or 'lookup failed'}"
        if http_status is not None:
            status_line += f" (HTTP {http_status})"
        lines.extend(["Known to VirusTotal: unknown", status_line])
        return "\n".join(lines) + "\n"

    attrs = _attributes(data)
    stats = _analysis_stats(attrs)
    lines.append("Known to VirusTotal: yes")
    lines.append("")
    lines.append("File:")
    lines.append(f"- meaningful_name: {attrs.get('meaningful_name', 'unknown')}")
    lines.append(f"- type_description: {attrs.get('type_description', 'unknown')}")
    lines.append(f"- size: {attrs.get('size', 'unknown')}")
    lines.append(f"- md5: {attrs.get('md5', 'unknown')}")
    lines.append(f"- sha1: {attrs.get('sha1', 'unknown')}")
    lines.append(f"- sha256: {attrs.get('sha256') or sha256}")
    lines.append(f"- first_submission_date: {_format_epoch(attrs.get('first_submission_date'))}")
    lines.append(f"- last_submission_date: {_format_epoch(attrs.get('last_submission_date'))}")
    lines.append(f"- last_analysis_date: {_format_epoch(attrs.get('last_analysis_date'))}")
    lines.append(f"- times_submitted: {attrs.get('times_submitted', 'unknown')}")
    lines.append(f"- reputation: {attrs.get('reputation', 'unknown')}")
    lines.append(f"- tags: {_join_values(attrs.get('tags'))}")
    lines.append("")
    lines.append("Detection stats:")
    for key in ("malicious", "suspicious", "undetected", "harmless", "timeout"):
        lines.append(f"- {key}: {_count(stats.get(key))}")
    lines.append("")
    lines.append("Votes:")
    raw_votes = attrs.get("total_votes")
    votes: dict[str, Any] = raw_votes if isinstance(raw_votes, dict) else {}
    lines.append(f"- harmless: {_count(votes.get('harmless'))}")
    lines.append(f"- malicious: {_count(votes.get('malicious'))}")
    lines.append("")
    lines.extend(_sandbox_lines(attrs))
    lines.append("")
    lines.extend(_crowdsourced_lines(attrs))
    return "\n".join(lines) + "\n"


def vt_has_malicious_signal(data: dict[str, Any] | None) -> bool:
    attrs = _attributes(data)
    stats = _analysis_stats(attrs)
    if _count(stats.get("malicious")) > 0:
        return True
    if _normalized(attrs.get("threat_verdict")) == "VERDICT_MALICIOUS":
        return True
    return any(_normalized(verdict.get("category")) == "MALICIOUS" for verdict in _sandbox_verdicts(attrs))


def vt_has_suspicious_signal(data: dict[str, Any] | None) -> bool:
    attrs = _attributes(data)
    stats = _analysis_stats(attrs)
    if _count(stats.get("suspicious")) > 0:
        return True
    if _normalized(attrs.get("threat_verdict")) == "VERDICT_SUSPICIOUS":
        return True
    if any(_normalized(verdict.get("category")) == "SUSPICIOUS" for verdict in _sandbox_verdicts(attrs)):
        return True
    return bool(_crowdsourced_items(attrs))


def vt_detection_counts(data: dict[str, Any] | None) -> tuple[int, int]:
    stats = _analysis_stats(_attributes(data))
    return _count(stats.get("malicious")), _count(stats.get("suspicious"))


def _read_response(response: Any) -> str:
    body = response.read()
    if isinstance(body, bytes):
        return body.decode("utf-8", errors="replace")
    return str(body)


def _error_message(raw: str) -> str | None:
    if not raw:
        return None
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return raw.strip() or None
    error = payload.get("error") if isinstance(payload, dict) else None
    if isinstance(error, dict):
        message = error.get("message") or error.get("code")
        return str(message) if message else None
    return None


def _attributes(data: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(data, dict):
        return {}
    node = data.get("data")
    if not isinstance(node, dict):
        return {}
    attrs = node.get("attributes")
    return attrs if isinstance(attrs, dict) else {}


def _analysis_stats(attrs: dict[str, Any]) -> dict[str, Any]:
    stats = attrs.get("last_analysis_stats")
    return stats if isinstance(stats, dict) else {}


def _sandbox_verdicts(attrs: dict[str, Any]) -> list[dict[str, Any]]:
    verdicts = attrs.get("sandbox_verdicts")
    if isinstance(verdicts, dict):
        return [value for value in verdicts.values() if isinstance(value, dict)]
    return []


def _crowdsourced_items(attrs: dict[str, Any]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for key in (
        "crowdsourced_yara_results",
        "crowdsourced_ids_results",
        "sigma_analysis_results",
    ):
        value = attrs.get(key)
        if isinstance(value, list):
            items.extend(item for item in value if isinstance(item, dict))
    sigma_stats = attrs.get("sigma_analysis_stats")
    if isinstance(sigma_stats, dict) and any(_count(value) > 0 for value in sigma_stats.values()):
        items.append({"source": "sigma_analysis_stats", **sigma_stats})
    return items


def _sandbox_lines(attrs: dict[str, Any]) -> list[str]:
    lines = ["Sandbox verdicts:"]
    verdicts = _sandbox_verdicts(attrs)
    if not verdicts:
        lines.append("- none reported")
        return lines
    for verdict in verdicts:
        category = verdict.get("category", "unknown")
        classification = _join_values(verdict.get("malware_classification"))
        lines.append(f"- {category}; classification: {classification}")
    return lines


def _crowdsourced_lines(attrs: dict[str, Any]) -> list[str]:
    lines = ["Crowdsourced rule signals:"]
    items = _crowdsourced_items(attrs)
    if not items:
        lines.append("- none reported")
        return lines
    for item in items[:20]:
        name = item.get("rule_name") or item.get("rule_id") or item.get("source") or item.get("id") or "unnamed"
        lines.append(f"- {name}")
    if len(items) > 20:
        lines.append(f"- ... {len(items) - 20} additional signals")
    return lines


def _format_epoch(value: object) -> str:
    if not isinstance(value, int | float):
        return "unknown"
    return datetime.fromtimestamp(value, UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def _join_values(value: object) -> str:
    if isinstance(value, list | tuple | set):
        return ", ".join(str(item) for item in value) if value else "none"
    if value is None:
        return "none"
    return str(value)


def _count(value: object) -> int:
    return value if isinstance(value, int) else 0


def _normalized(value: object) -> str:
    return str(value or "").strip().upper()
