from __future__ import annotations

import ipaddress
import json
import re
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urlparse
from urllib.request import Request, urlopen

SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
URLHAUS_URL_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"
URLHAUS_HOST_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/host/"

URL_PATTERN = re.compile(r"https?://[^\s<>)\"']+", re.IGNORECASE)
SHORTENER_HOSTS = {
    "bit.ly",
    "buff.ly",
    "cutt.ly",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "rebrand.ly",
    "s.id",
    "t.co",
    "tinyurl.com",
}
EXECUTABLE_SUFFIXES = {
    # URL paths include script/archive download extensions that are not always
    # meaningful as embedded PDF attachment filenames.
    ".app",
    ".bat",
    ".cmd",
    ".com",
    ".dmg",
    ".exe",
    ".hta",
    ".jar",
    ".js",
    ".msi",
    ".pkg",
    ".ps1",
    ".scr",
    ".sh",
    ".vbs",
    ".zip",
}
TOKEN_QUERY_KEYS = {
    "access_token",
    "auth",
    "code",
    "key",
    "password",
    "secret",
    "session",
    "token",
}


@dataclass(slots=True)
class UrlInventoryItem:
    url: str
    scheme: str
    host: str
    domain: str
    count: int
    source_artifact: str
    flags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "scheme": self.scheme,
            "host": self.host,
            "domain": self.domain,
            "count": self.count,
            "source_artifact": self.source_artifact,
            "flags": self.flags,
        }


@dataclass(slots=True)
class UrlInventory:
    urls: list[UrlInventoryItem] = field(default_factory=list)
    discarded_count: int = 0
    discarded_examples: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "urls": [url.to_dict() for url in self.urls],
            "discarded_count": self.discarded_count,
            "discarded_examples": self.discarded_examples,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> UrlInventory:
        items = []
        for raw in data.get("urls", []):
            if not isinstance(raw, dict) or not raw.get("url"):
                continue
            items.append(
                UrlInventoryItem(
                    url=str(raw.get("url")),
                    scheme=str(raw.get("scheme") or ""),
                    host=str(raw.get("host") or ""),
                    domain=str(raw.get("domain") or ""),
                    count=int(raw.get("count") or 0),
                    source_artifact=str(raw.get("source_artifact") or ""),
                    flags=[str(flag) for flag in raw.get("flags", []) if isinstance(flag, str)],
                )
            )
        return cls(
            urls=items,
            discarded_count=int(data.get("discarded_count") or 0),
            discarded_examples=[
                str(example) for example in data.get("discarded_examples", []) if isinstance(example, str)
            ],
        )


@dataclass(slots=True)
class SafeBrowsingResult:
    status: str
    matches: list[dict[str, Any]] = field(default_factory=list)
    raw_json: str | None = None
    error: str | None = None
    http_status: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "matches": self.matches,
            "error": self.error,
            "http_status": self.http_status,
        }


@dataclass(slots=True)
class UrlhausResult:
    status: str
    url_matches: list[dict[str, Any]] = field(default_factory=list)
    host_matches: list[dict[str, Any]] = field(default_factory=list)
    raw_responses: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None
    http_status: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "url_matches": self.url_matches,
            "host_matches": self.host_matches,
            "raw_responses": self.raw_responses,
            "error": self.error,
            "http_status": self.http_status,
        }


UrlReputationOpener = Callable[..., Any]


def extract_url_inventory(text: str, source_artifact: str = "pdf-risky-strings.txt") -> UrlInventory:
    counts: Counter[str] = Counter()
    discarded = 0
    discarded_examples: list[str] = []
    for match in URL_PATTERN.finditer(text):
        candidate = _trim_url_candidate(match.group(0))
        if _valid_url(candidate):
            counts[candidate] += 1
        else:
            discarded += 1
            if len(discarded_examples) < 10:
                discarded_examples.append(_printable_excerpt(candidate))

    items: list[UrlInventoryItem] = []
    for url, count in sorted(counts.items()):
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        items.append(
            UrlInventoryItem(
                url=url,
                scheme=parsed.scheme.lower(),
                host=host,
                domain=_effective_domain(host),
                count=count,
                source_artifact=source_artifact,
                flags=_local_url_flags(url),
            )
        )
    return UrlInventory(items, discarded, discarded_examples)


def inventory_from_json(text: str) -> UrlInventory | None:
    if not text.strip():
        return None
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    return UrlInventory.from_dict(data)


def url_inventory_summary_text(inventory: UrlInventory) -> str:
    lines = ["PDF URL Summary", ""]
    if not inventory.urls:
        lines.append("No URLs were found in risky string output.")
        lines.append(f"Discarded noisy URL-like matches: {inventory.discarded_count}")
        return "\n".join(lines) + "\n"

    domain_counts = Counter()
    for item in inventory.urls:
        domain_counts[item.host] += item.count
    pragprog_domains = Counter(
        {domain: count for domain, count in domain_counts.items() if _is_pragprog_domain(domain)}
    )
    other_domains = Counter(
        {domain: count for domain, count in domain_counts.items() if not _is_pragprog_domain(domain)}
    )

    lines.append(f"Unique URLs: {len(inventory.urls)}")
    lines.append(f"Unique domains: {len(domain_counts)}")
    lines.append(f"Discarded noisy URL-like matches: {inventory.discarded_count}")
    lines.append("")
    lines.append("PragProg domains:")
    if pragprog_domains:
        for domain, count in pragprog_domains.most_common():
            lines.append(f"- {domain}: {count}")
    else:
        lines.append("- none")
    lines.append("")
    lines.append("Other domains:")
    if other_domains:
        for domain, count in other_domains.most_common():
            lines.append(f"- {domain}: {count}")
    else:
        lines.append("- none")
    lines.append("")
    lines.append("URLs:")
    for item in inventory.urls:
        flag_text = f" flags={','.join(item.flags)}" if item.flags else ""
        lines.append(f"- {item.url}{flag_text}")
    return "\n".join(lines) + "\n"


def lookup_safe_browsing(
    urls: list[str],
    api_key: str,
    timeout: int | float = 15,
    *,
    opener: UrlReputationOpener = urlopen,
) -> SafeBrowsingResult:
    if not urls:
        return SafeBrowsingResult("no_urls")
    matches: list[dict[str, Any]] = []
    raw_payloads: list[dict[str, Any]] = []
    try:
        for batch in _batches(urls, 500):
            request_payload = {
                "client": {"clientId": "scannie", "clientVersion": "0.1.0"},
                "threatInfo": {
                    "threatTypes": [
                        "MALWARE",
                        "SOCIAL_ENGINEERING",
                        "UNWANTED_SOFTWARE",
                        "POTENTIALLY_HARMFUL_APPLICATION",
                    ],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url} for url in batch],
                },
            }
            # Safe Browsing documents the API key as a query parameter. Keep
            # error handling below limited to response bodies, not full_url.
            request = Request(
                f"{SAFE_BROWSING_URL}?key={api_key}",
                data=json.dumps(request_payload).encode("utf-8"),
                headers={"Content-Type": "application/json", "Accept": "application/json"},
                method="POST",
            )
            with opener(request, timeout=timeout) as response:
                raw = _read_response(response)
                payload = _json_payload(raw)
                raw_payloads.append(payload)
                batch_matches = payload.get("matches", [])
                if isinstance(batch_matches, list):
                    matches.extend(item for item in batch_matches if isinstance(item, dict))
        return SafeBrowsingResult("ok", matches=matches, raw_json=json.dumps(raw_payloads), http_status=200)
    except HTTPError as exc:
        raw = _read_response(exc)
        if raw:
            raw_payloads.append({"error": raw})
        return SafeBrowsingResult(
            "error",
            matches=matches,
            raw_json=json.dumps(raw_payloads) if raw_payloads else None,
            error=f"Safe Browsing HTTP {exc.code}: {_http_error_message_from_raw(raw, exc.reason)}",
            http_status=exc.code,
        )
    except json.JSONDecodeError as exc:
        return SafeBrowsingResult(
            "error",
            matches=matches,
            raw_json=json.dumps(raw_payloads) if raw_payloads else None,
            error=f"Safe Browsing returned malformed JSON: {exc}",
        )
    except TimeoutError as exc:
        return SafeBrowsingResult(
            "error",
            matches=matches,
            raw_json=json.dumps(raw_payloads) if raw_payloads else None,
            error=f"Safe Browsing lookup timed out: {exc}",
        )
    except URLError as exc:
        return SafeBrowsingResult(
            "error",
            matches=matches,
            raw_json=json.dumps(raw_payloads) if raw_payloads else None,
            error=f"Safe Browsing network error: {exc.reason}",
        )
    except OSError as exc:
        return SafeBrowsingResult(
            "error",
            matches=matches,
            raw_json=json.dumps(raw_payloads) if raw_payloads else None,
            error=f"Safe Browsing lookup failed: {exc}",
        )


def lookup_urlhaus(
    urls: list[str],
    hosts: list[str],
    timeout: int | float = 15,
    *,
    opener: UrlReputationOpener = urlopen,
) -> UrlhausResult:
    url_matches: list[dict[str, Any]] = []
    host_matches: list[dict[str, Any]] = []
    raw_responses: list[dict[str, Any]] = []
    try:
        for url in urls:
            payload = _post_urlhaus(URLHAUS_URL_ENDPOINT, {"url": url}, timeout, opener)
            raw_responses.append({"kind": "url", "target": url, "response": payload})
            if _urlhaus_hit(payload):
                url_matches.append(payload)
        for host in hosts:
            payload = _post_urlhaus(URLHAUS_HOST_ENDPOINT, {"host": host}, timeout, opener)
            raw_responses.append({"kind": "host", "target": host, "response": payload})
            if _urlhaus_hit(payload):
                host_matches.append({"host": host, **payload})
        return UrlhausResult(
            "ok",
            url_matches=url_matches,
            host_matches=host_matches,
            raw_responses=raw_responses,
            http_status=200,
        )
    except HTTPError as exc:
        return UrlhausResult(
            "error",
            url_matches=url_matches,
            host_matches=host_matches,
            raw_responses=raw_responses,
            error=f"URLhaus HTTP {exc.code}: {_http_error_message(exc)}",
            http_status=exc.code,
        )
    except json.JSONDecodeError as exc:
        return UrlhausResult(
            "error",
            url_matches=url_matches,
            host_matches=host_matches,
            raw_responses=raw_responses,
            error=f"URLhaus returned malformed JSON: {exc}",
        )
    except TimeoutError as exc:
        return UrlhausResult("error", url_matches, host_matches, raw_responses, f"URLhaus lookup timed out: {exc}")
    except URLError as exc:
        return UrlhausResult("error", url_matches, host_matches, raw_responses, f"URLhaus network error: {exc.reason}")
    except OSError as exc:
        return UrlhausResult("error", url_matches, host_matches, raw_responses, f"URLhaus lookup failed: {exc}")


def url_reputation_payload(
    inventory: UrlInventory,
    safe_browsing: SafeBrowsingResult,
    urlhaus: UrlhausResult,
) -> dict[str, Any]:
    return {
        "urls_checked": len(inventory.urls),
        "hosts_checked": len({item.host for item in inventory.urls}),
        "providers": {
            "safe_browsing": safe_browsing.to_dict(),
            "urlhaus": urlhaus.to_dict(),
        },
    }


def url_reputation_summary_text(
    inventory: UrlInventory,
    safe_browsing: SafeBrowsingResult,
    urlhaus: UrlhausResult,
) -> str:
    lines = [
        "URL Reputation Summary",
        "",
        "Lookup mode: reputation API lookup only; URLs were not fetched or rendered by scannie",
        f"URLs checked: {len(inventory.urls)}",
        f"Hosts checked: {len({item.host for item in inventory.urls})}",
        f"Discarded noisy URL-like matches: {inventory.discarded_count}",
        "",
        _safe_browsing_status_line(safe_browsing),
        _urlhaus_status_line(urlhaus),
    ]

    suspicious = [item for item in inventory.urls if _suspicious_flags(item.flags)]
    if suspicious:
        lines.extend(["", "Local URL flags:"])
        for item in suspicious[:20]:
            lines.append(f"- {item.url}: {', '.join(item.flags)}")
        if len(suspicious) > 20:
            lines.append(f"- ... {len(suspicious) - 20} additional flagged URLs")

    if safe_browsing.matches:
        lines.extend(["", "Safe Browsing matches:"])
        for match in safe_browsing.matches[:20]:
            raw_threat = match.get("threat")
            threat: dict[str, Any] = raw_threat if isinstance(raw_threat, dict) else {}
            lines.append(f"- {match.get('threatType', 'unknown')}: {threat.get('url', 'unknown')}")
    if urlhaus.url_matches:
        lines.extend(["", "URLhaus exact URL matches:"])
        for match in urlhaus.url_matches[:20]:
            lines.append(f"- {match.get('url', 'unknown')}: {match.get('threat', 'unknown')}")
    if urlhaus.host_matches:
        lines.extend(["", "URLhaus host matches:"])
        for match in urlhaus.host_matches[:20]:
            lines.append(f"- {match.get('host', 'unknown')}")
    return "\n".join(lines) + "\n"


def has_suspicious_local_flags(inventory: UrlInventory) -> bool:
    return any(_suspicious_flags(item.flags) for item in inventory.urls)


def _post_urlhaus(
    endpoint: str,
    form: dict[str, str],
    timeout: int | float,
    opener: UrlReputationOpener,
) -> dict[str, Any]:
    request = Request(
        endpoint,
        data=urlencode(form).encode("utf-8"),
        headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
        method="POST",
    )
    with opener(request, timeout=timeout) as response:
        return _json_payload(_read_response(response))


def _urlhaus_hit(payload: dict[str, Any]) -> bool:
    return payload.get("query_status") == "ok"


def _safe_browsing_status_line(result: SafeBrowsingResult) -> str:
    if result.status == "not_configured":
        return f"Safe Browsing: not checked ({result.error or 'missing API key'})"
    if result.status == "error":
        return f"Safe Browsing: error ({result.error or 'unknown error'})"
    if result.status == "no_urls":
        return "Safe Browsing: no URLs to check"
    count = len(result.matches)
    return f"Safe Browsing: {count} match{'es' if count != 1 else ''}" if count else "Safe Browsing: no matches"


def _urlhaus_status_line(result: UrlhausResult) -> str:
    if result.status == "error":
        return f"URLhaus: error ({result.error or 'unknown error'})"
    exact = len(result.url_matches)
    hosts = len(result.host_matches)
    if exact or hosts:
        return f"URLhaus: {exact} exact URL match{'es' if exact != 1 else ''}, {hosts} host match{'es' if hosts != 1 else ''}"
    return "URLhaus: no matches"


def _suspicious_flags(flags: list[str]) -> list[str]:
    return [flag for flag in flags if flag != "plain-http"]


def _local_url_flags(url: str) -> list[str]:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    flags: list[str] = []
    if parsed.scheme.lower() == "http":
        flags.append("plain-http")
    if _is_ip_literal(host):
        flags.append("ip-literal")
    if host in SHORTENER_HOSTS:
        flags.append("url-shortener")
    if "xn--" in host:
        flags.append("punycode")
    if any(parsed.path.lower().endswith(suffix) for suffix in EXECUTABLE_SUFFIXES):
        flags.append("executable-path")
    query_keys = {key.lower() for key in parse_qs(parsed.query)}
    if TOKEN_QUERY_KEYS & query_keys:
        flags.append("query-token")
    return flags


def _valid_url(url: str) -> bool:
    if any(ord(char) < 33 or ord(char) > 126 for char in url):
        return False
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    if parsed.scheme.lower() not in {"http", "https"}:
        return False
    host = parsed.hostname
    if not host:
        return False
    if _is_ip_literal(host):
        return True
    if not re.fullmatch(r"[A-Za-z0-9.-]+", host):
        return False
    return "." in host


def _trim_url_candidate(candidate: str) -> str:
    trimmed = candidate.rstrip(".,;:")
    while trimmed.endswith("]") and not _trailing_bracket_closes_ipv6_host(trimmed):
        trimmed = trimmed[:-1].rstrip(".,;:")
    return trimmed


def _trailing_bracket_closes_ipv6_host(url: str) -> bool:
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    netloc_start = len(parsed.scheme) + 3
    return parsed.netloc.startswith("[") and url.find("]", netloc_start) == len(url) - 1


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _effective_domain(host: str) -> str:
    if _is_ip_literal(host):
        return host
    labels = [label for label in host.lower().split(".") if label]
    if len(labels) < 2:
        return host.lower()
    return ".".join(labels[-2:])


def _is_pragprog_domain(domain: str) -> bool:
    return domain == "pragprog.com" or domain.endswith(".pragprog.com")


def _read_response(response: Any) -> str:
    body = response.read()
    if isinstance(body, bytes):
        return body.decode("utf-8", errors="replace")
    return str(body)


def _json_payload(raw: str) -> dict[str, Any]:
    payload = json.loads(raw or "{}")
    if not isinstance(payload, dict):
        raise json.JSONDecodeError("expected JSON object", raw, 0)
    return payload


def _http_error_message(exc: HTTPError) -> str:
    raw = _read_response(exc)
    return _http_error_message_from_raw(raw, exc.reason)


def _http_error_message_from_raw(raw: str, fallback: str | None) -> str:
    if not raw:
        return fallback or "HTTP error"
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return raw.strip() or fallback or "HTTP error"
    error = payload.get("error") if isinstance(payload, dict) else None
    if isinstance(error, dict):
        return str(error.get("message") or error.get("code") or fallback or "HTTP error")
    return fallback or "HTTP error"


def _batches(values: list[str], size: int) -> list[list[str]]:
    return [values[index : index + size] for index in range(0, len(values), size)]


def _printable_excerpt(text: str) -> str:
    cleaned = "".join(char if 32 <= ord(char) <= 126 else "?" for char in text)
    return cleaned[:160]
