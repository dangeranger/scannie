from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(slots=True)
class YaraStringMatch:
    offset: str
    identifier: str
    value: str
    length: int | None = None


@dataclass(slots=True)
class YaraRuleMatch:
    name: str
    target: str
    metadata: dict[str, str] = field(default_factory=dict)
    strings: list[YaraStringMatch] = field(default_factory=list)


PACKAGED_RULE_DETAILS = {
    "PDF_Risky_Actions": {
        "purpose": "Flags PDFs that contain active-content or risky document-action tokens.",
        "risk": "Packaged heuristic; review the matched strings and PDF findings before treating it as hostile.",
        "why": "%PDF- is present and at least one risky PDF token matched, such as /JS, /JavaScript, /OpenAction, /AA, /Launch, /EmbeddedFile, /RichMedia, /XFA, or /SubmitForm.",
    },
    "EPUB_Risky_Web_Content": {
        "purpose": "Flags EPUB content that contains script, event-handler, network, embed, or remote-resource indicators.",
        "risk": "Packaged heuristic; review matched strings and EPUB findings before treating it as hostile.",
        "why": "At least one risky web-content token matched, such as <script, javascript:, event handlers, fetch, XMLHttpRequest, WebSocket, iframe/object/embed, or remote URLs.",
    },
}


def parse_yara_output(stdout: str) -> list[YaraRuleMatch]:
    matches: list[YaraRuleMatch] = []
    current: YaraRuleMatch | None = None

    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        string_match = _parse_string_line(line)
        if string_match:
            if current:
                current.strings.append(string_match)
            continue

        rule_match = _parse_rule_line(line)
        if rule_match:
            matches.append(rule_match)
            current = rule_match

    return matches


def yara_rule_match_count(stdout: str) -> int:
    parsed = parse_yara_output(stdout)
    if parsed:
        return len(parsed)
    return len([line for line in stdout.splitlines() if line.strip()])


def packaged_rule_details(rule_name: str) -> dict[str, str]:
    return PACKAGED_RULE_DETAILS.get(
        rule_name,
        {
            "purpose": "Packaged heuristic YARA rule.",
            "risk": "Review the matched strings before treating this as hostile.",
            "why": "The YARA rule condition was satisfied.",
        },
    )


def _parse_string_line(line: str) -> YaraStringMatch | None:
    match = re.match(
        r"^(?P<offset>0x[0-9a-fA-F]+):(?:(?P<length>\d+):)?(?P<identifier>\$[A-Za-z0-9_*]+):\s?(?P<value>.*)$",
        line,
    )
    if not match:
        return None
    length = match.group("length")
    return YaraStringMatch(
        offset=match.group("offset"),
        length=int(length) if length is not None else None,
        identifier=match.group("identifier"),
        value=match.group("value"),
    )


def _parse_rule_line(line: str) -> YaraRuleMatch | None:
    match = re.match(
        r"^(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?:\[(?P<meta>.*?)\])?\s+(?P<target>.+)$",
        line,
    )
    if not match:
        return None
    return YaraRuleMatch(
        name=match.group("name"),
        target=match.group("target"),
        metadata=_parse_metadata(match.group("meta") or ""),
    )


def _parse_metadata(text: str) -> dict[str, str]:
    metadata: dict[str, str] = {}
    for key, quoted, bare in re.findall(r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:\"([^\"]*)\"|([^,\]]+))", text):
        metadata[key] = quoted or bare.strip()
    return metadata
