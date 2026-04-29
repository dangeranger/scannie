from __future__ import annotations

from importlib import resources
from pathlib import Path

PACKAGED_RULES = {
    "pdf": "pdf-risk.yar",
    "epub": "epub-risk.yar",
}


def packaged_rules_path(document_type: str) -> Path:
    try:
        filename = PACKAGED_RULES[document_type]
    except KeyError as exc:
        raise ValueError(f"unsupported document type for packaged rules: {document_type}") from exc
    return Path(str(resources.files("scannie").joinpath(f"rules/{filename}")))


def active_rules(document_type: str, custom_rules: list[Path] | None = None) -> list[Path]:
    rules = [packaged_rules_path(document_type)]
    rules.extend(Path(rule) for rule in custom_rules or [])
    return rules
