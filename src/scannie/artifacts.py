from __future__ import annotations

from .models import ScanResult


def artifact_text(result: ScanResult, relative_path: str) -> str:
    for artifact in result.artifacts:
        if artifact.relative_path != relative_path:
            continue
        if isinstance(artifact.content, bytes):
            return artifact.content.decode("utf-8", errors="replace")
        return artifact.content or ""
    return ""
