from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

VERDICT_LOW = "low"
VERDICT_REVIEW = "review"
VERDICT_HIGH = "high"
VERDICT_ERROR = "error"

SEVERITY_INFO = "info"
SEVERITY_REVIEW = "review"
SEVERITY_HIGH = "high"
SEVERITY_ERROR = "error"


def _path_to_str(value: Path | str | None) -> str | None:
    if value is None:
        return None
    return str(value)


@dataclass(slots=True)
class Finding:
    severity: str
    category: str
    message: str
    source: str | None = None
    artifact: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "category": self.category,
            "message": self.message,
            "source": self.source,
            "artifact": self.artifact,
        }


@dataclass(slots=True)
class ToolResult:
    name: str
    argv: list[str]
    status: str
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""
    stdout_artifact: str | None = None
    stderr_artifact: str | None = None
    error: str | None = None
    timed_out: bool = False
    missing: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "argv": self.argv,
            "status": self.status,
            "returncode": self.returncode,
            "stdout_artifact": self.stdout_artifact,
            "stderr_artifact": self.stderr_artifact,
            "error": self.error,
            "timed_out": self.timed_out,
            "missing": self.missing,
        }


@dataclass(slots=True)
class Artifact:
    name: str
    relative_path: str
    content: str | bytes | None = None
    description: str = ""
    binary: bool = False
    role: str = "raw"
    size_bytes: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "path": self.relative_path,
            "description": self.description,
            "binary": self.binary,
            "role": self.role,
            "size_bytes": self.size_bytes,
        }


@dataclass(slots=True)
class ScanOptions:
    out_dir: Path | None = None
    report_dir: Path | None = None
    rules: list[Path] = field(default_factory=list)
    max_expanded_size: int = 250 * 1024 * 1024
    force_type: str | None = None
    timeout_seconds: int = 30
    vt_enabled: bool = False
    vt_api_key: str | None = None
    vt_timeout_seconds: int = 15
    url_reputation_enabled: bool = False
    safe_browsing_api_key: str | None = None
    url_reputation_timeout_seconds: int = 15
    url_reputation_max_urls: int = 500


@dataclass(slots=True)
class ScanResult:
    input_path: str
    file_name: str
    verdict: str = VERDICT_ERROR
    file_type: str | None = None
    sha256: str | None = None
    size_bytes: int | None = None
    report_dir: str | None = None
    findings: list[Finding] = field(default_factory=list)
    tools: list[ToolResult] = field(default_factory=list)
    artifacts: list[Artifact] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def add_finding(
        self,
        severity: str,
        category: str,
        message: str,
        *,
        source: str | None = None,
        artifact: str | None = None,
    ) -> None:
        self.findings.append(
            Finding(
                severity=severity,
                category=category,
                message=message,
                source=source,
                artifact=artifact,
            )
        )

    def add_artifact(
        self,
        name: str,
        relative_path: str,
        content: str | bytes | None = None,
        *,
        description: str = "",
        binary: bool = False,
        role: str = "raw",
    ) -> Artifact:
        artifact = Artifact(
            name=name,
            relative_path=relative_path,
            content=content,
            description=description,
            binary=binary,
            role=role,
        )
        self.artifacts.append(artifact)
        return artifact

    def to_dict(self) -> dict[str, Any]:
        return {
            "input_path": self.input_path,
            "file_name": self.file_name,
            "verdict": self.verdict,
            "file_type": self.file_type,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "report_dir": self.report_dir,
            "findings": [finding.to_dict() for finding in self.findings],
            "tools": [tool.to_dict() for tool in self.tools],
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "errors": self.errors,
        }


def make_result(path: Path) -> ScanResult:
    resolved = path.resolve()
    return ScanResult(input_path=str(resolved), file_name=resolved.name)
