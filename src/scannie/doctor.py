from __future__ import annotations

import shutil
from dataclasses import dataclass

TOOLCHAIN = [
    "file",
    "xattr",
    "exiftool",
    "clamscan",
    "yara",
    "qpdf",
    "strings",
    "rg",
    "epubcheck",
    "zipinfo",
]

BREW_GUIDANCE = "brew install clamav yara qpdf exiftool jq ripgrep epubcheck"


@dataclass(slots=True)
class DoctorResult:
    present: list[str]
    missing: list[str]


def check_tools() -> DoctorResult:
    present: list[str] = []
    missing: list[str] = []
    for tool in TOOLCHAIN:
        if shutil.which(tool):
            present.append(tool)
        else:
            missing.append(tool)
    return DoctorResult(present=present, missing=missing)


def doctor_text(result: DoctorResult) -> str:
    lines = ["scannie doctor", ""]
    for tool in TOOLCHAIN:
        status = "ok" if tool in result.present else "missing"
        lines.append(f"{tool}: {status}")
    if result.missing:
        lines.extend(["", "Install missing tools with Homebrew:", BREW_GUIDANCE])
    return "\n".join(lines) + "\n"
