from __future__ import annotations

import re

from .models import ToolResult
from .yara import parse_yara_output

_CLAMAV_FOUND_RE = re.compile(r"^.+:\s+.+\s+FOUND$")


def clamav_detected(tool: ToolResult) -> bool:
    if tool.missing or tool.timed_out or tool.returncode != 1:
        return False
    return any(_CLAMAV_FOUND_RE.match(line.strip()) for line in tool.stdout.splitlines())


def yara_detected(tool: ToolResult) -> bool:
    return not tool.missing and not tool.timed_out and bool(parse_yara_output(tool.stdout))
