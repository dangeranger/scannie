from __future__ import annotations

import subprocess

from .models import ToolResult


def _decode_output(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def run_tool(argv: list[str], timeout: int = 30) -> ToolResult:
    if not argv:
        raise ValueError("argv must not be empty")

    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            text=False,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        return ToolResult(
            name=argv[0],
            argv=argv,
            status="missing",
            error=str(exc),
            missing=True,
        )
    except subprocess.TimeoutExpired as exc:
        return ToolResult(
            name=argv[0],
            argv=argv,
            status="timeout",
            stdout=_decode_output(exc.stdout),
            stderr=_decode_output(exc.stderr),
            error=f"Timed out after {timeout} seconds",
            timed_out=True,
        )

    status = "ok" if completed.returncode == 0 else "nonzero"
    return ToolResult(
        name=argv[0],
        argv=argv,
        status=status,
        returncode=completed.returncode,
        stdout=_decode_output(completed.stdout),
        stderr=_decode_output(completed.stderr),
    )
