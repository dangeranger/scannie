from __future__ import annotations

from collections.abc import Callable

from scannie.models import ToolResult


def empty_runner(argv: list[str], timeout: int) -> ToolResult:
    return ToolResult(name=argv[0], argv=argv, status="missing", missing=True, error="missing")


def mapping_runner(mapping: dict[str, ToolResult | Callable[[list[str]], ToolResult]]):
    def _run(argv: list[str], timeout: int) -> ToolResult:
        value: ToolResult | Callable[[list[str]], ToolResult] | None = None
        for length in range(len(argv), 0, -1):
            key = " ".join(argv[:length])
            if key in mapping:
                value = mapping[key]
                break
        if isinstance(value, ToolResult):
            return value
        if value is not None:
            return value(argv)
        return ToolResult(name=argv[0], argv=argv, status="missing", missing=True, error="missing")

    return _run
