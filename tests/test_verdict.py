from __future__ import annotations

import pytest

from scannie.models import Finding
from scannie.verdict import calculate_verdict


@pytest.mark.parametrize(
    ("findings", "expected"),
    [
        ([], "low"),
        ([Finding("review", "cat", "msg")], "review"),
        ([Finding("high", "cat", "msg"), Finding("review", "cat", "msg")], "high"),
        ([Finding("error", "cat", "msg"), Finding("high", "cat", "msg")], "error"),
    ],
)
def test_calculate_verdict(findings: list[Finding], expected: str) -> None:
    assert calculate_verdict(findings) == expected
