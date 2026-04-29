from __future__ import annotations

from .models import (
    SEVERITY_ERROR,
    SEVERITY_HIGH,
    SEVERITY_REVIEW,
    VERDICT_ERROR,
    VERDICT_HIGH,
    VERDICT_LOW,
    VERDICT_REVIEW,
    Finding,
)


def calculate_verdict(findings: list[Finding]) -> str:
    severities = {finding.severity for finding in findings}
    if SEVERITY_ERROR in severities:
        return VERDICT_ERROR
    if SEVERITY_HIGH in severities:
        return VERDICT_HIGH
    if SEVERITY_REVIEW in severities:
        return VERDICT_REVIEW
    return VERDICT_LOW
