from __future__ import annotations

import json

from scannie.models import Artifact, Finding, ScanResult, ToolResult


def test_models_serialize_to_json() -> None:
    result = ScanResult(
        input_path="/tmp/doc.pdf",
        file_name="doc.pdf",
        verdict="review",
        file_type="pdf",
        sha256="abc",
        size_bytes=3,
        findings=[Finding("review", "pdf-risk", "has active content")],
        tools=[ToolResult("file", ["file", "/tmp/doc.pdf"], "ok", returncode=0)],
        artifacts=[Artifact("file", "file.txt", "PDF document")],
    )

    payload = result.to_dict()
    assert payload["verdict"] == "review"
    assert payload["findings"][0]["category"] == "pdf-risk"
    assert payload["tools"][0]["stdout_artifact"] is None
    assert payload["artifacts"][0]["path"] == "file.txt"
    json.dumps(payload)
