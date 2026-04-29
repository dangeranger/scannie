from __future__ import annotations

import subprocess

import pytest

from scannie.command import run_tool


def test_run_tool_captures_success(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(**kwargs):  # type: ignore[no-untyped-def]
        raise AssertionError("called with keyword-only")

    def fake_subprocess_run(argv, capture_output, text, timeout, check):  # type: ignore[no-untyped-def]
        assert argv == ["tool", "arg"]
        assert capture_output is True
        assert text is False
        assert timeout == 5
        assert check is False
        return subprocess.CompletedProcess(argv, 0, b"out", b"err")

    monkeypatch.setattr(subprocess, "run", fake_subprocess_run)
    result = run_tool(["tool", "arg"], timeout=5)
    assert result.status == "ok"
    assert result.stdout == "out"
    assert result.stderr == "err"


def test_run_tool_decodes_binary_output_with_replacement(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, b"ok\xff", b"bad\xfe"),
    )

    result = run_tool(["tool"])

    assert result.stdout == "ok\ufffd"
    assert result.stderr == "bad\ufffd"


def test_run_tool_captures_nonzero(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 7, b"bad", b"worse"),
    )
    result = run_tool(["tool"])
    assert result.status == "nonzero"
    assert result.returncode == 7


def test_run_tool_captures_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise FileNotFoundError("no tool")

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = run_tool(["missing-tool"])
    assert result.status == "missing"
    assert result.missing is True


def test_run_tool_captures_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise subprocess.TimeoutExpired(args[0], timeout=1, output=b"partial", stderr=b"late")

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = run_tool(["slow"], timeout=1)
    assert result.status == "timeout"
    assert result.timed_out is True
    assert result.stdout == "partial"
    assert result.stderr == "late"
