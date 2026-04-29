# AGENTS.md

## Project

`scannie` is a Python CLI for static PDF and EPUB triage. It fingerprints files,
runs local scanner/inspection tools, records raw artifacts, and writes concise
analyst-facing summaries.

Get to the point. Keep changes pragmatic and well tested.

## Setup and Commands

Use `uv`; do not add `pip`-based setup instructions.

```bash
uv sync
uv run pytest
uv run scannie doctor
uv run scannie scan path/to/document.pdf --json
```

External tools are optional at runtime and are detected by `scannie doctor`.
Do not auto-install Homebrew packages from application code.

## Architecture

- `src/scannie/cli.py`: argument parsing, exit codes, and terminal output only.
- `src/scannie/scanner.py`: common scan orchestration and external tool recording.
- `src/scannie/pdf.py`: PDF-specific static analysis.
- `src/scannie/epub.py`: EPUB-specific static analysis and safe extraction.
- `src/scannie/report.py`: report directory writing and derived summary artifacts.
- `src/scannie/explain.py`: shared human-readable verdict explanation formatting.
- `src/scannie/models.py`: serializable result, finding, tool, and artifact models.

Keep scanner logic reusable through `scan_document(path, options) -> ScanResult`.
Future web upload/drop flows should call the scanner core instead of duplicating
CLI behavior.

## Testing

Use red/green/refactor TDD for behavior changes:

1. Add or update a focused failing test.
2. Implement the smallest change that passes.
3. Refactor while keeping `uv run pytest` green.

Prefer mocked subprocess runners in tests. Do not make tests require local
installations of `qpdf`, `clamav`, `yara`, `epubcheck`, or other scanner tools.

## Report Output Rules

Preserve raw artifacts for automation and deeper analysis. Add derived summaries
beside raw files rather than deleting or renaming raw artifacts.

Important report files include:

- `summary.json`: machine-readable scan result.
- `summary.txt`: analyst-readable result using shared explanation formatting.
- `artifact-index.txt`: artifact purpose, role, and size.
- `tool-status.txt`: concise external tool status.
- `yara-summary.txt`: packaged heuristic versus custom rule matches.
- PDF reports: `pdf-structure-summary.txt`, `pdf-risk-summary.txt`,
  `pdf-url-summary.txt`.

For CLI text output, keep `Verdict:` and `Report:` first, then include the
bounded explanation sections: `Why this verdict`, `Tool status`, and
`Start here`. Keep `--json` output pure JSON.

## Verdict Semantics

- ClamAV detections are `high`.
- Custom `--rules` YARA matches are `high`.
- Packaged `doc-risk.yar` matches are heuristic indicators and should be
  `review`, not malware detections.
- qPDF output saying “no embedded files” or “no attachments” must not create an
  embedded-file finding.
- Missing optional tools should be recorded without failing an otherwise useful
  scan.

## Safety and Scope

Do not render, open, execute, or upload scanned documents. V1 is static triage
only. Do not add VirusTotal uploads, quarantine/delete actions, Docker/VM
orchestration, or a web UI unless explicitly requested.

Do not commit generated scan outputs, virtual environments, caches, or
`triage-*` directories.
