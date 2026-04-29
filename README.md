# scannie

`scannie` is a command-line first static triage scanner for PDF and EPUB files.
It fingerprints documents, runs available local tools, inspects risky PDF/EPUB
structure, and writes local report artifacts.

## Getting started from zero

From the repository root:

```bash
brew install uv just
cd scannie

uv sync
```

Now verify the CLI:

```bash
uv run scannie doctor
uv run python -m scannie doctor
```

If you see this error:

```text
No module named scannie
```

the package is not installed into the Python environment currently running the
command. Run commands through `uv run` from the repository root, or run
`uv sync` first and then activate the generated virtual environment with:

```bash
source .venv/bin/activate
```

After activation, `scannie doctor` and `python -m scannie doctor` will use the
project environment directly.

## Optional scanner tools

`scannie` can run without every external tool installed, but missing tools reduce
coverage. On macOS, install the recommended toolchain with:

```bash
brew install clamav yara qpdf exiftool jq ripgrep epubcheck
```

Then update ClamAV signatures:

```bash
freshclam
```

## Usage

Run a dependency check:

```bash
uv run scannie doctor
```

Scan a document:

```bash
uv run scannie scan suspicious.pdf --json
uv run scannie scan suspicious.epub --out ./reports
```

Optionally enrich a scan with an existing VirusTotal report by SHA-256 hash:

```bash
VT_API_KEY=... uv run scannie scan suspicious.pdf --vt
```

`--vt` performs a hash-only lookup against VirusTotal. It does not upload,
reanalyze, quarantine, or delete the file. The report will include
`virustotal-summary.txt` and, when VirusTotal returns a response body,
`virustotal.json`. VirusTotal reputation is an external signal: malicious
results can raise the verdict, suspicious results can raise it to review, and
clean or unknown results never downgrade local findings.

VirusTotal public API keys have quota and rate limits. Avoid uploading private
documents to public multi-scanner services; upload and Private Scanning
workflows are intentionally out of scope for `scannie` v1.

Optionally enrich PDF URLs with reputation checks:

```bash
GOOGLE_SAFE_BROWSING_API_KEY=... uv run scannie scan suspicious.pdf --url-reputation
```

`--url-reputation` extracts URLs from the PDF and sends them to configured
reputation providers. It does not fetch, render, or submit URLs for live browser
analysis. V1 uses Google Safe Browsing for bulk exact-URL checks and URLhaus for
malware URL/host reputation. The report will include `url-inventory.json`,
`url-reputation.json`, and `url-reputation-summary.txt`.

URLhaus checks are performed one URL/host request at a time under the configured
per-request timeout, so PDFs with many URLs can take a while at the default 500
URL cap.

VirusTotal URL lookups are intentionally not used for bulk URL reputation in v1:
public VT quota is too constrained for documents with many URLs. The existing
`--vt` flag remains a file-hash lookup only.

Run tests:

```bash
uv run pytest
```

## Code quality

Use the repo `justfile` for local, hook, and future CI quality tasks:

```bash
just check
just fix
just hooks-install
just hooks-run
```

`just check` runs Ruff format checks, Ruff lint checks, ty typechecking, and the
pytest suite. `just fix` applies safe Ruff lint fixes and formats the code.

Future CI can use the same task surface:

```bash
uv sync --locked
just check
```

External tools are detected and used when present. They are not installed
automatically.
