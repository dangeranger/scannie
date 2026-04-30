# Security Policy

## Supported Versions

`scannie` is currently pre-1.0 software maintained by a single maintainer. Security fixes are applied to the default branch and included in the next tagged release when releases are available.

## Reporting a Vulnerability

Please do not report suspected vulnerabilities in public issues.

Use GitHub private vulnerability reporting for this repository:

https://github.com/dangeranger/scannie/security/advisories/new

If private reporting is unavailable, open a minimal public issue asking for a private security contact without including exploit details, sample documents, credentials, API keys, or other sensitive data.

## Scope

Security reports are most useful when they involve behavior in `scannie` itself, including:

- unsafe file extraction or path traversal while inspecting EPUB files
- document handling that renders, executes, uploads, deletes, or quarantines files unexpectedly
- command execution or argument injection involving optional local scanner tools
- leakage of API keys, scanned document contents, hashes, URLs, or report artifacts
- incorrect handling of malicious PDF or EPUB structure that materially changes the verdict or report

Reports about optional third-party tools such as `qpdf`, `yara`, `clamav`, `exiftool`, `epubcheck`, VirusTotal, Google Safe Browsing, or URLhaus should generally be reported upstream unless `scannie` uses the tool unsafely.

## Response Expectations

For valid vulnerability reports, the maintainer will try to:

- acknowledge the report within 7 days
- provide an initial assessment within 14 days
- coordinate disclosure timing before public details are published

Timelines may vary because this is a small single-maintainer project.

## Disclosure

Please allow coordinated disclosure before publishing details. If a vulnerability is confirmed, the fix, release notes, and any advisory will describe impact and remediation once users have had a reasonable chance to update.
