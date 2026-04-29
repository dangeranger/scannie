from __future__ import annotations

import zipfile
from pathlib import Path

import pytest


@pytest.fixture
def clean_pdf(tmp_path: Path) -> Path:
    path = tmp_path / "clean.pdf"
    path.write_bytes(b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n")
    return path


@pytest.fixture
def risky_pdf(tmp_path: Path) -> Path:
    path = tmp_path / "risky.pdf"
    path.write_bytes(
        b"%PDF-1.4\n"
        b"1 0 obj\n"
        b"<< /Type /Catalog /OpenAction 2 0 R >>\n"
        b"endobj\n"
        b"2 0 obj\n"
        b"<< /S /JavaScript /JS (app.alert('x')) >>\n"
        b"endobj\n%%EOF\n"
    )
    return path


@pytest.fixture
def clean_epub(tmp_path: Path) -> Path:
    path = tmp_path / "clean.epub"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("mimetype", "application/epub+zip")
        archive.writestr("META-INF/container.xml", "<container/>")
        archive.writestr("OEBPS/content.xhtml", "<html><body><p>Hello</p></body></html>")
    return path


@pytest.fixture
def risky_epub(tmp_path: Path) -> Path:
    path = tmp_path / "risky.epub"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("mimetype", "application/epub+zip")
        archive.writestr("OEBPS/content.xhtml", "<html><script>fetch('https://example.test')</script></html>")
    return path
