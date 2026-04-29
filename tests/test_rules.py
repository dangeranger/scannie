from __future__ import annotations

from pathlib import Path

from scannie.rules import active_rules, packaged_rules_path


def test_packaged_pdf_rules_are_discoverable() -> None:
    path = packaged_rules_path("pdf")
    assert path.exists()
    text = path.read_text()
    assert "PDF_Risky_Actions" in text
    assert "EPUB_Risky_Web_Content" not in text


def test_packaged_epub_rules_are_discoverable() -> None:
    path = packaged_rules_path("epub")
    assert path.exists()
    text = path.read_text()
    assert "EPUB_Risky_Web_Content" in text
    assert "PDF_Risky_Actions" not in text


def test_custom_rules_supplement_packaged_rules(tmp_path: Path) -> None:
    custom = tmp_path / "custom.yar"
    custom.write_text("rule Empty { condition: true }\n")
    rules = active_rules("pdf", [custom])
    assert rules[0] == packaged_rules_path("pdf")
    assert rules[1] == custom
