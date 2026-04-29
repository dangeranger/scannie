"""Static PDF and EPUB document triage."""

from .models import ScanOptions, ScanResult
from .scanner import scan_document

__all__ = ["ScanOptions", "ScanResult", "scan_document"]
