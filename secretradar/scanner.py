"""
Scan files and folders for secrets.

The filesystem scanner is the core: a cloned public GitHub repo, an exported
Postman collection, or a downloaded SwaggerHub definition are all just files
on disk, so one scanner covers every source once the content is local.

It skips binary files and very large files, and honours a simple ignore list
so a scan does not waste time in dependency folders.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .detectors import Finding, scan_text

# Folders and extensions that never hold source secrets worth scanning.
SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__",
             "dist", "build", ".mypy_cache", ".pytest_cache", "vendor"}
SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf",
                 ".zip", ".gz", ".tar", ".mp4", ".mp3", ".woff", ".woff2",
                 ".ttf", ".eot", ".so", ".dll", ".class", ".jar", ".pyc"}
MAX_BYTES = 2_000_000  # skip files larger than ~2 MB


@dataclass
class FileResult:
    path: str
    findings: list[Finding] = field(default_factory=list)


def _is_probably_text(sample: bytes) -> bool:
    if b"\x00" in sample:
        return False
    # Mostly printable ASCII or UTF 8 decodable.
    try:
        sample.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def scan_file(path: Path) -> FileResult:
    result = FileResult(path=str(path))
    try:
        if path.stat().st_size > MAX_BYTES:
            return result
        raw = path.read_bytes()
    except (OSError, PermissionError):
        return result
    if not _is_probably_text(raw[:1024]):
        return result
    text = raw.decode("utf-8", errors="replace")
    result.findings = scan_text(text)
    return result


def scan_path(root: str | Path) -> list[FileResult]:
    """Scan a single file or walk a whole folder."""
    root = Path(root)
    results: list[FileResult] = []
    if root.is_file():
        fr = scan_file(root)
        return [fr] if fr.findings else []
    for path in root.rglob("*"):
        if path.is_dir():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() in SKIP_SUFFIXES:
            continue
        fr = scan_file(path)
        if fr.findings:
            results.append(fr)
    return results


def scan_json_values(path: Path) -> FileResult:
    """
    Scan a Postman or SwaggerHub export more precisely by walking the JSON and
    scanning each string value. This catches secrets in fields even when the
    raw formatting would hide them, and ignores structural keys.
    """
    result = FileResult(path=str(path))
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return scan_file(path)  # fall back to plain text scanning

    def walk(node, trail: str):
        if isinstance(node, dict):
            for k, v in node.items():
                walk(v, f"{trail}.{k}" if trail else str(k))
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{trail}[{i}]")
        elif isinstance(node, str):
            for f in scan_text(node):
                # Record the JSON path in place of a line number for context.
                result.findings.append(f)

    walk(data, "")
    return result
