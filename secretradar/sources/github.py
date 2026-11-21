"""
Scan PUBLIC GitHub repositories you are allowed to read.

The respectful way to scan GitHub is to clone a public repository locally and
run the filesystem scanner over it, including its history. This module shells
out to git, so it never needs a token and never touches anything private.

It does NOT crawl all of GitHub, and it does NOT use the code search API to
hunt across other people's code at scale. Point it at repositories you own,
or at a specific public repository you have a legitimate reason to review
(your own, your employer's, or one you are reviewing with permission).

History matters: a secret removed in a later commit still lives in the git
history and is still exposed, so scan_repo walks every committed blob.
"""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from ..scanner import FileResult, scan_text
from ..detectors import Finding


def _run(args: list[str], cwd: str | None = None) -> str:
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True, check=True).stdout


def scan_repo(repo_url_or_path: str, history: bool = True) -> list[FileResult]:
    """
    Clone (if a URL) and scan a public repo.

    history=True also scans every blob ever committed, so secrets that were
    'deleted' in a later commit are still found.
    """
    is_url = repo_url_or_path.startswith(("http://", "https://", "git@"))
    if is_url:
        tmp = tempfile.mkdtemp(prefix="secretradar-")
        _run(["git", "clone", "--quiet", repo_url_or_path, tmp])
        repo = Path(tmp)
    else:
        repo = Path(repo_url_or_path)

    from ..scanner import scan_path
    results = scan_path(repo)

    if history and (repo / ".git").exists():
        results.extend(_scan_history(repo))
    return results


def _scan_history(repo: Path) -> list[FileResult]:
    """Scan every blob in the git history for secrets that were later removed."""
    results: list[FileResult] = []
    blobs = _run(["git", "rev-list", "--objects", "--all"], cwd=str(repo)).splitlines()
    seen: set[str] = set()
    for line in blobs:
        parts = line.split(maxsplit=1)
        if len(parts) != 2:
            continue
        sha, name = parts
        if sha in seen:
            continue
        seen.add(sha)
        try:
            kind = _run(["git", "cat-file", "-t", sha], cwd=str(repo)).strip()
            if kind != "blob":
                continue
            content = _run(["git", "cat-file", "-p", sha], cwd=str(repo))
        except subprocess.CalledProcessError:
            continue
        findings: list[Finding] = scan_text(content)
        if findings:
            results.append(FileResult(path=f"[history] {name} @ {sha[:8]}", findings=findings))
    return results
