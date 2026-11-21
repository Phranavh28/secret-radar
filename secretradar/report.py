"""
Turn scan results into output a human or a pipeline can act on.

Two formats:
  * a readable console summary, grouped by confidence, redacted
  * JSON, for a CI job or a disclosure tracker

Nothing here ever prints a full secret, and nothing here contacts any
provider to test a key. Verification is deliberately out of scope: using a
credential you found, even to check it, is unauthorised access.
"""

from __future__ import annotations

import json

from .scanner import FileResult

ORDER = {"high": 0, "medium": 1, "low": 2}


def summarise(results: list[FileResult]) -> dict:
    total = sum(len(r.findings) for r in results)
    by_conf: dict[str, int] = {"high": 0, "medium": 0, "low": 0}
    for r in results:
        for f in r.findings:
            by_conf[f.confidence] = by_conf.get(f.confidence, 0) + 1
    return {"files_with_findings": len(results), "total_findings": total,
            "by_confidence": by_conf}


def to_json(results: list[FileResult]) -> str:
    payload = {
        "summary": summarise(results),
        "files": [
            {"path": r.path,
             "findings": [f.as_dict() for f in sorted(r.findings, key=lambda x: ORDER[x.confidence])]}
            for r in results
        ],
    }
    return json.dumps(payload, indent=2)


def to_console(results: list[FileResult]) -> str:
    s = summarise(results)
    lines = [
        "Secret Radar scan",
        f"  files with findings: {s['files_with_findings']}",
        f"  total findings:      {s['total_findings']} "
        f"(high {s['by_confidence']['high']}, "
        f"medium {s['by_confidence']['medium']}, "
        f"low {s['by_confidence']['low']})",
        "",
    ]
    for r in results:
        lines.append(r.path)
        for f in sorted(r.findings, key=lambda x: ORDER[x.confidence]):
            tag = f.confidence.upper().ljust(6)
            lines.append(f"  [{tag}] L{f.line}:{f.column}  {f.detector}  {f.preview}")
        lines.append("")
    if not results:
        lines.append("No secrets found.")
    return "\n".join(lines)
