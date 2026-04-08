"""File and text scanning for agent-secrets-guard."""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO

from asg.detectors import Finding, DetectorRegistry

__all__ = ["ScanResult", "scan_file", "scan_stdin", "format_report"]


@dataclass
class ScanResult:
    path: str
    findings: list[Finding]


def scan_file(path: str | Path, registry: DetectorRegistry | None = None) -> ScanResult:
    """Scan a single file for secrets."""
    registry = registry or DetectorRegistry()
    path = Path(path)
    try:
        # Read as UTF-8, handle binary gracefully
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        raise OSError(f"Cannot read {path}: {e}") from e

    findings = registry.scan(raw)
    return ScanResult(path=str(path), findings=findings)


def scan_stdin(stdin: TextIO, registry: DetectorRegistry | None = None) -> ScanResult:
    """Scan stdin for secrets."""
    registry = registry or DetectorRegistry()
    findings = registry.scan(stdin.read())
    return ScanResult(path="<stdin>", findings=findings)


def _serialize_finding(f: Finding) -> dict:
    return {
        "label": f.label,
        "pattern": f.pattern,
        "start": f.start,
        "end": f.end,
        "line": f.line,
    }


def format_report(results: list[ScanResult], json_output: bool = False) -> str:
    """Format scan results for human or JSON output."""
    if json_output:
        out = {
            "files_scanned": len(results),
            "total_findings": sum(len(r.findings) for r in results),
            "results": [
                {"path": r.path, "findings": [_serialize_finding(f) for f in r.findings]}
                for r in results
            ],
        }
        return json.dumps(out, indent=2)

    lines: list[str] = []
    total = 0
    for result in results:
        if not result.findings:
            continue
        total += len(result.findings)
        lines.append(f"\n{result.path}:")
        for f in result.findings:
            lines.append(f"  [{f.line}] {f.label} ({f.pattern}) — bytes {f.start}:{f.end}")

    if not lines:
        return "No secrets found."

    header = f"\n{'='*50}\n  agent-secrets-guard scan report\n{'='*50}"
    return header + "\n" + "\n".join(lines) + f"\n\nTotal: {total} finding(s) in {len(results)} file(s)\n"


def redact_text(text: str, findings: list[Finding]) -> str:
    """Apply redaction to text, preserving positions."""
    # Sort descending to apply from end first (avoids offset drift)
    for f in sorted(findings, key=lambda x: (x.start, x.end), reverse=True):
        text = f.redact(text)
    return text
