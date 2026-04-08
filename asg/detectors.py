"""Secret pattern detectors for agent-secrets-guard."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Re-export dataclasses
__all__ = ["Finding", "DetectorRegistry", "detect"]

# Compiled patterns (flag: ASCII for cross-platform safety)
_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    (
        "AWS Access Key ID",
        re.compile(r"\bAKIA[A-Z0-9]{16}\b", re.ASCII),
        "AWS Access Key ID (AKIA...)",
    ),
    (
        "GitHub Token",
        re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}", re.ASCII),
        "GitHub personal access / workflow token",
    ),
    (
        "Slack Token",
        re.compile(r"xox[baprs]-[a-zA-Z0-9]{10,}-[a-zA-Z0-9]{10,}-[a-zA-Z0-9]{24,}", re.ASCII),
        "Slack bot/user token",
    ),
    (
        "Generic Bearer Token",
        re.compile(r"Bearer\s+[A-Za-z0-9\-_~.+:/=?@]{20,}", re.ASCII | re.IGNORECASE),
        "Authorization: Bearer token",
    ),
    (
        "Generic API Key (Bearer pattern)",
        re.compile(r"api[_-]?key\s*[:=]\s*['\"]?[A-Za-z0-9\-_~.+:/=?@]{20,}", re.ASCII | re.IGNORECASE),
        "api_key / api-key credential",
    ),
    (
        "JWT Token",
        re.compile(r"eyJ[A-Za-z0-9_=-]{20,}\.eyJ[A-Za-z0-9_=-]{10,}\.[A-Za-z0-9_=-]{10,}", re.ASCII),
        "JSON Web Token",
    ),
    (
        "PEM Private Key",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----", re.ASCII),
        "PEM-encoded private key block",
    ),
    (
        ".env key=value secret",
        re.compile(r"(?:password|secret|token|api_key|api-key|auth|credential)\s*[:=]\s*['\"]?[A-Za-z0-9\-_~.+:/=?@]{8,}", re.ASCII | re.IGNORECASE),
        ".env-style secret assignment",
    ),
    (
        "Generic Secret Word",
        re.compile(r"(?:secret|password|token|api_key|apikey)\s*[:=]\s*['\"]?[A-Za-z0-9\-_~.+:/=?@]{10,}", re.ASCII | re.IGNORECASE),
        "Hardcoded secret / password",
    ),
    (
        "Discord Bot Token",
        re.compile(r"[A-Z][A-Za-z\d]{22}\.[A-Za-z\d]{6}\.[A-Za-z\d]{25,}", re.ASCII),
        "Discord bot token",
    ),
    (
        "NuGet API Key",
        re.compile(r"oye[a-z0-9]{16,32}", re.ASCII),
        "NuGet API key (oyez pattern)",
    ),
]

# Sentinel for "no end marker" sentinel
_NO_END = object()


@dataclass
class Finding:
    """A detected secret."""

    label: str
    pattern: str
    start: int  # byte offset in original text
    end: int    # byte offset (exclusive)
    line: int   # 1-based line number

    def redact(self, text: str, preserve_length: bool = False) -> str:
        """Return text with this finding replaced."""
        span = text[self.start:self.end]
        if preserve_length:
            return text[:self.start] + span[0] + "*" * (len(span) - 1) + text[self.end:]
        return text[:self.start] + "***REDACTED***" + text[self.end:]


@dataclass
class DetectorRegistry:
    """Collection of compiled patterns."""

    patterns: list[tuple[str, re.Pattern, str]] = field(default_factory=lambda: _PATTERNS)

    def scan(self, text: str) -> list[Finding]:
        """Scan text for all matching secrets, deduplicated by span."""
        findings: list[Finding] = []
        seen: set[tuple[int, int]] = set()

        for label, regex, description in self.patterns:
            for m in regex.finditer(text):
                key = (m.start(), m.end())
                if key in seen:
                    continue
                seen.add(key)
                # Compute line number
                line = text.count("\n", 0, m.start()) + 1
                findings.append(
                    Finding(
                        label=label,
                        pattern=description,
                        start=m.start(),
                        end=m.end(),
                        line=line,
                    )
                )

        # Sort by position
        findings.sort(key=lambda f: f.start)
        return findings


# Default singleton
_registry = DetectorRegistry()


def detect(text: str) -> list[Finding]:
    """Scan text for secrets (convenience function)."""
    return _registry.scan(text)