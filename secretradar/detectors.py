"""
Secret detectors.

Each detector looks for one kind of credential. A detector either matches a
known provider key format (high confidence) or flags a high entropy string
that sits next to a secret looking keyword (lower confidence, more context
needed).

Design choices that matter for a real scanner:

  * Every finding carries a confidence level, so a reviewer triages the
    high confidence ones first.
  * Secrets are never stored or printed in full. The scanner keeps only a
    redacted preview and a SHA 256 fingerprint, so two copies of the same
    leaked key can be grouped without the plaintext ever leaving the host.
  * Detectors are data, not code: adding a provider is one entry in
    PROVIDER_PATTERNS, so the engine stays small and testable.
"""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass


# --------------------------------------------------------------------------
# Finding
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Finding:
    detector: str          # which detector fired, e.g. "AWS Access Key ID"
    confidence: str        # "high", "medium" or "low"
    preview: str           # redacted, safe to log and display
    fingerprint: str       # sha256 of the raw secret, for grouping and dedupe
    line: int              # 1 based line number within the scanned text
    column: int            # 1 based column where the match starts

    def as_dict(self) -> dict:
        return {
            "detector": self.detector,
            "confidence": self.confidence,
            "preview": self.preview,
            "fingerprint": self.fingerprint,
            "line": self.line,
            "column": self.column,
        }


# --------------------------------------------------------------------------
# Safety helpers: never emit a usable secret
# --------------------------------------------------------------------------

def fingerprint(secret: str) -> str:
    """A stable id for a secret that does not reveal it."""
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()[:16]


def redact(secret: str) -> str:
    """Show only enough to recognise a secret, never enough to use it."""
    if len(secret) <= 8:
        return secret[0] + "*" * (len(secret) - 1) if secret else ""
    return f"{secret[:4]}...{secret[-4:]} ({len(secret)} chars)"


def shannon_entropy(value: str) -> float:
    """Bits of entropy per character. Random looking secrets score high."""
    if not value:
        return 0.0
    counts = {c: value.count(c) for c in set(value)}
    length = len(value)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


# --------------------------------------------------------------------------
# Known provider key formats (high confidence)
# --------------------------------------------------------------------------
# Each entry: name -> compiled pattern. Patterns match the key shape only;
# we do not call any provider to check whether a key is live.

PROVIDER_PATTERNS: dict[str, re.Pattern] = {
    "AWS Access Key ID": re.compile(r"\b((?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[A-Z0-9]{16})\b"),
    "GitHub Token": re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,})\b"),
    "GitHub Fine Grained Token": re.compile(r"\b(github_pat_[A-Za-z0-9_]{70,})\b"),
    "Slack Token": re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b"),
    "Slack Webhook": re.compile(r"(https://hooks\.slack\.com/services/T[A-Za-z0-9/]{40,})"),
    "Google API Key": re.compile(r"\b(AIza[A-Za-z0-9_\-]{35})\b"),
    "Stripe Secret Key": re.compile(r"\b(sk_(?:live|test)_[A-Za-z0-9]{24,})\b"),
    "Stripe Restricted Key": re.compile(r"\b(rk_(?:live|test)_[A-Za-z0-9]{24,})\b"),
    "SendGrid API Key": re.compile(r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b"),
    "Twilio API Key": re.compile(r"\b(SK[a-f0-9]{32})\b"),
    "OpenAI API Key": re.compile(r"\b(sk-[A-Za-z0-9_\-]{20,})\b"),
    "Private Key Block": re.compile(r"(-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----)"),
    "JWT": re.compile(r"\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b"),
    "Google OAuth Client Secret": re.compile(r"\b(GOCSPX-[A-Za-z0-9_\-]{28})\b"),
}


# --------------------------------------------------------------------------
# Generic high entropy secrets near a keyword (medium / low confidence)
# --------------------------------------------------------------------------
# Catches keys that match no known format, e.g. a bespoke API token assigned
# to a key = "..." pair. We require both a secret looking keyword AND high
# entropy so ordinary config values do not flood the results.

_ASSIGNMENT = re.compile(
    r"""(?ix)
    (?P<key>[A-Za-z0-9_.\-]{0,40}
        (?:api[_\-]?key|secret|token|passwd|password|auth|credential|access[_\-]?key|private[_\-]?key)
        [A-Za-z0-9_.\-]{0,20})
    \s*[:=]\s*
    ['"]?(?P<value>[A-Za-z0-9+/_\-=.]{16,100})['"]?
    """
)

ENTROPY_HIGH = 4.0   # bits/char: clearly random, treat as medium confidence
ENTROPY_LOW = 3.3    # bits/char: possibly random, low confidence


# Values that look secret shaped but are not: placeholders and examples.
_PLACEHOLDER = re.compile(
    r"(?i)(your[_\-]?|example|placeholder|dummy|sample|changeme|xxxx+|000000|<[^>]+>|\.\.\.|redacted|insert[_\-]?)"
)


def _looks_like_placeholder(value: str) -> bool:
    if _PLACEHOLDER.search(value):
        return True
    # A single repeated character, or an obvious sequence, is not a real key.
    if len(set(value)) <= 3:
        return True
    return False


# --------------------------------------------------------------------------
# Engine
# --------------------------------------------------------------------------

def _locate(text: str, index: int) -> tuple[int, int]:
    """Turn a string offset into a 1 based line and column."""
    before = text[:index]
    line = before.count("\n") + 1
    column = index - (before.rfind("\n")) if "\n" in before else index + 1
    return line, column


def scan_text(text: str) -> list[Finding]:
    """Return every secret found in a block of text, de duplicated by position."""
    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()

    # 1. Known provider formats: high confidence.
    for name, pattern in PROVIDER_PATTERNS.items():
        for match in pattern.finditer(text):
            secret = match.group(1)
            key = (fingerprint(secret), match.start())
            if key in seen:
                continue
            seen.add(key)
            line, column = _locate(text, match.start(1))
            findings.append(Finding(name, "high", redact(secret),
                                    fingerprint(secret), line, column))

    # 2. Generic keyword + high entropy: medium or low confidence.
    for match in _ASSIGNMENT.finditer(text):
        value = match.group("value")
        if _looks_like_placeholder(value):
            continue
        entropy = shannon_entropy(value)
        if entropy < ENTROPY_LOW:
            continue
        key = (fingerprint(value), match.start("value"))
        if key in seen:
            continue
        seen.add(key)
        confidence = "medium" if entropy >= ENTROPY_HIGH else "low"
        line, column = _locate(text, match.start("value"))
        findings.append(Finding(
            f"Generic secret near '{match.group('key').strip()}'",
            confidence, redact(value), fingerprint(value), line, column))

    return findings
