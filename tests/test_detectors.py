from pathlib import Path

import pytest

from secretradar import (fingerprint, scan_json_values, scan_path, scan_text,
                         shannon_entropy)
from tests import secret_samples as S

FIXTURES = Path(__file__).parent / "fixtures"


# --------------------------------------------------------------------------
# Provider formats: must be caught
# --------------------------------------------------------------------------

@pytest.mark.parametrize("secret, detector", [
    (S.AWS, "AWS Access Key ID"),
    (S.GITHUB, "GitHub Token"),
    (S.STRIPE_LIVE, "Stripe Secret Key"),
    (S.GOOGLE, "Google API Key"),
    (S.SLACK, "Slack Token"),
    (S.GOOGLE_OAUTH, "Google OAuth Client Secret"),
])
def test_provider_secret_detected(secret, detector):
    findings = scan_text(f"token = {secret}")
    assert any(f.detector == detector and f.confidence == "high" for f in findings), \
        f"{detector} not detected"


def test_private_key_block_detected():
    header = "-----BEGIN " + "RSA PRIVATE KEY" + "-----"
    text = header + "\nMIIEpAIBAAKCAQEA...\n"
    findings = scan_text(text)
    assert any(f.detector == "Private Key Block" for f in findings)


# --------------------------------------------------------------------------
# False positives: must NOT be caught
# --------------------------------------------------------------------------

@pytest.mark.parametrize("value", [
    'API_KEY = "your-api-key-here"',
    'password = "changeme"',
    'token = "<insert_token_here>"',
    'secret = "xxxxxxxxxxxxxxxx"',
    'timeout = "30"',
    'host = "localhost"',
    'example_key = "EXAMPLE_PLACEHOLDER_VALUE"',
])
def test_placeholders_not_flagged(value):
    assert scan_text(value) == [], f"False positive on: {value}"


def test_low_entropy_not_flagged():
    assert scan_text('api_key = "aaaaaaaaaaaaaaaaaaaaaaaa"') == []


# --------------------------------------------------------------------------
# Generic high entropy secrets near a keyword
# --------------------------------------------------------------------------

def test_generic_high_entropy_secret_flagged():
    findings = scan_text(f'custom_api_key = "{S.GENERIC}"')
    assert findings
    assert findings[0].confidence in {"medium", "low"}


# --------------------------------------------------------------------------
# Safety: output never reveals a usable secret
# --------------------------------------------------------------------------

def test_preview_is_redacted():
    findings = scan_text(f"key = {S.AWS}")
    for f in findings:
        assert S.AWS not in f.preview
        assert "..." in f.preview or "*" in f.preview


def test_fingerprint_is_stable_and_not_the_secret():
    fp = fingerprint(S.GITHUB)
    assert fp == fingerprint(S.GITHUB)
    assert S.GITHUB not in fp
    assert len(fp) == 16


def test_entropy_ranking():
    assert shannon_entropy("aaaaaaaa") < shannon_entropy("aB3$xY9!")


# --------------------------------------------------------------------------
# Scanning files and folders (fixtures written at runtime, never committed)
# --------------------------------------------------------------------------

def test_scan_config_file_finds_real_and_skips_placeholders(tmp_path):
    config = tmp_path / "sample_config.py"
    config.write_text(S.config_file_body(), encoding="utf-8")
    results = scan_path(config)
    detectors = {f.detector for r in results for f in r.findings}
    assert "AWS Access Key ID" in detectors
    assert "GitHub Token" in detectors
    assert "Stripe Secret Key" in detectors
    previews = [f.preview for r in results for f in r.findings]
    assert all("your-api-key-here" not in p for p in previews)


def test_scan_clean_file_finds_nothing():
    assert scan_path(FIXTURES / "clean.txt") == []


def test_json_aware_scan_of_postman_export(tmp_path):
    export = tmp_path / "collection.json"
    export.write_text(S.postman_body(), encoding="utf-8")
    fr = scan_json_values(export)
    detectors = {f.detector for f in fr.findings}
    assert "Stripe Secret Key" in detectors
    assert all("your_api_key" not in f.preview for f in fr.findings)
