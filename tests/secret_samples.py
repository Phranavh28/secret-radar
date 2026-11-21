"""
Test secrets, assembled from fragments at runtime.

None of these are real or live. They are built by joining fragments so that
no complete, scannable secret literal is ever committed to the repository.
That keeps GitHub push protection (and this project's own scanner) from
flagging the test suite, while still giving the detectors a realistic,
contiguous string to match at runtime.
"""

# Each value is split so the full token never appears on one line in the repo.
AWS = "AKIA" + "IOSFODNN7" + "EXAMPLE"
GITHUB = "ghp_" + "ABCDEFGHIJKLMNOP" + "QRSTUVWXYZ0123456789"
STRIPE_LIVE = "sk_live_" + "51H8xQ2eZvKYlo2C" + "abcdefghIJKLmnop"
STRIPE_TEST = "sk_test_" + "51ABCdefGHIjklMN" + "Opqr STUvwx1234".replace(" ", "")
GOOGLE = "AIza" + "SyB1234567890abcdef" + "GHIJKLmnopqrstuv"
SLACK = "xoxb-" + "123456789012-" + "abcdefghijklmnop"
GOOGLE_OAUTH = "GOCSPX-" + "abcdefghijklmnop" + "qrstuvwxyz12"
GENERIC = "a1B2c3D4e5F6" + "g7H8i9J0" + "kLmNoPqRsTuV"

# A config file body with real looking secrets and safe values, built from
# the fragments above. Written to a temp file by the tests, never committed.
def config_file_body() -> str:
    return "\n".join([
        "# Generated fixture: real looking secrets plus safe values.",
        f'AWS_ACCESS_KEY_ID = "{AWS}"',
        f'GITHUB_TOKEN = "{GITHUB}"',
        f'STRIPE = "{STRIPE_LIVE}"',
        f'GOOGLE_MAPS = "{GOOGLE}"',
        '# Safe values that must NOT be flagged:',
        'API_KEY = "your-api-key-here"',
        'password = "changeme"',
        'timeout = "30"',
        'DATABASE_HOST = "localhost"',
        f'custom_token = "{GENERIC}"',
        "",
    ])


def postman_body() -> str:
    import json
    doc = {
        "info": {"name": "Demo API"},
        "item": [
            {"name": "Get user", "request": {"header": [
                {"key": "Authorization", "value": f"Bearer {STRIPE_TEST}"}]}},
            {"name": "Example", "request": {"header": [
                {"key": "x-api-key", "value": "<your_api_key>"}]}},
        ],
    }
    return json.dumps(doc, indent=2)
