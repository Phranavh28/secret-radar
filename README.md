# Secret Radar

Find exposed API keys, tokens and other secrets in files, git repositories and API exports (Postman, SwaggerHub) before an attacker does.

Secret Radar **detects and reports** secrets. It never uses a key it finds, and it never contacts a provider to test whether a key is live. That line is deliberate (see [Responsible use](#responsible-use)).

## What it does

- Detects **known provider key formats** with high confidence: AWS, GitHub, Google, Stripe, Slack, SendGrid, Twilio, OpenAI, JWTs, private key blocks and more.
- Detects **unknown secrets** by combining a secret looking keyword (`api_key`, `token`, `secret`) with a high entropy value, so bespoke tokens are caught too.
- **Filters false positives:** placeholders, examples and low entropy values (`your-api-key-here`, `changeme`, `xxxx`) are ignored.
- **Scans git history,** so a secret that was committed and later "removed" is still found, because it still lives in the history.
- **Redacts everything:** findings show only a short preview and a SHA 256 fingerprint. The full secret never appears in output or logs.
- **Fits a pipeline:** a pre commit hook or CI job that exits non zero stops a leak at the source.

## Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt   # standard library only; pytest for tests
```

## Use

```bash
# Scan a folder (a cloned repo, a project, a downloads folder)
python -m secretradar scan ./my-project

# Scan a Postman or SwaggerHub export, walking the JSON structure
python -m secretradar scan collection.json --json-aware

# Machine readable output for a tracker or dashboard
python -m secretradar scan ./my-project --json

# Fail a build if any HIGH confidence secret is present
python -m secretradar scan . --fail-on high
```

Scan a public GitHub repository, including its history:

```python
from secretradar.sources import scan_repo
from secretradar import to_console

results = scan_repo("https://github.com/you/your-repo", history=True)
print(to_console(results))
```

## How to use it against Postman, SwaggerHub and GitHub, the right way

| Source | The respectful route |
| --- | --- |
| **Your own repos** | Scan them directly, history included. Fix what you find. |
| **Public GitHub repos** | Clone the specific public repo you have a reason to review, then scan it locally. Do not crawl all of GitHub or mass harvest with the code search API. |
| **Postman** | Export your own workspace, or a public collection, to JSON and scan it with `--json-aware`. |
| **SwaggerHub** | Download the public API definition (JSON or YAML) and scan the file. |

## Responsible use

This tool exists to **reduce** exposure, not to exploit it.

- **Never use a key you find.** Using a credential you discovered, even once, even just to check it works, is unauthorised access to a computer system and is an offence (in Australia, under the Commonwealth Criminal Code; similar laws apply elsewhere).
- **Scan what you are allowed to read:** your own code and accounts, your employer's with permission, or public data you review for a legitimate reason.
- **If you find someone else's exposed secret, report it, do not touch it.** Most providers have a process:
  - AWS: the key owner should be told to deactivate it; AWS also auto quarantines keys it detects in public repos.
  - GitHub: push protection and secret scanning partners can be notified; you can open a private report to the repo owner.
  - Stripe, Google, Slack and others have abuse or security contacts.
- **Handle findings carefully.** The redacted preview and fingerprint are safe to share; never paste a full secret into a ticket, a chat or a screenshot.

Verification (checking whether a found key is live) is intentionally **not** built in, because doing it to a key that is not yours crosses the line above.

## Repo layout

```
secretradar/detectors.py     patterns, entropy, redaction, the scan engine
secretradar/scanner.py       scan files, folders and JSON exports
secretradar/report.py        console and JSON output (always redacted)
secretradar/cli.py           command line entry point
secretradar/sources/github.py  clone and scan a public repo, history included
tests/                       22 tests: real secrets caught, placeholders ignored, output redacted
```

## Roadmap

See [ROADMAP.md](ROADMAP.md): more providers, YAML and env file support, a SwaggerHub and Postman public API connector that respects rate limits, a verification stage that is **safe by design** (it only confirms a key's format and provider, never calls the provider), and an ATT&CK mapping to T1552 Unsecured Credentials.

## Author

Phranavh Sivaraman · [LinkedIn](https://linkedin.com/in/phranavhsivaraman) · [Portfolio](https://phranavh.vercel.app)
