# Roadmap

Each stage adds real capability and real engineering skill. Build one stage to the finish before starting the next.

## Stage 1: Core engine (done)

- [x] Provider patterns, entropy detection, false positive filtering
- [x] File, folder and JSON aware scanning
- [x] Git history scanning
- [x] Redaction and fingerprinting (no plaintext secret ever leaves the host)
- [x] CLI with `--json` and `--fail-on`
- [x] 22 tests

## Stage 2: Hardening and coverage

- [ ] Add 15 more provider patterns (Azure, GitLab, npm, PyPI, Mailgun, Datadog, Cloudflare, Terraform Cloud, Postgres and MongoDB connection strings)
- [ ] Support YAML, `.env`, `.ini` and `.properties` files in the JSON aware walker
- [ ] A per rule test fixture, like the detection-as-code repo: each provider needs a real looking positive and a placeholder negative
- [ ] An allow list file so a project can mark known safe values

## Stage 3: Pre commit and CI

- [ ] Publish the pre commit hook (already in `.pre-commit-hooks.yaml`)
- [ ] GitHub Action that scans every push and comments on the pull request
- [ ] A baseline file so an existing repo can adopt the tool without failing on old findings

## Stage 4: Respectful source connectors

- [ ] Postman: read a collection by its public URL through the official API, with your own API key and rate limiting
- [ ] SwaggerHub: pull a public API definition through the registry API
- [ ] GitHub: watch the public events stream for newly pushed public repos, clone and scan each, and queue likely findings for responsible disclosure. Never store or use a secret; store only the fingerprint, the location and the provider.

## Stage 5: Safe verification and disclosure

- [ ] A verification stage that confirms only the format and the provider of a finding, and never calls the provider with the key
- [ ] A disclosure tracker: for each confirmed external leak, record the repo, the provider and the status (notified, rotated, closed), using fingerprints only
- [ ] Templates for responsible disclosure messages to repo owners and providers

## Stage 6: Reporting and portfolio

- [ ] Map findings to MITRE ATT&CK T1552.001 Credentials In Files
- [ ] An HTML report with the summary and redacted findings
- [ ] A blog post on phranavh.vercel.app: "Why deleting a secret from your latest commit does not remove it"
- [ ] Add the project to your resume with real numbers (providers covered, tests, repos scanned)
