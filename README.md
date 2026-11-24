# CipherSetu

**Find cryptography in source code, prioritize what needs review, and give developers a concrete migration starting point.**

![Research alpha](https://img.shields.io/badge/status-research%20alpha-157861)
![Python 3.12](https://img.shields.io/badge/Python-3.12-2F5D7B)
![Go 1.27](https://img.shields.io/badge/Go-1.27-16798A)
![Local-first](https://img.shields.io/badge/runtime-localhost-333B40)

[Quick start](#quick-start) · [GitHub Issues](#optional-github-issue-tracking) · [Migration demo](#try-the-migration-demo) · [Development](#development)

## What CipherSetu does

| Discover | Prioritize | Hand off |
| --- | --- | --- |
| Scan a GitHub commit, repository ZIP, or built-in demo for cryptographic identifiers. | Inspect file and line references, triage scores, likely use, and suggested next steps. | Export a JSON report or open a GitHub issue with all findings for a developer to review. |

The Go CLI demonstrates authenticated migration for CipherSetu envelopes. An optional patch preview validates one synthetic RSA-OAEP wrapping pattern. The proposed writer uses **ML-KEM-768 + X25519** for new records, while the dual reader continues to open legacy records.

## Quick start

### Docker

~~~bash
git clone https://github.com/Vinit09-M/CIPHERSETU.git
cd CIPHERSETU
docker compose up --build
~~~

Open [http://127.0.0.1:8000](http://127.0.0.1:8000) and select **Try a sample scan**. The Docker image includes scanning, patch planning, and report export. Patch validation in Docker requires a trusted Linux CipherSetu CLI mounted into the container with CIPHERSETU_CLI set to its in-container path.

### Python 3.12

From the cloned repository on Windows:

~~~powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
~~~

On macOS or Linux:

~~~bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
~~~

### Your first repository scan

1. Enter a GitHub URL or owner/repository and a branch, simple tag, or commit SHA. The default is HEAD. For a private preview, use the optional read-only Contents token.
2. Choose **Scan and preview only** to keep the result local. Alternatively, upload a repository ZIP up to 10 MiB.
3. Review the findings and coverage, then download the JSON report or reopen the scan from history. Where a supported rule matches, **Preview patch** shows the proposed code and validation results.

## Optional GitHub issue tracking

Issue tracking is off by default. To enable it on a repository you administer:

1. [Register and install a GitHub App](https://docs.github.com/en/apps/creating-github-apps/writing-code-for-a-github-app/quickstart). Give it **Contents: Read-only** and **Issues: Read and write**. Limit the installation to the intended repository and enable GitHub Issues there.
2. Download the App's PEM private key. Store it outside all Git checkouts. Set CIPHERSETU_GITHUB_APP_ID and CIPHERSETU_GITHUB_APP_KEY_FILE before starting the server. CipherSetu obtains a short-lived installation token scoped to the scanned repository.
3. Enable **Automatically track findings in GitHub Issues** in the dashboard and choose **Start repository scan**. Each tracked GitHub scan with findings creates a new issue, including repeat scans of the same commit.

Issues list every finding with its file and line, criticality, impact, and suggested remediation. Large reports continue in comments on the same issue. Developers assign ownership and submit code changes through their usual review process.

## Try the migration demo

Use the [Go toolchain required by the module](migration/go.mod) and synthetic data:

~~~bash
go -C migration run ./cmd/ciphersetu demo --dir demo-output
~~~

The demo creates a new legacy envelope and matching temporary keys, rewraps its data key, checks recovered plaintext against the original, and rejects a tampered copy. The original file remains available to the legacy key. Previously obtained legacy copies retain their original exposure.

For dashboard patch validation, build the CLI and set CIPHERSETU_CLI to the executable path before starting the Python server. For example, in PowerShell:

~~~powershell
$env:CIPHERSETU_CLI = Join-Path $env:TEMP 'ciphersetu-validation.exe'
go -C migration build -buildvcs=false -o "$env:CIPHERSETU_CLI" ./cmd/ciphersetu
~~~

The rule recognizes the exact synthetic wrapper at apps/payments/wrap_key.py. It validates hybrid writes, reads of fresh legacy and hybrid records, and tamper rejection. Use fresh synthetic fixtures for migration tests. Previously archived files require their original matching keys and compatible readers.

See the [CLI guide](migration/USAGE.md), [envelope format](migration/docs/FORMAT.md), and [migration security notes](migration/SECURITY.md).

## Scope and interpretation

- **Research alpha for one local user.** Run on localhost with synthetic or authorized input. Start with a non-production repository.
- **Triage scores describe review priority.** An identifier match can be an import, a policy entry, a public key reference, or active code. The scanner evaluates text and excludes runtime use, dependency graphs, and Git history from its coverage.
- **The migration CLI supports CipherSetu envelopes.** It requires matching keys. Its research key files are unencrypted and belong outside source control.
- **Reports can contain paths and line numbers.** SQLite stores reports under data/scans.db by default. Repository source and keys stay out of the reports.

## Development

~~~bash
python -m pytest -q
go -C migration test ./...
~~~

The Python suite builds a temporary Go CLI, exercises the synthetic writer and reader, and mocks GitHub API calls. [API reference](http://127.0.0.1:8000/docs) · [Go CLI license](migration/LICENSE)
