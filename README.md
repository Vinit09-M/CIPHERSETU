# CipherSetu

**Find the cryptography in your codebase. Decide what to migrate first.**

An RSA reference in a payments service could be the public key that protects a customer’s data key, a signature check that authenticates a request, or a comment in an old example. Each calls for a different decision. CipherSetu gives application security teams and developers a shared starting point for post-quantum migration: the file, the line, the likely use, and a concrete next step.

**Research alpha** · Local dashboard · GitHub and ZIP scans · Optional GitHub Issues

[Run the sample](#run-the-sample) · [Scan your repository](#scan-your-repository) · [Try a migration](#try-a-migration) · [Set up issue tracking](#set-up-issue-tracking)

## Run the sample

With Git and Docker Compose installed, run this from a terminal.

~~~sh
git clone https://github.com/Vinit09-M/CIPHERSETU.git
cd CIPHERSETU
docker compose up --build
~~~

Open [the local dashboard](http://127.0.0.1:8000) and select **Try a sample scan**. You can explore the findings and export a JSON report before connecting a repository or configuring credentials.

<details>
<summary><strong>Run locally with Python instead</strong></summary>

From the cloned repository, use Python 3.12 to install the dependencies and start FastAPI.

**Windows PowerShell**

~~~powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
~~~

**macOS or Linux**

~~~sh
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
~~~

Open [the dashboard](http://127.0.0.1:8000) or explore the [local API documentation](http://127.0.0.1:8000/docs).

</details>

## Scan your repository

1. Enter a GitHub URL or `owner/repository`. Select a branch, simple tag, or commit SHA, or leave the ref at `HEAD`. For a private preview, supply a token with read-only Contents access. You can also upload a repository ZIP up to 10 MiB.
2. Select **Scan and preview only**. Open a finding and inspect the surrounding code. Severity helps prioritize review. An import or a public key alone cannot establish how an application uses it.
3. Export the JSON report for review, or enable issue tracking to put the findings in the developers’ queue. If the supported migration rule matches, **Preview patch** shows the proposed change and its validation status.

| What you find | What to check next |
| --- | --- |
| RSA wrapping a data key | Confirm which writer produces the record and which readers must remain compatible. |
| RSA used for signatures, tokens, certificates, or TLS | Identify the signing or protocol owner and review compatibility with its consumers. |
| A public key, import, or documentation reference | Trace the reference to an active call site before proposing a change. |

## Try a migration

The included demo answers a practical rollout question: **can we change how new records are protected and still read records written before the change?** With the [Go version specified by the module](migration/go.mod), run this from the repository root.

~~~sh
go -C migration run ./cmd/ciphersetu demo --dir demo-output
~~~

The CLI generates synthetic data and fresh keys, rewraps a data key, verifies the recovered data, and checks that a tampered record is rejected. Keep the generated keys outside version control.

The dashboard’s patch preview covers a specific RSA-OAEP data-key wrapper in the Testing-Crypto fixture, `apps/payments/wrap_key.py`. Its proposed writer uses **ML-KEM-768 + X25519** for new records. Its reader can open both formats with their matching keys. Validation generates fresh legacy records so it can exercise both read paths.

For dashboard validation on Windows, build the CLI from the repository root, then start the Python server **in the same shell**.

~~~powershell
$env:CIPHERSETU_CLI = Join-Path $env:TEMP 'ciphersetu-validation.exe'
go -C migration build -buildvcs=false -o "$env:CIPHERSETU_CLI" ./cmd/ciphersetu
~~~

For Docker validation, mount a trusted Linux build of the CLI into the container and set `CIPHERSETU_CLI` to its path inside the container. The standard Compose setup supports scanning, patch planning, and report export.

[CLI guide](migration/USAGE.md) · [Envelope format](migration/docs/FORMAT.md) · [Migration security notes](migration/SECURITY.md)

## Set up issue tracking

Tracking is **off by default**. Enable it when a team is ready to receive findings in its repository.

1. [Register a GitHub App](https://docs.github.com/en/apps/creating-github-apps/writing-code-for-a-github-app/quickstart) with **Contents — Read-only** and **Issues — Read and write**. Install it on the selected repository and enable Issues there.
2. Store the App’s PEM private key outside all checkouts. Before starting the server, set `CIPHERSETU_GITHUB_APP_ID` and `CIPHERSETU_GITHUB_APP_KEY_FILE` in its environment. The second value is the path to the PEM file. The app obtains a short-lived installation token for the selected repository.
3. In the dashboard, enable **Automatically track findings in GitHub Issues** and select **Start repository scan**.

Each tracked scan with findings opens a fresh issue, even for a previously scanned commit. The issue lists every finding with its path and line, criticality, impact, and suggested remediation. Large reports continue in comments on the same issue. The repository owner reviews the advice and approves changes through the team’s usual process.

## Scope and development

CipherSetu is a single-user, localhost research tool. Scan authorized code. Its text scanner covers the selected snapshot. Runtime behavior, dependency graphs, and Git history require separate review. Reports can contain repository paths and line numbers and are stored in `data/scans.db` by default. The migration CLI handles CipherSetu envelopes and requires matching keys. Its research key files are unencrypted.

To run the tests, activate the Python environment above and install the Go toolchain.

~~~sh
python -m pytest -q
go -C migration test ./...
~~~

The Python tests exercise the synthetic writer and reader with a temporary CLI and mock GitHub publication. The [Go CLI license](migration/LICENSE) applies to the migration module.
