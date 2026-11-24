# CipherSetu
### Move encrypted data toward quantum resilience.

**v0.2.0-alpha — a separate open-source research project.**

CipherSetu migrates its own RSA-protected file envelopes to hybrid post-quantum
key protection. It verifies the recovered content before publishing a new copy.
No account, API key, network service, Docker, or CipherHarbor installation is needed.

## Start here: Windows PowerShell

Extract the ZIP into a folder you own, open PowerShell in `CipherSetu`, and run:

```powershell
.\bin\ciphersetu-windows-amd64.exe demo --dir demo-output
```

Expected: JSON with `"status": "PASS"`, `"migration_verified": true`,
`"old_key_rejected_for_new_envelope": true`, and `"tampered_copy_rejected": true`.

Then inspect and verify the migrated file:

```powershell
.\bin\ciphersetu-windows-amd64.exe inspect --in demo-output\migrated.aegis
.\bin\ciphersetu-windows-amd64.exe verify --in demo-output\migrated.aegis --private demo-output\hybrid-keys\private.json --original demo-output\sample.txt
Get-Content demo-output\report.json
```

Use a new directory name (for example `demo-output-2`) to run the demo again.
CipherSetu refuses to overwrite existing files or demo directories.
Unsigned alpha executables can trigger operating-system warnings; use your organization's
normal software review process or build the source yourself. Do not disable security controls.

## What the demo does

1. Creates synthetic text and two key pairs locally.
2. Encrypts the text with AES-256-GCM and protects its random data key with RSA-3072-OAEP-SHA256.
3. Recovers the data key using the old private key.
4. Protects that key using HPKE with ML-KEM-768 + X25519, HKDF-SHA256, and AES-256-GCM.
5. Decrypts the migrated envelope and compares the plaintext byte for byte.
6. Saves a new envelope; preserves the original encrypted file.
7. Demonstrates rejection of the old key for the new envelope and of a tampered copy.

**Important:** rejecting the old key for the new envelope does NOT revoke its access
to the old envelope. Existing copies still carry their old exposure.

## Output files

| File | Meaning |
|---|---|
| `sample.txt` | Synthetic original |
| `legacy.aegis` | AES-256 data with RSA-protected data key |
| `migrated.aegis` | Same ciphertext with hybrid-protected data key |
| `recovered.txt` | Successfully recovered original content |
| `report.json` | Demo results, without keys or plaintext |
| `legacy-keys/` and `hybrid-keys/` | Generated local public and private keys |

**Private keys are unencrypted in this research alpha. Use synthetic data only.**
POSIX permissions are restricted, but Windows access depends on your folder's ACLs.
The demo stores keys beside data for learning, not production custody.

## Linux and macOS

```sh
# Linux x86-64
chmod +x bin/ciphersetu-linux-amd64
./bin/ciphersetu-linux-amd64 demo --dir demo-output

# macOS Apple Silicon
chmod +x bin/ciphersetu-darwin-arm64
./bin/ciphersetu-darwin-arm64 demo --dir demo-output
```

Windows x86-64 and macOS ARM64 binaries are cross-compiled; this release's runtime
validation was performed on Linux x86-64. Other platforms can build from source.

## Use individual commands

See [USAGE.md](USAGE.md) for a complete manual migration, decryption, and CI example.
Run the executable with `help` for a concise command reference.

## Scope and limits

- Only CipherSetu v1 envelopes; not arbitrary encrypted ZIPs, OpenPGP files, database dumps,
  cloud-KMS ciphertexts, or vendor backups. File extensions do not determine compatibility.
- Maximum plaintext **16 MiB per file**; whole-file processing in memory, no streaming.
- Uses Go's standard crypto implementations, not a new encryption algorithm.
- ML-KEM is standardized. The Go hybrid HPKE KEM is documented against
  `draft-ietf-hpke-pq`; the application envelope is our versioned research format.
  This release is not independently audited, certified, or a production-ready migration system.
- Rewrapping keeps the same data key and data ciphertext. It does not repair prior key
  compromise or protect old copies already collected by an attacker.
- No signatures or sender authentication, rollback prevention, KMS/HSM, passwords,
  encrypted private-key storage, automated key deletion, multi-recipient access, or cloud integration.
- Original copies are never automatically deleted. Plan retention and backup retirement separately.

## Build and test

Requires Go 1.27.x; release tested and built with Go 1.27.3. No third-party modules.

```sh
go build -buildvcs=false -trimpath -o ciphersetu ./cmd/ciphersetu
go test -race ./...
go vet ./...
go test ./internal/envelope -run '^$' -fuzz FuzzParseEnvelope -fuzztime=10s
```

On Windows, use `go build -buildvcs=false -trimpath -o ciphersetu.exe ./cmd/ciphersetu`.
The normal tests work without CGO; the race detector requires supported CGO tooling.

Read [SECURITY.md](SECURITY.md), [docs/FORMAT.md](docs/FORMAT.md),
[docs/ROADMAP.md](docs/ROADMAP.md), and [docs/VALIDATION.md](docs/VALIDATION.md).
Source code is MIT licensed. The project name has not been checked for trademarks.
