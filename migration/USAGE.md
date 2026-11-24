# CipherSetu usage

Windows PowerShell examples below use the included x86-64 executable.
Run from the extracted `CipherSetu` folder. All parent folders must already exist,
except directories created by `keygen` and `demo`. Use a private local NTFS directory;
FAT/exFAT and some network filesystems do not support the atomic hard-link publishing used here.

## 1. Generate demo legacy keys and new hybrid keys

```powershell
$Aegis = '.\bin\ciphersetu-windows-amd64.exe'
& $Aegis keygen --type rsa-demo --dir old-keys
& $Aegis keygen --type hybrid --dir new-keys
'Synthetic customer record, for testing only.' | Set-Content sample.txt
```

Each directory contains `public.json` and `private.json`. Never commit private keys.
Public keys must be distributed through an authenticated channel; the CLI does not
verify who owns a supplied public key. Losing the required private key loses access.

## 2. Create a legacy sample

```powershell
& $Aegis encrypt --in sample.txt --public old-keys\public.json --out old.aegis --legacy-demo
& $Aegis inspect --in old.aegis
```

`--legacy-demo` is mandatory to create RSA-protected samples. Use hybrid protection
for new files. `inspect` is a structural check, not proof of authenticity.

## 3. Migrate and save the report

```powershell
& $Aegis migrate --in old.aegis --old-private old-keys\private.json --new-private new-keys\private.json --out migrated.aegis > migration-report.json
if ($LASTEXITCODE -ne 0) { throw 'Migration failed; inspect the error above.' }
Get-Content migration-report.json
```

Migration needs both private keys in this alpha: the old key unlocks the data key,
and the new key verifies successful recovery before publication. A future production
adapter should perform these operations through separated KMS/HSM custody.
The envelope and redirected report are not one filesystem transaction. If report writing
fails after migration, verify the output independently. Do not treat an empty report as success.

## 4. Verify and restore

```powershell
& $Aegis verify --in migrated.aegis --private new-keys\private.json --original sample.txt
& $Aegis decrypt --in migrated.aegis --private new-keys\private.json --out restored.txt
```

Without `--original`, verify checks authenticated decryption only. It cannot independently
know that the envelope contains the intended original file or prove sender identity.

## 5. Demonstrate rejection

```powershell
& $Aegis decrypt --in migrated.aegis --private old-keys\private.json --out rejected.txt
```

Expected: nonzero exit code; no `rejected.txt`. The original `old.aegis` remains
accessible with the old key. This is not cryptographic revocation of old copies.
The `demo` command also flips a byte in an in-memory copy and verifies rejection.

## 6. Encrypt a new file directly

```powershell
& $Aegis encrypt --in sample.txt --public new-keys\public.json --out fresh.aegis
& $Aegis verify --in fresh.aegis --private new-keys\private.json --original sample.txt
```

Every encryption generates a fresh random 256-bit data key, 96-bit GCM nonce,
128-bit file ID, and fresh HPKE encapsulation. Algorithms do not change secretly.

## CI/CD integration

The included GitHub Actions workflow tests Linux, Windows and macOS, runs static
analysis, and runs the synthetic demo. It needs no API keys. The workflow is supplied
for your repository; hosted jobs were not executed when packaging this release.

For a local CI job:

```sh
go test ./...
go vet ./...
go build -buildvcs=false -trimpath -o ciphersetu ./cmd/ciphersetu
./ciphersetu demo --dir ci-demo
```

Check the process exit code. Never upload `ci-demo` as a public artifact: it contains
private keys. A migration job for actual company data is outside this alpha's scope.

## Troubleshooting and interruption

- **File exists:** choose a new output filename. Existing files are never overwritten.
- **Unsupported envelope/header:** input must be the CipherSetu v1 format; renaming it will not convert it.
- **Wrong key/authentication failed:** use the matching private key; do not bypass verification.
- **Publish failed:** use a local filesystem supporting hard links and an absent destination.
- **Interrupted migration:** source is preserved. If destination exists, run `verify` with
  the destination key. Otherwise retry. A `.ciphersetu-*` temporary file may remain
  after a process crash; inspect and remove only after confirming no process uses it.
- **Interrupted key generation:** a partial new key directory can remain. Preserve any
  generated key material, inspect the directory, and use a fresh directory for another attempt.
- Output is synced before publishing, but portable directory-fsync/power-loss durability
  is not guaranteed. There is no multi-file transactional journal or automatic resume.
