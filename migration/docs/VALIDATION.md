# Release validation — 2026-11-04

Toolchain: Go 1.27.3. Host: Linux x86-64. No third-party Go modules.

Passed:
- `go test -race ./...` for envelope and CLI packages.
- `go vet ./...`.
- Five-second fuzz budget for strict envelope JSON parsing: 46,130 executions,
  no failure. This short run is a smoke test, not exhaustive fuzzing.
- Compiled Linux binary executed demo and independent `verify --original`: PASS.
- Windows x86-64 and macOS ARM64 cross-compilation.

Tests cover empty/binary payload recovery, source/ciphertext preservation,
old-key rejection, wrong hybrid recipient, public-key rejection, tampered payload,
nonce, ID, wrapped key, encapsulation, recipient, header version, suite and cipher,
malformed nonce, tampered legacy migration, remigration rejection, randomized
new encryption, strict JSON including case-variant duplicate fields, bounded reads,
plaintext size rejection, no-overwrite writes, missing parents, key serialization,
and CLI workflow/error paths including absence of output on failed decryption.

Not performed: Windows/macOS native execution, hosted CI, independent crypto review,
interoperability with another HPKE implementation, cloud/HSM integration, simulated
quantum attacks, filesystem crash/power-loss injection, large-scale benchmarks,
or side-channel testing. Tests do not establish production readiness.

The build does not contain generated demo keys or encrypted user data. Keys and
synthetic samples are generated afresh when the user runs the demo.
