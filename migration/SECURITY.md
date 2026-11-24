# Security model and limitations

CipherSetu 0.1.0-alpha is an unaudited research CLI, for synthetic data only.
Do not equate standard-library primitives with validation of this application protocol.

## Protected operations

- AES-256-GCM authenticates file contents and a stable versioned header.
- RSA-OAEP-SHA256 legacy wrapping binds a context as the OAEP label.
- Hybrid HPKE wrapping binds the same context as HPKE info: domain, header, nonce,
  SHA-256 ciphertext digest, suite, and recipient identifier.
- Recipient identifiers hash the canonical public-key JSON; they are identifiers, not secrets.
- Fixed suite allowlist; no automatic downgrade, fallback, or external algorithm plugins.
- Structural and length checks precede decryption. JSON duplicates, unknown fields,
  trailing values, and excessive nesting are rejected.
- Authentication failure releases no plaintext output. Migration verifies original
  and destination plaintext equality before saving the destination.
- Output publication uses a synced private temporary file and a no-replace hard link.
  Existing source and output files are never intentionally replaced.

## Trust boundaries

The local machine, executable, OS random generator, input-key provenance, output directory,
user account, and private-key handling must be trusted. Destination directories must not
be writable by adversaries. This is not a network decryption oracle or multi-user service.
Private keys are stored unencrypted. Unix modes do not establish restrictive Windows ACLs.
Do not run with real data, in shared temporary folders, or from a synchronizing public folder.
Plaintext and keys exist in process memory; Go does not guarantee elimination of all copies,
locked memory, swap exclusion, or protection from crash dumps. Best-effort clear is not secure erasure.

Anyone with the recipient public key can create a new valid envelope: AEAD provides
integrity within an encryption operation, not sender identity or freshness. Replacement
of an entire file, rollback to a valid old file, and replay are not detected without an
external trusted record. Reports are unsigned local records, not third-party attestations.

## Rewrapping is not retroactive protection

The data-encryption key remains the same. An attacker who later recovers it from a
harvested RSA envelope can decrypt the corresponding unchanged data ciphertext,
including the migrated copy. A lost/compromised data key requires a separate re-encryption
strategy, not merely new wrapping. Even re-encryption cannot secure harvested old plaintext.
Retaining old envelopes/backups retains their old exposure; deletion is not automated here.

## Production prerequisites

Independent format and implementation review; authenticated key distribution;
KMS/HSM integration and separated custody; encrypted key backups and recovery drills;
Windows ACL validation; native multi-platform testing; fault-injection/power-loss tests;
resource profiling; streaming design; interoperability vectors; dependency and toolchain
maintenance; signed release distribution; retention and old-backup retirement procedures.
The hybrid HPKE suite follows the Go implementation's draft mapping and may need a
versioned migration as specifications evolve. No FIPS validation claim is made.

## Reporting issues

Do not include real private keys or sensitive files in public issues. This source archive
has no hosted project or private reporting endpoint yet. A maintainer must establish
private reporting before public production distribution. For local testing, document
reproduction with synthetic keys and data.
