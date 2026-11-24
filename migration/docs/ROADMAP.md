# Roadmap

Delivered: local CLI, controlled RSA legacy format, hybrid HPKE destination, safe
no-overwrite publication, recovery verification, synthetic accept/reject demo,
JSON reports, automated tests, source, cross-compiled executables, and usage guide.

Next: independent cryptographic review and cross-implementation vectors before new
features. Validate fault behavior and platform permissions. Separate key custody from
migration with KMS/HSM adapters and authenticated public-key distribution.

Then: design an authenticated streaming format for large files; batch job manifests
and crash recovery; explicit data-key rotation/re-encryption mode; supported-format
adapters; signed evidence and externally anchored rollback detection.

Later: cloud object-store integration, read-only discovery, policy checks in CI,
retention-aware risk prioritization, key lifecycle and disaster-recovery workflows.

Not promised: decrypting files without their owner's keys, converting arbitrary
ciphertext, identifying unknown encryption with certainty, protecting previously
harvested copies, quantum-proof guarantees, or inventing a new cryptographic algorithm.
