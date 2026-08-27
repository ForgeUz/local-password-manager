# Vault Crypto — Threat Model

**Version:** V6.5.1

## T1: Attacker steals vault file
- **Mitigation:** Vault encrypted at rest (AES-256-GCM under VRK). Cannot decrypt without master password.
- **Verified by:** `test/security/crypto/test_aes_gcm.dart`, `test/security/auth/test_master_password.dart`.
- **Residual risk:** Offline brute-force of weak master passwords (Argon2id mitigates).

## T2: Attacker has physical access to unlocked device
- **Mitigation:** Auto-lock, SecureBuffer zeroing, clipboard timeout, FLAG_SECURE.
- **Verified by:** `test/security/memory/test_zeroing.dart`, `test/security/clipboard/test_clipboard.dart`.

## T3: Attacker observes user typing (shoulder surfing)
- **Mitigation:** Password field masked, TOTP masked, duress password indistinguishable.
- **Residual risk:** Behavioral biometrics is anomaly deterrent, not authentication.

## T4: Malware on device
- **Mitigation:** Seccomp deny-list (Linux), encrypted at rest, no plaintext secrets in memory during lock, sensitive clipboard MIME.
- **Verified by:** `test/security/sandbox/test_seccomp.dart`, `test/security/memory/test_zeroing.dart`.

## T5: Network attacker (for sync)
- **Mitigation:** All sync traffic encrypted (Noise protocol), TOFU prevents MITM after first connection.
- **Residual risk:** First-connection MITM possible (documented limitation).
- **Verified by:** `test/security/sync/test_noise.dart`, `test/security/attacks/test_sync_mitm.dart`.

## T6: Coercion attack
- **Mitigation:** Duress vault provides plausible denial; cannot prove existence of primary vault.
- **Verified by:** `test/security/duress/test_duress.dart`, `test/security/format/test_decoy.dart`.

## T7: Malicious vault file (parsing attack)
- **Mitigation:** Bounds-checked parser, uniform CorruptBlobError, fuzzing.
- **Verified by:** `test/security/format/test_gen4_parser.dart`, `tool/fuzz_vault.dart`, `tool/fuzz_vault_grammar.dart`.

## T8: Timing side-channel
- **Mitigation:** Constant-time comparison, AES-NI, uniform error messages.
- **Verified by:** `tool/timing_analysis.dart`, `tool/timing_statistical.dart`, `tool/timing_cache.dart`.

## T9: Replay / MITM during sync
- **Mitigation:** Replay counter, vector clock, Noise MAC, TOFU.
- **Verified by:** `test/security/sync/test_replay.dart`, `tool/fuzz_sync_protocol.dart`.

## T10: Supply chain / build tampering
- **Mitigation:** Pinned dependencies, libsodium provenance, build reproducibility.
- **Verified by:** `tool/verify_deps.dart`, `tool/verify_build.dart`, `tool/verify_libsodium.dart`.
