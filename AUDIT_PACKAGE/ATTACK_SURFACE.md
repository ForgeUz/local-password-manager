# Vault Crypto — Attack Surface Enumeration

**Version:** V6.5.1

Every input to the system, where it enters, what validation is applied, and
which tests verify it.

| Input | Entry point | Validation | Malformed handling | Test |
|-------|-------------|-----------|--------------------|------|
| Vault file | `V4Header.parse` | Bounds checks, magic, version, sanity limits | `CorruptBlobError` | `test_gen4_parser.dart`, `fuzz_vault.dart` |
| Master password | `unlockVault` | Argon2id KDF | `DecryptionFailedError` | `test_master_password.dart` |
| Duress password | `duressUnlockSession` | Argon2id KDF | `DuressDecryptError` | `test_duress.dart` |
| TOTP secret | `TotpUriParser` | base32, algorithm, digits, period | `TotpImportError` | `fuzz_totp_import.dart` |
| TOTP code | `SecondFactor.open` | constant-time compare | `BackupCodeError` | `test_totp.dart` |
| Backup codes | `SecondFactor.open` | Argon2id hash, single-use, rate-limit | `BackupCodeError` | `test_totp.dart` |
| Shamir shares | `ShamirKit.parseShare` | base64, length check | `StateError` | `test_shamir.dart` |
| Autofill request | `TierAutofillEnforcer` | tier, domain match, lookalike | `Block*` decision | `test_autofill.dart` |
| Sync peer | `NoiseSession` | PSK, TOFU, window, attempts | `PairStatus.failed/cooldown` | `test_noise.dart`, `fuzz_sync_protocol.dart` |
| Search query | `SearchTag` | URL normalization, min length | deterministic tag | `test_sse.dart` |
| Entry data | `V4VaultEntry.fromJson` | JSON parse | `DecryptionFailedError` | `test_error_leakage.dart` |
| Sync messages | `ReplayCounter` | monotonic counter | rejected | `test_replay.dart` |
