# Vault Crypto — Security Test Coverage

**Version:** V6.5.1

## security.md Gates (1-20)

| Gate | Test file | Status |
|------|-----------|--------|
| 1.1 Argon2id | `test/security/crypto/test_argon2id.dart` | PASS |
| 1.2 AES-GCM | `test/security/crypto/test_aes_gcm.dart` | PASS |
| 1.3 HKDF | `test/security/crypto/test_hkdf.dart` | PASS |
| 1.4 Key hierarchy | `test/security/crypto/test_key_hierarchy.dart` | PASS |
| 1.5 Nonce | `test/security/crypto/test_nonce.dart` | PASS |
| 2.1 Format parsing | `test/security/format/test_gen4_parser.dart` | PASS |
| 2.2 Decoy vault | `test/security/format/test_decoy.dart` | PASS |
| 3.1 SecureBuffer | `test/security/memory/test_secure_buffer.dart` | PASS |
| 3.2 Secret zeroing | `test/security/memory/test_zeroing.dart` | PASS |
| 4.1 Master password | `test/security/auth/test_master_password.dart` | PASS |
| 4.2 TOTP | `test/security/auth/test_totp.dart` | PASS |
| 5 Duress | `test/security/duress/test_duress.dart` | PASS |
| 6.1-6.3 Sync | `test/security/sync/*.dart` | PASS |
| 7.1,7.3 Android | `test/security/android/*.dart` | PASS |
| 8 Search SSE | `test/security/search/test_sse.dart` | PASS |
| 9.1-9.2 Recovery | `test/security/recovery/*.dart` | PASS |
| 10 Clipboard | `test/security/clipboard/test_clipboard.dart` | PASS |
| 11 Seccomp | `test/security/sandbox/test_seccomp.dart` | PASS |
| 12 Error leakage | `test/security/errors/test_error_leakage.dart` | PASS |
| 13.1 Vault fuzz | `tool/fuzz_vault.dart` | PASS |
| 14.1-14.2 Integration | `test/security/integration/*.dart` | PASS |
| 16.1 Memory dump | `tool/memory_dump.dart` | PASS |
| 16.2 Timing | `test/security/runtime/test_timing.dart` | PASS |
| 18 Vectors | `test/security/vectors/test_vectors.dart` | PASS |
| 19 Performance | `tool/performance_test.dart` | PASS |

## security2.md Gates (21-32)

| Gate | Test file | Status |
|------|-----------|--------|
| 21.1 Vault states | `test/security/statemachine/test_vault_states.dart` | PASS |
| 21.2 Sync states | `test/security/statemachine/test_sync_states.dart` | PASS |
| 22.1 Crypto model | `test/security/model/test_crypto_model.dart` | PASS |
| 22.2 Format model | `test/security/model/test_format_model.dart` | PASS |
| 23.1 Grammar fuzz | `tool/fuzz_vault_grammar.dart` | PASS |
| 23.2 Sync fuzz | `tool/fuzz_sync_protocol.dart` | PASS |
| 23.3 TOTP fuzz | `tool/fuzz_totp_import.dart` | PASS |
| 24.1 Lock race | `test/security/concurrency/test_lock_race.dart` | PASS |
| 24.2 Concurrent access | `test/security/concurrency/test_concurrent_access.dart` | PASS |
| 25.1 Power loss | `test/security/crash/test_power_loss.dart` | PASS |
| 25.2 FS edge cases | `test/security/crash/test_fs_edge_cases.dart` | PASS |
| 26.1 TOTP differential | `test/security/differential/test_totp_differential.dart` | PASS |
| 26.2 Argon2 differential | `test/security/differential/test_argon2_differential.dart` | PASS |
| 27.1 Deps | `tool/verify_deps.dart` | PASS |
| 27.2 Build | `tool/verify_build.dart` | PASS |
| 27.3 libsodium | `tool/verify_libsodium.dart` | PASS |
| 28.1 Statistical timing | `tool/timing_statistical.dart` | PASS |
| 28.2 Cache timing | `tool/timing_cache.dart` | PASS |
| 29.1 Multi-vault | `test/security/multivault/test_multiple_vaults.dart` | PASS |
| 29.2 Edge vaults | `test/security/multivault/test_edge_vaults.dart` | PASS |
| 31.1 CI workflow | `.github/workflows/security.yml` | PASS |
| 31.2 Regression | `test/security/regression/test_regression_suite.dart` | PASS |
| 32.1 Sync MITM | `test/security/attacks/test_sync_mitm.dart` | PASS |
| 32.2 Clipboard attack | `test/security/attacks/test_clipboard_attack.dart` | PASS |
