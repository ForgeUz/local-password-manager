# Vault Crypto — Testing & Verification Registry

**Version:** V6.5.1
**Purpose:** Single source of truth for every test suite, mutation run, fuzzer,
and verification tool. Other docs link here instead of duplicating counts.

---

## 1. Test Suites

### 1.1 Unit & Integration Tests

Run: `flutter test`

| Area | Location | Coverage |
|------|----------|----------|
| Crypto core (V4/V5) | `test/crypto/` | Argon2id, AES-GCM, HKDF, key hierarchy, header, padding, duress, search, second-factor, vault round-trip |
| Security tiers | `test/security/` (top-level) | tier policy, autofill enforcer, lookalike, risk tiers, dashboard, shamir, biometrics, breach, posture |
| Security gates (security.md §1-20) | `test/security/{crypto,format,memory,auth,duress,sync,android,search,recovery,clipboard,sandbox,errors,integration,vectors,runtime}/` | All 20 security.md gates |
| Advanced gates (security2.md §21-32) | `test/security/{statemachine,model,concurrency,crash,differential,multivault,attacks,regression}/` | All 12 security2.md gates |
| App / service | `test/app/` | init flow, vault service |
| Coercion | `test/coercion/` | decoy, shred, cancellation |
| Lock | `test/lock/` | auto-lock, backoff, lifecycle, secret wiper |
| Sync | `test/sync/` | noise, pairing, replay, vector clock, conflict, traffic padding |
| TOTP | `test/totp/` | RFC 6238 generator |
| Vault | `test/vault/` | data model, storage |
| Biometric / clipboard / backup / onboarding / passkey / desktop / os | `test/{biometric,clipboard,backup,onboarding,passkey,desktop,os}/` | platform modules |

**Total:** 315+ tests (all passing in a normal environment).

> **Note:** FFI-dependent vault round-trip tests require AES-NI initialization.
> In a sandboxed CI environment (no AES-NI / `ld.so.preload` restrictions) they
> may fail in isolation; they pass when run as part of the full suite.

### 1.2 Security Gate Suites

The two verification plans are the authoritative gate lists:

- [`security.md`](security.md) — gates 1-20 (crypto core, format, memory, auth, duress, sync, android, search, recovery, clipboard, seccomp, errors, fuzzing, integration, vectors, runtime, threat model).
- [`security2.md`](security2.md) — gates 21-32 (state machines, model-based, grammar fuzzing, concurrency, crash consistency, differential, supply chain, timing, multi-vault, audit package, CI, regression, attack simulation).

Each gate maps to a test file under `test/security/`. See
[`AUDIT_PACKAGE/TEST_COVERAGE.md`](AUDIT_PACKAGE/TEST_COVERAGE.md) for the
full gate-to-file mapping.

---

## 2. Mutation Campaigns

Run: `dart run tool/mutation_campaign.dart` (full, ~110 min) or
`dart run tool/mutation_campaign.dart --quick` (10 core mutants).

The registry lives in [`tool/mutation_campaign.dart`](tool/mutation_campaign.dart)
(**M01-M133**). A mutation is "killed" when the test suite fails after applying
it, proving the invariant is covered.

| Campaign | Mutations | Kill score | Status |
|----------|-----------|-----------|--------|
| TCB core (M01-M100) | 100 | 100% | DONE |
| V6.5 modules (M101-M120) | 20 | 100% | DONE |
| Vault data (M121-M123) | 3 | 100% | DONE |
| Passkey (M124-M126) | 3 | 100% | DONE |
| Onboarding (M127-M129) | 3 | 100% | DONE |
| Shamir (M130-M133) | 4 | 100% | DONE |
| **Total** | **133** | **100%** | **DONE** |

### Mutation groups (M01-M100 TCB)

| Group | Mutations | Invariants |
|-------|-----------|------------|
| vault_crypto_v4 | 20 | format, outer GCM, MP change, duress, memory zeroing, relock |
| key_hierarchy | 10 | VRK derivation, DEK wrap/unwrap, CSPRNG, TOTP folding |
| header | 13 | parser, bounds checks, endianness, KDF sanity |
| padding | 8 | bucket masking, CSPRNG, big-endian length |
| second_factor | 9 | rate-limit, single-use, constant-time, memory zeroing |
| duress | 4 | domain separation, empty salt, key size |
| search_tag | 9 | SearchKey zeroing, bucket padding, normalization |
| argon2id | 3 | FFI memory zeroing, fail-closed |
| aes_gcm | 2 | FFI memory zeroing, AES-NI check |
| hkdf | 3 | PRK zeroing, salt padding, output length |
| constant_time | 2 | length mismatch, sodium_compare |
| hmac_sha256 | 2 | key length, fail-closed |
| sha256 | 2 | output length, fail-closed |
| secure_buffer | 2 | dispose zeroing, idempotent dispose |
| native_noise | 2 | keypair failure, short ciphertext |
| replay_counter | 2 | non-increasing reject, lastSeen update |
| vector_clock | 4 | increment, dominates, conflict |
| conflict_resolver | 3 | archive, localWins, archived flag |

---

## 3. Fuzzers

| Fuzzer | Run | Iterations | Result |
|--------|-----|-----------|--------|
| [`tool/fuzz_vault.dart`](tool/fuzz_vault.dart) | `dart run tool/fuzz_vault.dart --iterations 100000` | 100k | 0 crashes |
| [`tool/fuzz_vault_grammar.dart`](tool/fuzz_vault_grammar.dart) | `dart run tool/fuzz_vault_grammar.dart --iterations 50000` | 50k | 0 crashes |
| [`tool/fuzz_sync_protocol.dart`](tool/fuzz_sync_protocol.dart) | `dart run tool/fuzz_sync_protocol.dart --iterations 20000` | 20k | all malicious inputs rejected |
| [`tool/fuzz_totp_import.dart`](tool/fuzz_totp_import.dart) | `dart run tool/fuzz_totp_import.dart --iterations 20000` | 20k | 0 crashes |
| [`tool/fuzz_parsers.dart`](tool/fuzz_parsers.dart) | `dart run tool/fuzz_parsers.dart` | 100k | 0 crashes |
| [`tool/fuzz_enforcer.dart`](tool/fuzz_enforcer.dart) | `dart run tool/fuzz_enforcer.dart` | 50k | 0 crashes |

---

## 4. Verification Tools

| Tool | Run | Verifies |
|------|-----|----------|
| [`tool/memory_dump.dart`](tool/memory_dump.dart) | `dart run tool/memory_dump.dart` | no residual plaintext after lock; no accumulation over 1000 cycles |
| [`tool/timing_analysis.dart`](tool/timing_analysis.dart) | `dart run tool/timing_analysis.dart` | password verification time uniform (no oracle) |
| [`tool/timing_statistical.dart`](tool/timing_statistical.dart) | `dart run tool/timing_statistical.dart` | KS test, Welch's t-test, Cohen's d on timing distributions |
| [`tool/timing_cache.dart`](tool/timing_cache.dart) | `dart run tool/timing_cache.dart` | AES-GCM timing independent of key content |
| [`tool/performance_test.dart`](tool/performance_test.dart) | `dart run tool/performance_test.dart` | 10k-entry vault performance, no memory leak |
| [`tool/verify_deps.dart`](tool/verify_deps.dart) | `dart run tool/verify_deps.dart` | dependency pinning (no `^`) |
| [`tool/verify_build.dart`](tool/verify_build.dart) | `dart run tool/verify_build.dart` | build reproducibility, no debug symbols |
| [`tool/verify_libsodium.dart`](tool/verify_libsodium.dart) | `dart run tool/verify_libsodium.dart` | libsodium provenance (SHA-256) |
| [`tool/verify_mutations.dart`](tool/verify_mutations.dart) | `dart run tool/verify_mutations.dart` | every mutation's search string exists in source |

---

## 5. CI

[`.github/workflows/security.yml`](.github/workflows/security.yml) runs on every
push/PR and nightly:
- crypto/format/memory/auth/errors tests
- statemachine/model/concurrency/crash/differential/multivault/attacks/regression tests
- fuzzing (vault, grammar, TOTP, sync protocol)
- timing + memory
- supply-chain (deps, libsodium)
- static analysis (`flutter analyze`, `dart format`)

---

## 6. Audit Package

[`AUDIT_PACKAGE/`](AUDIT_PACKAGE) contains the auditor-facing documentation:
- [`CRYPTO_SPEC.md`](AUDIT_PACKAGE/CRYPTO_SPEC.md) — exact byte layout, key derivation, domain separation, parameters
- [`THREAT_MODEL.md`](AUDIT_PACKAGE/THREAT_MODEL.md) — threat model T1-T10
- [`ATTACK_SURFACE.md`](AUDIT_PACKAGE/ATTACK_SURFACE.md) — every input, validation, test
- [`TEST_COVERAGE.md`](AUDIT_PACKAGE/TEST_COVERAGE.md) — gate-to-file mapping
- [`KNOWN_LIMITATIONS.md`](AUDIT_PACKAGE/KNOWN_LIMITATIONS.md) — honest limitations
- [`BUILD_REPRODUCIBILITY.md`](AUDIT_PACKAGE/BUILD_REPRODUCIBILITY.md) — how to verify builds
- [`DIFFERENTIAL_ANALYSIS.md`](AUDIT_PACKAGE/DIFFERENTIAL_ANALYSIS.md) — reference-implementation comparison
