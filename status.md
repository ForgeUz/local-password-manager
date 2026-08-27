# Vault Crypto - Implementation Status

**Last updated:** 2026-08-25
**Current version:** V6.5.1 (Mutation Campaign Complete)

Status legend: DONE / PARTIAL / NOT STARTED / NEXT

---

## 1. Summary

| Metric | Value |
|--------|-------|
| Total tests | 315+ (all passing) |
| Mutation kill score | 100% (133/133: 100 TCB + 20 V6.5 + 3 vault_data + 3 passkey + 3 onboarding + 4 shamir) |
| Security gate suites | security.md (1-20) + security2.md (21-32) — DONE |
| Fuzzing | 6 fuzzers, 0 crashes |
| Analyzer errors | 0 |
| Analyzer warnings | pre-existing info/warnings only |
| External audit | NOT STARTED (pending) |
| Linux build | DONE (verified + installed as desktop app) |
| Android build | DONE (verified, libsodium bundled, device-tested) |

> **Full test/mutation/fuzzer registry:** See [`TESTING.md`](TESTING.md).

---

## 2. Crypto Core (V4/V5) - VERIFIED

The Trusted Computing Base is complete and internally verified.

| Component | Status | Notes |
|-----------|--------|-------|
| `vault_crypto_v4.dart` (format, outer GCM, MP change, duress) | DONE | Mutation-tested |
| `key_hierarchy.dart` (VRK, DEK wrap/unwrap) | DONE | Mutation-tested |
| `header.dart` (parser, bounds checks) | DONE | Bounds checking applied |
| `padding.dart` (bucket masking) | DONE | Constant-time |
| `second_factor.dart` (rate-limit, constant-time) | DONE | Mutation-tested |
| `duress.dart` (domain separation) | DONE | Mutation-tested |
| `search_tag.dart` (SearchKey zeroing, normalization) | DONE | URL normalization applied |
| `argon2id.dart` (FFI wrapper) | DONE | `sodium_memzero` applied |
| `aes_gcm.dart` (FFI wrapper) | DONE | AES-NI check, `sodium_memzero` |
| `hkdf.dart` (FFI wrapper) | DONE | `sodium_memzero` applied |
| `secure_buffer.dart` (`sodium_malloc`) | DONE | Dispose zeroing verified |

**Post-audit hardening applied:**
- Native memory zeroing (all FFI wrappers)
- Dart-side zeroing (IKM/MK/VRK/DEK/SFM/SearchKey)
- Bounds checking (header, second_factor)
- AES-NI hardware check (fail-closed)
- Error oracle prevention (unified errors)
- URL normalization (search tags)
- Header parser RangeError fix (truncated-header boundary now throws CorruptBlobError, found by `tool/fuzz_vault.dart`)

---

## 3. V6.5 Mass-User Features - IMPLEMENTED

All V6.5 modules implemented and unit-tested. The core mutation campaign is complete (100/100).

### 3.1 Security Tiers

| Item | Status |
|------|--------|
| `security_tier.dart` (enum, TierPolicy, TierValidator) | DONE (21 tests) |
| `security_tier_ui_helper.dart` (UI metadata, suggestions) | DONE |
| `tier_autofill_enforcer.dart` (decision engine, lookalike) | DONE (10 tests) |
| Tier selector widget | DONE |
| Downgrade confirmation | DONE |

### 3.2 TOTP Generator

| Item | Status |
|------|--------|
| `totp_generator.dart` (RFC 6238) | DONE (5 tests) |
| `totp_import.dart` (otpauth:// parser) | DONE (8 tests) |
| RFC 6238 compliance (SHA1/SHA256/SHA512) | DONE (all vectors pass) |
| TOTP display widget (countdown, copy) | DONE |
| QR scanner screen | DONE |

### 3.3 P2P Sync (logic DONE, UI PARTIAL)

| Item | Status |
|------|--------|
| `sync_session.dart` (orchestration) | DONE (4 tests) |
| `pairing_session.dart` (state machine, PSK) | DONE (5 tests) |
| `noise_session.dart` (Noise NNpsk0, TOFU) | DONE (4 tests) |
| `conflict_resolver.dart` (manual resolution) | DONE (3 tests) |
| `vector_clock.dart` (conflict detection) | DONE (4 tests) |
| `replay_counter.dart` (replay prevention) | DONE (2 tests) |
| `traffic_padding.dart` (traffic analysis) | DONE (3 tests) |
| Sync pairing UI screen | DONE (rebuilt via pure SyncStore + SyncState typestate) |

### 3.4 Android Platform (code + device test DONE)

| Item | Status |
|------|--------|
| `MainActivity.kt` (biometric, clipboard, plugin reg) | DONE (code review pass) |
| `VaultAutofillService.kt` (autofill framework) | DONE (code review pass) |
| `BleTransportPlugin.kt` (BLE transport) | DONE (refactored to MethodCallHandler) |
| `AndroidManifest.xml` (permissions, services) | DONE (zero-cloud enforced) |
| Real device verification | DONE (Android 13 device-tested) |

### 3.5 Passkeys (P3)
| Item | Status |
|------|--------|
| passkey_platform.dart (MethodChannel bridge) |	DONE
| PasskeyPlugin.kt (Android CredentialManager) |	DONE
| VaultEntry.passkeyCredentialId (V4 schema evolution) | DONE (Mutation tested M121-M123)

---

## 4. Testing & Verification

| Suite | Count | Status |
|-------|-------|--------|
| Full test suite | 315+ | DONE (all pass) |
| Mutation campaign (core) | 100/100 | DONE (100% kill, M01-M100) |
| Mutation campaign (V6.5) | 20/20 | DONE (100% kill, M101-M120) |
| Mutation campaign (Vault Data) | 3/3 | DONE (100% kill, M121-M123) |
| Mutation campaign (Passkey) | 3/3 | DONE (100% kill, M124-M126) |
| Mutation campaign (OnBoarding) | 3/3 | DONE (100% kill, M127-M129) |
| Mutation campaign (Shamir) | 4/4 | DONE (100% kill, M130-M133) |
| Static analysis | 0 errors | DONE |
| Security gate suite (`security.md` gates 1-20) | DONE | all gates tested |
| Advanced suite (`security2.md` gates 21-32) | DONE | statemachine, model, fuzzers, concurrency, crash, differential, multivault, attacks, regression |
| Vault fuzzing (`tool/fuzz_vault.dart`) | 100k | DONE (0 crashes) |
| Grammar fuzzing (`tool/fuzz_vault_grammar.dart`) | 50k | DONE (0 crashes) |
| Sync protocol fuzzing (`tool/fuzz_sync_protocol.dart`) | 20k | DONE (all malicious inputs rejected) |
| TOTP import fuzzing (`tool/fuzz_totp_import.dart`) | 20k | DONE (no crashes) |
| Memory dump (`tool/memory_dump.dart`) | 1000 cycles | DONE (no residual) |

> **Full registry:** See [`TESTING.md`](TESTING.md).

---

## 5. Platform Status

### Linux

- Compiles
- Runs
- Seccomp deny-list live
- Tray / hotkey native
- Sensitive clipboard MIME implemented
- Build script with integrity hash (`build_linux.sh`)

### Android

- Code written (MainActivity, Autofill, BLE plugin)
- Manifest correct (no INTERNET, allowBackup=false)
- Refactored BLE plugin (MethodChannel, not Activity)
- Compiled and device-tested (biometric, autofill, BLE, FLAG_SECURE)
- libsodium bundled for arm64-v8a and armeabi-v7a

### Other platforms

- iOS: NOT STARTED
- Windows: NOT STARTED
- macOS: NOT STARTED

---

## 6. V6 Roadmap Progress

| Priority | Task | Status |
|----------|------|--------|
| P0 | External cryptographic audit | NEXT (AUDIT_BRIEF_V65.md prepared, auditor recruitment pending) |
| P1 | Publish project + gather feedback | PARTIAL (docs ready, announcement post pending) |
| P2 | Onboarding flow design | DONE (Typestate Wizard + Mutation tested M127-M129) |
| P3 | Recovery UX design | NOT STARTED |
| P4 | Android build environment setup | DONE (`android/DEPS.md` written) |
| P5 | Android device verification | DONE (device-tested) |
| P6 | TPM sealing design | NOT STARTED (research not started) |
| P7 | Noise PQ-hybrid transport | NOT STARTED (research not started) |
| P8 | Runtime integrity attestation | NOT STARTED (research not started) |

---

## 7. Documentation Status

| Document | Status |
|----------|--------|
| `README.md` | DONE (updated for V6.5.1) |
| `SECURITY.md` | DONE (updated for V6.5.1 threat model) |
| `SECURITY_AUDIT.md` | DONE (updated with V6.5 audit) |
| `AUDIT_BRIEF_V65.md` | DONE (created) |
| `CONTRIBUTING.md` | DONE (created) |
| `v6_delta.md` | DONE (complete) |
| `v6.5_delta.md` | DONE (complete) |
| `status.md` | DONE (this document) |
| `android/DEPS.md` | DONE (build instructions) |

---

## 8. Known Issues

**None known at this time.** See `SECURITY.md` for vulnerability reporting.

---

## 9. Honest Limitations (current)

Carried forward, still applicable:

1. `V4VaultEntry.password` is Dart `String` in UI model (Flutter limitation). Crypto core never holds it as String.
2. Mutation testing covers only encoded mutations. Not a substitute for external audit.
3. Wayland global-shortcut portal limitation (X11 grab works).
4. Behavioral biometrics is anomaly deterrent, not authentication.

V6.5 additions:

5. RESOLVED: V6.5 modules mutation-tested (20/20 killed, M101-M120, 100% score).
6. P2P sync requires both devices online simultaneously (no async).
7. BLE 10m range physical, not software-enforced.
8. TOTP secrets in vault = single point of failure.
9. Security tiers advisory (determined user can bypass UI).
10. TOFU first-pairing vulnerable to MITM.

---

## 10. Immediate Next Steps

### This week
1. Draft announcement post (P1)
2. Begin auditor outreach (P0)

### Next 2 weeks
3. Publish on GitHub with release tag `v1.0.0-pre-audit` (P1)
4. Post announcement to HN, Reddit, security lists (P1)
5. DONE: mutation campaign extended to V6.5 (20/20 killed)

### Blocked
- External audit (P0) - needs auditor

---

## 11. Phase Acceptance Checklist

### V6.5 Acceptance
- [x] Security tiers implemented + tested
- [x] TOTP generator implemented + tested
- [x] P2P sync logic implemented + tested
- [x] Android platform code written
- [x] All internal inconsistencies fixed (0 analyzer errors)
- [x] README, SECURITY, SECURITY_AUDIT, AUDIT_BRIEF, CONTRIBUTING updated
- [x] Android compiled and device-tested
- [x] V6.5 mutation campaign run

### V6 Acceptance (from v6_delta.md)
- [x] `v6_delta.md` created
- [x] `v6.5_delta.md` created
- [x] Audit brief prepared (P0)
- [ ] Project published on GitHub with release tag (P1)
- [ ] Announcement post written (P1)
- [x] Onboarding flow designed (P2)
- [ ] Recovery UX designed (P3)
- [x] Android build instructions written (P4)

---

**Bottom line:** Crypto core verified (133/133 mutation kill). Full suite is 315+ tests, all passing. Security gate suites (security.md gates 1-20 + security2.md gates 21-32) complete. Six fuzzers, 0 crashes. Linux and Android builds verified and device-tested (libsodium bundled). Remaining blocker: external audit. See [`TESTING.md`](TESTING.md) for the full verification registry.
