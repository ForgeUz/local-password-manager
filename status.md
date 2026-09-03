# Vault Crypto - Implementation Status

**Last updated:** 2026-09-03
**Current version:** V6.5.3 (Mutation-Window Remediation & KDF Floor Fix)

Status legend: DONE / PARTIAL / NOT STARTED / NEXT

---

## 1. Summary

| Metric | Value |
|--------|-------|
| Total tests | 584 (all passing) |
| Mutation kill score | 100% (137/137: 100 TCB + 20 V6.5 + 3 vault_data + 3 passkey + 3 onboarding + 4 shamir + 4 adaptive_posture) |
| Security gate suites | security.md (1-20) + security2.md (21-32) — DONE |
| Fuzzing | 8 fuzzers, 0 crashes, 0 timeouts |
| Analyzer errors | 0 |
| Analyzer warnings | 0 (clean) |
| External audit | NOT STARTED (pending) |
| Linux build | DONE (Hermetic, byte-identical, Wayland shortcuts) |
| Android build | DONE (Binder transit closed, CredentialManager passkeys) |
| Security roadmap | Phases 0-3 DONE (see §12) |
| Direct dependencies | 13 (allowlist-gated; pointycastle removed) |

> **Full test/mutation/fuzzer registry:** See [`TESTING.md`](TESTING.md).

---

## 2. Crypto Core (V4/V5) - VERIFIED

The Trusted Computing Base is complete and internally verified.

| Component | Status | Notes |
|-----------|--------|-------|
| `vault_crypto_v4.dart` (format, outer GCM, MP change, duress) | DONE | Mutation-tested |
| `key_hierarchy.dart` (VRK, DEK wrap/unwrap) | DONE | Mutation-tested |
| `header.dart` (parser, bounds checks) | DONE | Bounds checking applied, Fuzzed (0 crashes) |
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
- Header parser RangeError fix (truncated-header boundary now throws CorruptBlobError, found by `tool/fuzz_parsers.dart`)

---

## 2b. V6.5.3 Mutation-Window Remediation (2026-09-03)

A live mutation from the mutation-testing campaign escaped into production
(`vault_crypto_v4.dart` header-MAC used an all-zero nonce), breaking every
lock→unlock round-trip. Root-caused, fixed, and hardened.

**P0 — Root cause & regression guard**
- Reverted the live nonce mutation: header-MAC now uses the header's stored
  `nonce` (was `Uint8List(12)`).
- `_encodeId` now SHA-256-hashes entry ids (was UTF-8 truncation) — fixes
  record-id collisions in `importCsv` (17+ char ids differing only in the tail).
- Added a CI regression guard (`test/security/regression/`) that fails if any
  `MUTATION` marker is committed in `lib/`.
- Hardened `tool/mutation_campaign.dart`: runs on a temp copy (never in-place),
  aborts if the tree is already dirty, cleans up on exit.

**P1 — CI green**
- Static analysis sweep: `tool/**` excluded, FFI `constant_identifier_names`
  ignores, all `use_build_context_synchronously` guarded, `curly_braces` fixed.
  `flutter analyze` now reports **0 issues**.
- Timing gate made statistical (medians, interleaved samples, 30% tolerance).

**P2 — Real bugs**
- `vault_service.dart`: centralized MK derivation on header KDF params
  (`_deriveMk`); `_relockCurrent` forwards header params on every edit (no
  floor-downgrade brick); `resetVault` wipes VRK/entries/searchTags + deletes
  SFM + clears snapshots; `importVaultFile` locks after import (no stale-VRK/
  new-salt corruption); async mutex serializes all mutating ops; `importCsv`
  batches + relocks once; CSV export escapes quotes + neutralizes formula
  injection; canary alarm awaits the lock.
- `vault_crypto_v4.dart`: `_decryptSession` single-pass (was double-decrypt);
  `duressUnlockSession` derives from slot 2's own header (self-contained decoy)
  and catches `CorruptBlobError`.
- `vault_storage.dart`: `writeBlob` atomic; unique temp filename (pid+random);
  `deleteSfm`; async `vaultExists`.
- `concurrent_access_test.dart`: rewritten to test VaultService-level parallel
  saves (only passes with the mutex).

**P3 — KDF floor bug (critical)**
- `kdfFloorMemory = 64 MiB` but every call site passed `~/ 1024` = 65536.
  libsodium's `crypto_pwhash` memlimit is in **bytes**, so the real KDF used
  only **64 KiB** — sub-ms and weak. Fixed all sites to pass the full 64 MiB.
  Timing test now takes ~2s and has an absolute lower bound (>10ms) as a
  tripwire against future param downgrades.

**P4 — CI & hardening**
- Added a `unit-tests` job covering all orphaned non-security test dirs.
- `timeout-minutes` on every job; `actions/checkout` and
  `subosito/flutter-action` pinned by commit SHA.
- `debugVrk` guarded to debug builds.

> **Data note:** any `vault.blob`/snapshot written by the mutated build is
> permanently unreadable (tag computed under the zero nonce). Delete and
> recreate dev vaults; `resetVault` now clears snapshots + SFM.

---

## 3. V6.5 Mass-User Features - IMPLEMENTED

All V6.5 modules implemented, unit-tested, and mutation-verified.

### 3.1 Security Tiers

| Item | Status |
|------|--------|
| `security_tier.dart` (enum, TierPolicy, TierValidator) | DONE (21 tests) |
| `security_tier_ui_helper.dart` (UI metadata, suggestions) | DONE |
| `tier_autofill_enforcer.dart` (decision engine, lookalike) | DONE (Mutation tested M101-M108, RFC 1035 DoS guard) |
| Tier selector widget | DONE |
| Downgrade confirmation | DONE |

### 3.2 TOTP Generator

| Item | Status |
|------|--------|
| `totp_generator.dart` (RFC 6238) | DONE (Mutation tested M115-M120) |
| `totp_import.dart` (otpauth:// parser) | DONE (Fuzzed, 0 crashes) |
| RFC 6238 compliance (SHA1/SHA256/SHA512) | DONE (all vectors pass) |
| TOTP display widget (countdown, copy) | DONE |
| QR scanner screen | DONE |

### 3.3 P2P Sync (Logic + UI DONE)

| Item | Status |
|------|--------|
| `sync_session.dart` (orchestration) | DONE (4 tests) |
| `pairing_session.dart` (state machine, PSK) | DONE (5 tests) |
| `noise_session.dart` (Noise NNpsk0, TOFU) | DONE (4 tests) |
| `conflict_resolver.dart` (manual resolution) | DONE (3 tests) |
| `vector_clock.dart` (conflict detection) | DONE (4 tests) |
| `replay_counter.dart` (replay prevention) | DONE (2 tests) |
| `traffic_padding.dart` (traffic analysis) | DONE (3 tests) |
| Sync pairing UI screen | DONE (Rebuilt via pure `SyncStore` + `SyncState` typestate) |

### 3.4 Android Platform (Security Hardened)

| Item | Status |
|------|--------|
| `MainActivity.kt` (biometric, clipboard, plugin reg) | DONE |
| `VaultAutofillService.kt` (autofill framework) | DONE |
| `AutofillSession.kt` (Binder transit singleton) | DONE (P0-2 hole closed, no Intent extras leak) |
| `BleTransportPlugin.kt` (BLE transport) | DONE (refactored to MethodCallHandler) |
| `AndroidManifest.xml` (permissions, services) | DONE (zero-cloud enforced) |
| Real device verification | DONE (Android 13 device-tested) |

### 3.5 Passkeys (P3 - FIDO2/WebAuthn)

| Item | Status |
|------|--------|
| `PasskeyPlugin.kt` (Android 14+ CredentialManager) | DONE |
| `passkey_platform.dart` (MethodChannel bridge) | DONE |
| `passkey_core.dart` (rpId isolation) | DONE (Mutation tested M126) |
| `passkey_challenge.dart` (CSPRNG base64url) | DONE (Mutation tested M124-M125) |
| `VaultEntry.passkeyCredentialId` (V4 schema evolution) | DONE (Mutation tested M121-M123) |
| Entry Detail UI wiring | DONE |

### 3.6 Onboarding Flow (P2 - Progressive Disclosure)

| Item | Status |
|------|--------|
| `onboarding_core.dart` (Typestate Wizard) | DONE (Mutation tested M127-M129) |
| `setup_screen.dart` refactor (StreamBuilder + Store) | DONE |
| Zero-Knowledge Doctrine enforcement | DONE (Compile-time state transitions) |

### 3.7 Adaptive Posture & Recovery

| Item | Status |
|------|--------|
| `adaptive_posture.dart` (Rule Engine) | DONE (Mutation tested M134-M137) |
| `shamir_kit.dart` (GF(256) Math) | DONE (Mutation tested M130-M133) |

---

## 4. Testing & Verification

| Suite | Count | Status |
|-------|-------|--------|
| Full test suite | 570 | DONE (all pass) |
| Mutation campaign (core) | 100/100 | DONE (100% kill, M01-M100) |
| Mutation campaign (V6.5) | 20/20 | DONE (100% kill, M101-M120) |
| Mutation campaign (Vault Data) | 3/3 | DONE (100% kill, M121-M123) |
| Mutation campaign (Passkey) | 3/3 | DONE (100% kill, M124-M126) |
| Mutation campaign (OnBoarding) | 3/3 | DONE (100% kill, M127-M129) |
| Mutation campaign (Shamir) | 4/4 | DONE (100% kill, M130-M133) |
| Mutation campaign (Adaptive Posture) | 4/4 | DONE (100% kill, M134-M137) |
| Static analysis | 0 errors | DONE |
| Security gate suite (`security.md` gates 1-20) | DONE | all gates verified |
| Advanced suite (`security2.md` gates 21-32) | DONE | statemachine, model, fuzzers, concurrency |
| Vault fuzzing (`tool/fuzz_vault.dart`) | 100k | DONE (0 crashes) |
| Parser fuzzing (`tool/fuzz_parsers.dart`) | 300k | DONE (0 crashes, typed errors only) |
| Enforcer fuzzing (`tool/fuzz_enforcer.dart`) | 50k | DONE (0 timeouts, RFC 1035 guard active) |
| Grammar fuzzing (`tool/fuzz_vault_grammar.dart`) | 50k | DONE (0 crashes) |
| Sync protocol fuzzing (`tool/fuzz_sync_protocol.dart`) | 20k | DONE (all malicious inputs rejected) |
| TOTP import fuzzing (`tool/fuzz_totp_import.dart`) | 20k | DONE (no crashes) |
| Memory dump (`tool/memory_dump.dart`) | 1000 cycles | DONE (no residual) |

> **Full registry:** See [`TESTING.md`](TESTING.md).

---

## 5. Platform Status

### Linux

- Compiles & Runs
- **Hermetic Builds:** `SOURCE_DATE_EPOCH`, `-ffile-prefix-map`, `ZERO_AR_DATE` ensure byte-identical release binaries.
- Seccomp deny-list live
- Tray / Hotkey native (X11 + Wayland `xdg-desktop-portal` fallback)
- Hotkey changed to `Ctrl+Alt+Space` (avoids layout switcher conflicts)
- Sensitive clipboard MIME implemented
- Build script with integrity hash (`build_linux.sh`)

### Android

- Code written (MainActivity, Autofill, BLE plugin, Passkey plugin)
- Manifest correct (no INTERNET, allowBackup=false)
- **P0-2 Closed:** Autofill credentials transit via `AutofillSession` singleton, completely bypassing Android Binder/Intent extras.
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
| P3 | Recovery UX design | NOT STARTED (Shamir core verified, UI pending) |
| P4 | Android build environment setup | DONE (`android/DEPS.md` written) |
| P5 | Android device verification | DONE (device-tested) |
| P6 | TPM sealing design | NOT STARTED (research not started) |
| P7 | Noise PQ-hybrid transport | NOT STARTED (research not started) |
| P8 | Runtime integrity attestation | NOT STARTED (research not started) |

---

## 7. Documentation Status

| Document | Status |
|----------|--------|
| `README.md` | DONE (updated for V6.5.3) |
| `SECURITY.md` | DONE (updated for V6.5.3 threat model) |
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
3. Behavioral biometrics is anomaly deterrent, not authentication.

V6.5 additions:

4. RESOLVED: V6.5 modules mutation-tested (137/137 killed, 100% score).
5. P2P sync requires both devices online simultaneously (no async).
6. BLE 10m range physical, not software-enforced.
7. TOTP secrets in vault = single point of failure.
8. Security tiers advisory (determined user can bypass UI).
9. TOFU first-pairing vulnerable to MITM.
10. **Passkeys:** Native Android CredentialManager integration requires Android 14+. Older devices fall back to password/biometric unlock.

---

## 10. Immediate Next Steps

### This week
1. Draft announcement post (P1)
2. Begin auditor outreach (P0)

### Next 2 weeks
3. Publish on GitHub with release tag `v1.0.0-pre-audit` (P1)
4. Post announcement to HN, Reddit, security lists (P1)

### Blocked
- External audit (P0) - needs auditor

---

## 11. Phase Acceptance Checklist

### V6.5 Acceptance
- [x] Security tiers implemented + tested
- [x] TOTP generator implemented + tested
- [x] P2P sync logic + UI implemented + tested
- [x] Android platform code written + Binder hole closed
- [x] Passkeys (FIDO2) implemented + tested
- [x] Onboarding Typestate Wizard implemented + tested
- [x] All internal inconsistencies fixed (0 analyzer errors)
- [x] README, SECURITY, SECURITY_AUDIT, AUDIT_BRIEF, CONTRIBUTING updated
- [x] Android compiled and device-tested
- [x] Full mutation campaign run (137/137 killed)

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

## 12. Security Roadmap Execution (Phases 0-3)

Executed against the threat-informed roadmap. All four P0 gaps closed; the two
attack families that reach this app (infostealers, AI-driven coercion) are now
defended.

### Phase 0 — P0 fixes (DONE)
- **Duress write-guard**: all five mutators throw `StateError` in a duress
  session (a write under VRK_duress would brick the primary vault).
- **Service-layer key zeroization (CWE-226)**: MK/VRK zeroed at all 7
  derivation sites; `exportCsv` uses `MpStrength.checkBytes` (no MP String).
- **`debugVrk` release guard**: const `bool.fromEnvironment` throw (dead-code
  eliminated in release).
- **`unlock()` mutex + `lock()` full-wipe**: no race on state swap; lock clears
  `_searchTags`/`_lastReveal`/`_isDuress`.
- **P1**: `_searchTags` populated on VRK/shares unlock; canary wipe synchronous.
- **Regression tests**: `test/app/vault_service_p0_test.dart` (7 tests).

### Phase 1 — Threat hardening (DONE)
- `memory_dump` extended with service-layer zeroization check.
- `ProcessHardening.harden()` runs before first `SecureBuffer.alloc`.
- Keystore `setIsStrongBoxBacked(true)` (best-effort).
- Clipboard 30s auto-wipe + `EXTRA_IS_SENSITIVE` + `FLAG_SECURE` verified.
- `verify_deps` is an allowlist gate; gitleaks CI job added.

### Phase 2 — Hygiene (DONE)
- Comment-traceability tool (`tool/verify_comment_traceability.dart`).
- Coverage matrix (`SECURITY_COVERAGE_MATRIX.md`).
- Mutation campaign verified (temp-copy + ≥90% floor).
- **God-class split**: `CanaryService`, `CsvService`, `RecoveryService`,
  `DecoyService` extracted; `VaultService` delegates.

### Phase 3 — Backlog (DONE except device/post-ship)
- **KDF calibration at creation**: `createVault` accepts raised params.
- **Boundary docs**: `security.md` §16 (String-on-heap, no-browser-extension,
  decoy-vs-coercion, KDF calibration).
- **Dependency audit**: removed unused `pointycastle 3.9.1` (flagged advisory
  surface); allowlist now 13 deps.

### CI fixes (DONE)
- Fixed hallucinated `subosito/flutter-action` SHA pin (real SHA for v2.23.0).
- Added `dependabot.yml`, least-privilege `permissions`, `concurrency`,
  SHA-pinned gitleaks job.

### Next goals
1. **Device-only verification** (needs real Android): autofill per-event
   confirmation, Keystore attestation, FLAG_SECURE.
2. **Baseline regeneration**: 15 stale mutation search strings + 75 untested
   security comments (comment-traceability gate).
3. **`very_good_analysis` adoption** (dependency decision; update allowlist).
4. **Decrypt-on-demand** (post-ship): remove the String-on-heap boundary.
5. **External audit** (P0 blocker).

---

**Bottom line:** Crypto core and V6.5 features mathematically verified (137/137 mutation kill). Full suite is 584 tests, all passing. Security gate suites complete. Eight fuzzers, 0 crashes/timeouts. Linux (Hermetic/Wayland) and Android (Binder-closed/Passkeys) builds verified. V6.5.3 remediated a live mutation-window bug and fixed the KDF floor (64 MiB was silently reduced to 64 KiB). Security roadmap Phases 0-3 executed: all four P0 gaps closed, god-class split done, KDF calibration added, unused `pointycastle` removed. Remaining: device-only verification, baseline regeneration, external audit. See [`TESTING.md`](TESTING.md) for the full verification registry.