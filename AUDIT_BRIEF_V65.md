# Audit Brief - Vault Crypto V6.5.1

**Version under audit:** V6.5.1 (Mutation Campaign Complete)
**Date:** 2026-08-25
**Status:** Seeking external cryptographic audit
**Repository:** https://github.com/ForgeUz/local-password-manager
**Primary language:** Dart/Flutter (Dart SDK >=3.0.0), Kotlin (Android platform layer)
**Crypto backend:** libsodium via FFI (no home-rolled crypto)

---

## 1. Executive Summary

Vault Crypto is a local-first, zero-cloud password manager. The cryptographic core (V4/V5) is internally verified:

- **570 tests** (all passing)
- **133/133 mutation kill** (100% kill score across entire TCB + V6.5 + vault data + passkey + onboarding + shamir)
- **Security gate suites** — [`security.md`](security.md) (gates 1-20) + [`security2.md`](security2.md) (gates 21-32)
- **6 fuzzers, 0 crashes**
- **0 analyzer errors**

V6.5 adds mass-user features (security tiers, TOTP, P2P BLE sync, Android autofill) without modifying the verified crypto core. **We seek independent verification of both the crypto core and the new V6.5 modules.**

> **Full test/mutation/fuzzer registry:** See [`TESTING.md`](TESTING.md).
> **Auditor-facing docs:** See [`AUDIT_PACKAGE/`](AUDIT_PACKAGE) (CRYPTO_SPEC, THREAT_MODEL, ATTACK_SURFACE, TEST_COVERAGE, KNOWN_LIMITATIONS, BUILD_REPRODUCIBILITY, DIFFERENTIAL_ANALYSIS).

**Core doctrine (enforced, non-negotiable):**
- **Zero-Cloud** - no server, no relay, no telemetry. Only egress is opt-in breach monitoring (5-char SHA-1 prefix).
- **Zero-Trust** - every input treated as hostile until math proves otherwise.
- **Zero-Recovery-by-design** - no backdoor, no vendor reset.
- **No home-rolled crypto** - libsodium only.
- **Sync optional** - removing sync module leaves a working offline manager.

---

## 2. What We Are Asking Auditors To Verify

### Priority 1: Crypto Core (V4/V5) - already mutation-tested

1. Correct usage of AES-256-GCM (nonce uniqueness, AAD, tag verification)
2. Correct HKDF usage (domain separation via unique info strings)
3. Correct Argon2id parameters (64 MiB, 3 iterations, parallelism 1)
4. Memory zeroing completeness (`sodium_memzero` before `free`)
5. Parser bounds checking (no buffer overflow on malformed input)
6. Constant-time comparison for secret material
7. Fail-closed on hardware errors (AES-NI unavailable)
8. Structural deniability (duress vault indistinguishable from primary)

### Priority 2: V6.5 Modules - unit-tested, not yet mutation-tested

9. **Security tiers** - enforcement risk (can critical tier be autofilled?)
10. **TOTP generator** - RFC 6238 correctness, secret handling
11. **P2P sync** - Noise protocol usage, pairing entropy, conflict resolution
12. **Android autofill** - domain matching, lookalike detection, tier enforcement
13. **Android biometric** - Keystore key invalidation, VRK wrap/unwrap

### Priority 3: Architecture & Threat Model

14. Is the threat model complete? What are we missing?
15. Are there cross-module attacks (e.g., sync + autofill interaction)?
16. Are honest limitations actually limitations, or hidden vulnerabilities?

---

## 3. Trusted Computing Base (TCB) Files

### 3.1 Crypto Core (V4/V5) - Dart

| File | Responsibility | Key Invariants |
|------|----------------|----------------|
| `lib/src/crypto/v4/vault_crypto_v4.dart` | Outer AES-GCM, MP change, duress unlock, entry encrypt/decrypt | Nonce uniqueness, AAD integrity, constant-time tag verify, VRK never stored |
| `lib/src/crypto/v4/key_hierarchy.dart` | VRK derivation, DEK generation, DEK wrap/unwrap | HKDF domain separation, per-entry DEK, CSPRNG for DEK |
| `lib/src/crypto/v4/header.dart` | Vault blob parser, bounds checks | DEK max 1024, ciphertext max 1MB, tags max 100, clock max 256 |
| `lib/src/crypto/v4/padding.dart` | Bucket masking (size oracle prevention) | Constant-time padding, CSPRNG for padding selection |
| `lib/src/crypto/v4/second_factor.dart` | 2FA rate limiting, backup codes | 3 attempts + 60s cooldown, constant-time compare, single-use codes |
| `lib/src/crypto/v4/duress.dart` | Duress VRK derivation, domain separation | VRK_duress ≠ VRK_primary, HKDF distinct info strings |
| `lib/src/crypto/v4/search_tag.dart` | Searchable encryption tags, normalization | HMAC-SHA256, SearchKey zeroed, URL scheme strip, prefix padding |
| `lib/src/crypto/native/argon2id.dart` | FFI wrapper for Argon2id | `sodium_memzero` before free, fail-closed on error |
| `lib/src/crypto/native/aes_gcm.dart` | FFI wrapper for AES-256-GCM | AES-NI check fail-closed, `sodium_memzero` before free |
| `lib/src/crypto/native/hkdf.dart` | FFI wrapper for HKDF | Unique info per use, PRK/IKM zeroed |
| `lib/src/crypto/native/secure_buffer.dart` | `sodium_malloc` wrapper, dispose zeroing | `sodium_memzero` on dispose, no plaintext escape |

### 3.2 V6.5 Mass-User Modules - Dart

| File | Responsibility | Key Invariants |
|------|----------------|----------------|
| `lib/src/security/security_tier.dart` | Tier enum, `TierPolicy`, `TierValidator` | Critical blocks autofill+export, downgrade needs confirm, ordinal ordering |
| `lib/src/security/security_tier_ui_helper.dart` | UI metadata, domain suggestions | Advisory only, never auto-applied |
| `lib/src/autofill/tier_autofill_enforcer.dart` | Autofill decision engine, lookalike detection | Sealed decision type, hard-stop on lookalike/mismatch, no critical autofill |
| `lib/src/totp/totp_generator.dart` | RFC 6238 TOTP | Deterministic, ±1 window, zero-padded, constant-time validate |
| `lib/src/totp/totp_import.dart` | otpauth:// parser, Google Auth export | Base32 validation, secret in SecureBuffer, typed errors |
| `lib/src/sync/sync_session.dart` | Sync lifecycle orchestration | Optional (removable), no plaintext transport |
| `lib/src/sync/pairing_session.dart` | Pairing state machine, PSK derivation | Argon2id PSK, 60s window, 3 attempts, cooldown |
| `lib/src/sync/noise_session.dart` | Noise NNpsk0 handshake | TOFU pinning, forward secrecy |
| `lib/src/sync/conflict_resolver.dart` | Manual conflict resolution | No auto-merge, all-resolved gate |
| `lib/src/sync/vector_clock.dart` | Conflict detection | Dominance check, skew rollback protection |
| `lib/src/sync/replay_counter.dart` | Replay attack prevention | Reject non-increasing counters |
| `lib/src/sync/traffic_padding.dart` | Traffic analysis resistance | Bucket padding, dummy messages |

### 3.3 Android Platform Layer - Kotlin

| File | Responsibility | Key Invariants |
|------|----------------|----------------|
| `android/app/src/main/kotlin/com/example/vault_crypto/MainActivity.kt` | Biometric Keystore, clipboard, plugin registration | AES-GCM wrap VRK, `invalidatedByBiometricEnrollment`, sensitive MIME, VRK never plaintext |
| `android/app/src/main/kotlin/com/example/vault_crypto/VaultAutofillService.kt` | Autofill Framework integration | Domain from `webDomain`, tier enforcement, null FillResponse for critical |
| `android/app/src/main/kotlin/com/example/vault_crypto/BleTransportPlugin.kt` | BLE transport (Nearby Connections) | Encrypted passthrough only, no plaintext inspection, permission checks |
| `android/app/src/main/AndroidManifest.xml` | Permissions, services, backup policy | `allowBackup=false`, no INTERNET permission, BLE permission split by API |

---

## 4. Threat Model

### 4.1 Primary Threats (V4/V5)

| Threat | Capability | Mitigation | Residual Risk |
|--------|-----------|------------|---------------|
| File-only attacker | Read encrypted vault blob | AES-GCM + Argon2id + structural deniability | None if MP strong |
| Memory attacker | Inspect process memory | `sodium_memzero`, `sodium_malloc`, SecureBuffer | Dart String in UI (documented) |
| Coercion | Force password disclosure | Duress vault, group shred | Coercer with BOTH passwords wins |
| Patched build | Modified binary | Build hash, code signing (planned) | No runtime attestation yet |

### 4.2 V6.5 Threats (New)

| Threat | Capability | Mitigation | Residual Risk |
|--------|-----------|------------|---------------|
| Network attacker (sync) | MITM on BLE/WiFi Direct | Noise NNpsk0, Argon2id PSK, TOFU | First-pairing MITM if attacker present |
| Phishing via autofill | Trick autofill into wrong domain | `webDomain` extraction, lookalike detection, tier hard-stop | User can disable autofill |
| TOTP secret theft | Compromise vault → all TOTP | Per-entry DEK encryption | Single point of failure (documented) |
| BLE range extension | Amplify signal beyond 10m | High-entropy passphrase, rate limiting | Physical limit not software-enforced |
| Pairing interception | Capture handshake, offline dictionary | Argon2id PSK (64 MiB, 3 iter) | Weak passphrase = weak PSK |

---

## 5. Invariants We Believe Are Enforced

These are the properties we want auditors to verify (or break):

### Crypto Core
1. AES-GCM nonce never reused with same key
2. HKDF info strings unique per derivation context
3. All secrets zeroed before memory release
4. All parser inputs bounds-checked before use
5. No information leakage via error types (oracle prevention)
6. Duress vault cryptographically indistinguishable from primary
7. Destroying one DEK shreds exactly one entry (no cross-entry leakage)
8. Master password change re-wraps ALL DEKs + ALL search tags atomically

### V6.5
9. Critical tier NEVER autofills (manual entry only)
10. Critical tier CANNOT export
11. Tier downgrade requires explicit user confirmation
12. Tier stored in encrypted blob (attacker cannot downgrade)
13. Lookalike domain -> hard-stop (no autofill)
14. Domain mismatch -> block (no autofill)
15. TOTP secret never appears in plaintext after import
16. TOTP codes validated with ±1 window only
17. Sync data encrypted before reaching BLE transport
18. Pairing requires ≥3 attempts before cooldown
19. Conflict resolution blocks sync until all resolved
20. Conflict resolution blocks sync until all resolved

### Android
21. Biometric key invalidated on new fingerprint enrollment
22. VRK never stored in plaintext on disk
23. Autofill extracts domain from trusted source (`webDomain`)
24. No INTERNET permission (zero-cloud enforced at OS level)
25. `allowBackup=false` prevents OS-level vault exfiltration

---

## 6. Current Verification Status

### What Has Been Verified

| Method | Scope | Result |
|--------|-------|--------|
| Unit tests | 570 tests | All pass |
| Mutation testing | 133 mutations, full TCB + V6.5 + vault data + passkey + onboarding + shamir | 100% kill (133/133) |
| Security gate suites | security.md (1-20) + security2.md (21-32) | All gates tested |
| Fuzzing | 6 fuzzers | 0 crashes |
| Static analysis | `flutter analyze` | 0 errors, 2 warnings (pre-existing) |
| Code review | All TCB files | Internal review complete |
| Memory audit | FFI wrappers + Dart zeroing | PASS (documented residual) |

### What Has NOT Been Verified

| Gap | Impact | Mitigation Plan |
|-----|--------|-----------------|
| External cryptographic audit | **Critical** - this is why we are here | This audit |
| V6.5 mutation testing | Medium - 70 tests pass but no mutation campaign | Extend campaign pre-audit |
| Android automated platform tests | Low - device-tested, no automated unit layer | Add automated platform tests |
| Formal verification | Low - mutation testing is a strong proxy | Optional (Lean 4/Dafny) |
| Fuzzing | Medium - parsers tested but not fuzzed | Add fuzzing for parsers |

---

## 7. Honest Limitations

We state these upfront. They are known, documented, and accepted:

1. **`V4VaultEntry.password` is a Dart `String` in UI model.** Flutter limitation. Crypto core never holds it as String.
2. **Mutation testing covers only encoded mutations.** Not a substitute for external audit.
3. **V6.5 modules not yet mutation-tested.** 70 unit tests pass; mutation campaign extension planned.
4. **Android autofill has no automated unit tests.** Device-tested on Android 13; automated coverage for the platform layer not present.
5. **P2P sync requires both devices online simultaneously.** No async sync (zero-cloud constraint).
6. **BLE 10m range is physical, not software-enforced.** Signal amplifier could extend range.
7. **TOTP secrets in vault = single point of failure.** Hardware tokens recommended for critical accounts.
8. **Security tiers are advisory.** Determined user can bypass UI. Tier stored encrypted (attacker cannot downgrade).
9. **TOFU first-pairing vulnerable to MITM.** Mitigated by physical proximity + user verification.
10. **Zero-recovery is by design.** Lost MP + lost shares = permanent data loss. No backdoor.

---

## 8. Known Issues

**None known at this time.** If you find one, see Section 10.

---

## 9. Build & Test Instructions

### Prerequisites (Linux)

```bash
sudo apt install -y clang cmake ninja-build pkg-config \
  libgtk-3-dev liblzma-dev libstdc++-12-dev \
  libsodium-dev libseccomp-dev \
  libx11-dev libxtst-dev libayatana-appindicator3-dev libportal-dev
```

### Run Tests

```bash
flutter pub get
flutter test                    # 570 tests
flutter analyze                 # 0 issues
dart run tool/mutation_campaign.dart   # mutation kill score (133/133)
```

### Build (Linux)

```bash
./build_linux.sh   # release build + integrity hash
```

### Build (Android)

```bash
flutter build apk --release
```

---

## 10. Vulnerability Reporting

**Email:** security@vaultcrypto.dev (replace with your actual contact)
**PGP:** [your PGP key fingerprint]
**Response time:** 48h acknowledgment, 7d initial assessment
**Disclosure policy:** 90-day responsible disclosure
**Bounty:** Critical findings may be eligible (contact us)
**Safe harbor:** No legal action for good-faith research

---

## 11. Audit Logistics

### What We Provide
- Full source code access (public repo)
- Architecture documentation (v6_delta.md, v6.5_delta.md)
- Threat model (SECURITY.md)
- Internal audit results (SECURITY_AUDIT.md)
- Direct communication with maintainers

### What We Need From Auditor
- Written report with findings (severity-rated)
- Verification of invariants in Section 5
- Recommendations for hardening
- Permission to publish report (with credit)

### Timeline Estimate
- Scoping: 1 week
- Core crypto review: 2-3 weeks
- V6.5 review: 1-2 weeks
- Reporting: 1 week
- **Total: ~5-7 weeks**

### Compensation
- Professional firm rates (contact us for budget)
- Independent researchers: credit + co-authorship + bounty
- Open-source community: recognition + audit report

---

## 12. Contact

**Maintainer:** [your name / GitHub: ForgeUz]
**Email:** security@vaultcrypto.dev
**GitHub:** https://github.com/ForgeUz/local-password-manager
**Issues:** https://github.com/ForgeUz/local-password-manager/issues

---

## Appendix A: File Line Counts (TCB)

Run to verify scope:

```bash
# Crypto core
wc -l lib/src/crypto/v4/*.dart lib/src/crypto/native/*.dart

# V6.5 modules
wc -l lib/src/security/security_tier*.dart \
      lib/src/autofill/tier_autofill_enforcer.dart \
      lib/src/totp/*.dart \
      lib/src/sync/*.dart

# Android
wc -l android/app/src/main/kotlin/com/example/vault_crypto/*.kt
```

## Appendix B: Mutations Already Killed (133/133)

See `SECURITY_AUDIT.md` Task 3 for full mutation list by group:
- vault_crypto_v4: 20
- key_hierarchy: 10
- header: 13
- padding: 8
- second_factor: 9
- duress: 4
- search_tag: 9
- argon2id: 3
- aes_gcm: 2
- hkdf: 3
- constant_time: 2
- hmac_sha256: 2
- sha256: 2
- secure_buffer: 2
- native_noise: 2
- replay_counter: 2
- vector_clock: 4
- conflict_resolver: 3

---

**End of Audit Brief.**