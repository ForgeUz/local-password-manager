# Vault Crypto Security Verification Plan

**Current Status:** Internal Audit Complete (137/137 Mutations Killed, 570 Tests, 8 Fuzzers)
**Last Updated:** V6.5.3

## 1. Cryptographic Core Invariants

### 1.1 Argon2id KDF

```
File: lib/src/crypto/native/argon2id.dart
Test file: test/security/crypto/test_argon2id.dart

VERIFY:
[x] Output length is exactly 32 bytes (256 bits)
[x] Parameters: memory_cost = 65536 (64 MiB), time_cost = 3, parallelism = 1
[x] Same input (password + salt) → identical output (determinism)
[x] Different salt → completely different output (avalanche)
[x] Different password → completely different output
[x] Salt is 16+ bytes, cryptographically random
[x] No hardcoded salt or password in test vectors
[x] FFI wrapper correctly passes parameters to libsodium
[x] FFI wrapper zeroes password buffer after use (sodium_memzero)
[x] FFI wrapper zeroes salt buffer after use
[x] FFI wrapper zeroes output buffer when disposed
[x] Function throws on empty password
[x] Function throws on empty salt
[x] Function throws on invalid parameters

METHOD:
- Property-based testing with 10,000 random password/salt pairs
- Verify determinism by running same input 1000 times
- Verify avalanche effect: flip 1 bit in password, compare outputs
- Manual FFI review: check calloc/free, sodium_memzero calls
```

### 1.2 AES-256-GCM Encryption/Decryption

```
File: lib/src/crypto/native/aes_gcm.dart
Test file: test/security/crypto/test_aes_gcm.dart

VERIFY:
[x] Uses crypto_aead_aes256gcm_encrypt from libsodium (not custom AES)
[x] Key is exactly 32 bytes
[x] Nonce is exactly 12 bytes
[x] Nonce is cryptographically random (never counter-based)
[x] Nonce is NEVER reused with same key (verify with nonce tracking)
[x] Authenticated data (AAD) is used where appropriate (GEN4 header MAC)
[x] Encryption adds 16-byte tag to ciphertext
[x] Decryption fails on tampered ciphertext (authentication)
[x] Decryption fails on tampered tag
[x] Decryption fails on tampered AAD
[x] Decryption fails on truncated ciphertext
[x] Decryption fails on extended ciphertext
[x] Error messages are uniform (no oracle about what failed)
[x] AES-NI availability check implemented (crypto_aead_aes256gcm_is_available)
[x] Fail-closed when AES-NI unavailable
[x] FFI wrapper zeroes key buffer after use
[x] FFI wrapper zeroes plaintext buffer after use
[x] FFI wrapper zeroes ciphertext buffer after use
[x] FFI wrapper zeroes decrypted output when disposed
```

### 1.3 HKDF Key Derivation

```
File: lib/src/crypto/native/hkdf.dart
Test file: test/security/crypto/test_hkdf.dart

VERIFY:
[x] Uses HMAC-SHA-256 as PRF (not SHA-1)
[x] Salt is 32 bytes minimum
[x] IKM (Input Keying Material) is zeroed after use
[x] PRK (Pseudo-Random Key) is zeroed after use
[x] Output key length is 32 bytes
[x] Domain separation info strings are unique and unambiguous
[x] Info string for VRK derivation: "vault-crypto/v4/vrk"
[x] Info string for DEK wrap key: "vault-crypto/v4/dek-wrap"
[x] Info string for search key: "vault-crypto/v4/search"
[x] Info string for TOTP sealing: "vault-crypto/v4/totp-seal"
[x] Different info strings produce completely different outputs
[x] Info strings do not prefix-collide
```

### 1.4 Key Hierarchy (VRK → DEK)

```
File: lib/src/crypto/v4/key_hierarchy.dart
Test file: test/security/crypto/test_key_hierarchy.dart

VERIFY:
[x] VRK derived from MK via HKDF with domain separation
[x] Each DEK is independently generated CSPRNG (not derived from VRK)
[x] DEK is wrapped (encrypted) under VRK using AES-256-GCM
[x] DEK unwrap: decrypt with VRK → verify auth tag → return DEK
[x] DEK is 32 bytes
[x] DEK wrap uses unique nonce for each encryption
[x] Destroying VRK makes all DEKs unrecoverable
[x] IKM (MK || TOTP) is zeroed after VRK derivation
[x] VRK is stored in SecureBuffer, never as Dart Uint8List
```

### 1.5 Nonce Management

```
Files: lib/src/crypto/native/aes_gcm.dart, all files using AES-GCM

VERIFY:
[x] No two encryptions under same key use same nonce
[x] Nonce generation uses Sodium.randombytes_buf (CSPRNG)
[x] Nonce is never derived from counter or timestamp
[x] Nonce is never hardcoded
[x] Nonce collision probability < 2^-32 for 10^9 operations (birthday bound)
```

---

## 2. File Format Security (GEN4)

### 2.1 Format Parsing & DoS Resistance

```
File: lib/src/crypto/v4/header.dart
Test file: test/security/format/test_gen4_parser.dart
Fuzzer: tool/fuzz_parsers.dart

VERIFY:
[x] Parser handles files of size 0 bytes
[x] Parser handles truncated header
[x] Parser handles header with length fields exceeding file size
[x] Parser always throws CorruptBlobError (not FormatException, RangeError, etc.)
[x] Parser never accesses memory out of bounds (checkBounds helper)
[x] Sanity limits enforced: DEK < 1024B, Ciphertext < 1MB, Tags < 100, VC < 256B
[x] 100,000 random byte sequences parsed with 0 crashes
[x] 100,000 mutated byte sequences parsed with 0 crashes
```

### 2.2 Decoy Vault

```
File: lib/src/crypto/v4/vault_crypto_v4.dart (decoy logic)
Test file: test/security/format/test_decoy.dart

VERIFY:
[x] Decoy vault uses completely different key derivation path
[x] Primary password cannot open decoy vault
[x] Decoy password cannot open primary vault
[x] Decoy vault has identical file structure to primary (indistinguishable)
[x] Decoy vault is stored in same file, not separate file (Slot 2)
[x] Error messages for wrong password are identical for both vaults
```

---

## 3. Memory Safety

### 3.1 SecureBuffer Usage

```
File: lib/src/crypto/native/secure_buffer.dart
Test file: test/security/memory/test_secure_buffer.dart

VERIFY:
[x] SecureBuffer.alloc() uses sodium_malloc (not calloc directly)
[x] SecureBuffer.dispose() calls sodium_memzero
[x] SecureBuffer.dispose() is idempotent (safe to call twice)
[x] SecureBuffer.dispose() frees native memory
[x] SecureBuffer does not implement toString() (no accidental logging)
[x] All crypto operations accept SecureBuffer, not Uint8List
```

### 3.2 Secret Zeroing

```
Files: All files in lib/src/crypto/, lib/src/vault/
Test file: test/security/memory/test_zeroing.dart

VERIFY EVERY SECRET IS ZEROED:
[x] Master Password: SecureBuffer.zero() called on lock
[x] MK (Argon2id): password/salt/output buffers zeroed via FFI
[x] VRK: zeroed on lock, zeroed on dispose
[x] DEK: zeroed after wrapping, zeroed after unwrapping and use
[x] TOTP Secret: zeroed after KDF folding
[x] Search Key: zeroed after tag generation
```

---

## 4. Authentication Flows

### 4.1 Master Password Verification

```
File: lib/src/crypto/v4/vault_crypto_v4.dart (unlock path)
Test file: test/security/auth/test_master_password.dart

VERIFY:
[x] Password comparison uses constant-time algorithm
[x] Failed verification time equals successful verification time (±5%)
[x] Rate limiting on failed attempts (exponential backoff via BackoffCalculator)
[x] No information leaked in error messages (wrong password vs corrupt vault)
```

### 4.2 TOTP Integration

```
File: lib/src/totp/totp_generator.dart, lib/src/totp/totp_import.dart
Test file: test/security/auth/test_totp.dart
Fuzzer: tool/fuzz_totp_import.dart

VERIFY:
[x] TOTP is folded into KDF (mathematically affects key derivation)
[x] TOTP verification is constant-time (no early exit, M118 verified)
[x] TOTP window tolerance: ±1 time step (30 seconds, M117 verified)
[x] Codes zero-padded to exact digit count (M116 verified)
[x] Dynamic truncation uses last-byte offset (M115 verified)
[x] Malformed otpauth:// URIs handled without crashes (20k fuzz iterations)
```

### 4.3 Biometric Authentication

```
File: android/app/src/main/kotlin/.../MainActivity.kt
Test file: test/security/auth/test_biometric.dart

VERIFY:
[x] Biometric prompt uses BiometricPrompt API (not deprecated)
[x] Biometric authentication gates crypto operation (VRK retrieval), not just UI
[x] Biometric failure does not lock vault (fallback to password)
[x] FLAG_SECURE set on biometric prompt (no screenshots)
```

### 4.4 FIDO2/WebAuthn Passkeys (P3)

```
File: lib/src/passkey/passkey_core.dart, passkey_challenge.dart, passkey_platform.dart
Test file: test/passkey/passkey_core_test.dart, passkey_challenge_test.dart

VERIFY:
[x] Challenge generates >= 32 bytes of CSPRNG entropy (M124 verified)
[x] Challenge strictly base64url encoded without padding (M125 verified)
[x] verifyRpId enforces exact domain match, preventing cross-domain phishing (M126 verified)
[x] Private keys NEVER leave hardware-backed Keystore (Android CredentialManager)
[x] VaultEntry schema safely evolves with optional passkeyCredentialId (M121-M123 verified)
```

---

## 5. Duress Vault Security

```
File: lib/src/coercion/decoy_vault.dart
Test file: test/security/duress/test_duress.dart

VERIFY:
[x] Duress password produces different VRK than primary password
[x] Duress vault is cryptographically isolated from primary
[x] Domain separation: different HKDF info string for duress
[x] Duress vault contains realistic-looking entries (Canaries)
[x] UI does not reveal duress mechanism (no hints, no visual differences)
```

---

## 6. P2P Sync Security

### 6.1 Noise Protocol Handshake

```
File: lib/src/sync/noise_session.dart
Test file: test/security/sync/test_noise.dart

VERIFY:
[x] Noise NNpsk0 pattern implemented correctly
[x] Pre-shared key (PSK) derived via Argon2id(passphrase, salt, 64MiB, 3 iterations)
[x] TOFU (Trust-On-First-Use) pinning implemented for subsequent connections
[x] 60-second pairing window enforced
[x] Maximum 3 pairing attempts before cooldown
```

### 6.2 Replay Prevention & Conflict Resolution

```
File: lib/src/sync/replay_counter.dart, lib/src/sync/vector_clock.dart
Test file: test/security/sync/test_replay.dart

VERIFY:
[x] Vector clock detects concurrent modifications
[x] Replay counter increments monotonically
[x] Duplicate messages rejected
[x] Conflict detection triggers manual resolution (no auto-merge)
```

---

## 7. Android-Specific Security

### 7.1 Autofill Service & Binder Transit

```
File: android/app/src/main/kotlin/.../VaultAutofillService.kt, AutofillSession.kt
Test file: test/security/android/test_autofill.dart

VERIFY:
[x] Domain extracted from AssistStructure.webDomain (trusted source)
[x] Lookalike detection: homoglyph, edit distance ≤1, subdomain impersonation
[x] RFC 1035 domain length guard (253 chars) prevents algorithmic DoS
[x] Critical tier entries NEVER autofill (hard stop)
[x] P0-2 CLOSED: Credentials transit via AutofillSession singleton, completely bypassing Android Binder/Intent extras (no plaintext leaks).
```

### 7.2 Manifest Security

```
File: android/app/src/main/AndroidManifest.xml

VERIFY:
[x] allowBackup="false" (prevents Android auto-backup to Google Drive)
[x] No INTERNET permission (Zero-Cloud enforced)
[x] FLAG_SECURE set on all activities (prevents screenshots)
```

---

## 8. Search Functionality (SSE)

```
File: lib/src/crypto/v4/search_tag.dart
Test file: test/security/search/test_sse.dart

VERIFY:
[x] Search tags use Searchable Symmetric Encryption (SSE)
[x] Search tags never decrypt domain during search
[x] URL normalization: strips http://, https://, ftp://
[x] Minimum query length: 3 characters
[x] Search key is zeroed after use
```

---

## 9. Recovery Mechanisms

### 9.1 Shamir Secret Sharing

```
File: lib/src/security/shamir_kit.dart
Test file: test/security/shamir_kit_test.dart

VERIFY:
[x] Uses standard Shamir Secret Sharing scheme over GF(256)
[x] GF(256) multiplication reduction mod 0x11b (M130 verified)
[x] Lagrange basis uses GF division (M131 verified)
[x] Horner evaluation uses XOR (M132 verified)
[x] Fermat inverse uses exponent 254 (M133 verified)
[x] Threshold K of N shares reconstruct secret
[x] K-1 shares reveal NOTHING about secret
```

---

## 10. Adaptive Posture & Onboarding

### 10.1 Adaptive Posture Rule Engine

```
File: lib/src/security/adaptive_posture.dart
Test file: test/security/adaptive_posture_test.dart

VERIFY:
[x] Canary triggered -> lockdown (priority override) (M134 verified)
[x] Failure threshold >= 2 escalates to high (M135 verified)
[x] Unknown network escalates ONLY when strictRoamingEnabled (M136 verified)
[x] High posture -> autoLockTimeout = 30 seconds (M137 verified)
```

### 10.2 Typestate Onboarding

```
File: lib/src/onboarding/onboarding_core.dart
Test file: test/onboarding/onboarding_core_test.dart

VERIFY:
[x] Cannot bypass Doctrine (Zero-Knowledge warning) (M127 verified)
[x] SubmitMP stores the SecureBuffer (M128 verified)
[x] GoBack from CreateMP wipes MP reference (memory leak prevention) (M129 verified)
```

---

## 11. Clipboard & OS Integration

### 11.1 Clipboard Security

```
File: lib/src/clipboard/native_clipboard.dart, linux/runner/desktop_plugin.cc

VERIFY:
[x] Clipboard cleared after 30-second timeout
[x] Clipboard cleared on vault lock
[x] Sensitive MIME type set: text/plain;charset=utf-8;sensitive=true
```

### 11.2 Linux Desktop Integration

```
File: linux/runner/desktop_plugin.cc

VERIFY:
[x] Global hotkey uses X11 XGrabKey with NumLock/CapsLock variants
[x] Wayland fallback uses org.freedesktop.portal.GlobalShortcuts via GDBus
[x] Hotkey trigger changed to Ctrl+Alt+Space (avoids layout switcher conflicts)
```

### 11.3 Hermetic & Reproducible Builds

```
File: build_linux.sh, linux/CMakeLists.txt

VERIFY:
[x] SOURCE_DATE_EPOCH pins build time to last git commit
[x] -ffile-prefix-map strips absolute build paths from DWARF debug info
[x] ZERO_AR_DATE=1 ensures deterministic ar archive timestamps
[x] Two consecutive builds produce byte-identical ELF binaries
```

---

## 12. Fuzzing Campaign Results

| Fuzzer | Iterations | Crashes | Timeouts | Status |
|--------|------------|---------|----------|--------|
| `tool/fuzz_vault.dart` | 100,000 | 0 | 0 | DONE |
| `tool/fuzz_parsers.dart` | 300,000 | 0 | 0 | DONE |
| `tool/fuzz_enforcer.dart` | 50,000 | 0 | 0 | DONE |
| `tool/fuzz_vault_grammar.dart` | 50,000 | 0 | 0 | DONE |
| `tool/fuzz_sync_protocol.dart` | 20,000 | 0 | 0 | DONE |
| `tool/fuzz_totp_import.dart` | 20,000 | 0 | 0 | DONE |

---

## 13. Mutation Testing Campaign Results

**Total Mutations:** 137
**Kill Score:** 100% (137/137 Killed)

| Group | Mutations | Status |
|-------|-----------|--------|
| Core TCB (M01-M100) | 100/100 | KILLED |
| V6.5 Features (M101-M120) | 20/20 | KILLED |
| Vault Data Schema (M121-M123) | 3/3 | KILLED |
| Passkey Core (M124-M126) | 3/3 | KILLED |
| Onboarding Typestate (M127-M129) | 3/3 | KILLED |
| Shamir GF(256) Math (M130-M133) | 4/4 | KILLED |
| Adaptive Posture (M134-M137) | 4/4 | KILLED |

---

## 14. Threat Model Verification

**T1: Attacker steals vault file**
- [x] Cannot decrypt without master password
- [x] Cannot determine vault contents from file structure
- [x] Cannot distinguish primary from decoy vault

**T2: Attacker has physical access to unlocked device**
- [x] Vault auto-locks after inactivity (Adaptive Posture timeout)
- [x] Memory dump reveals no useful secrets (SecureBuffer zeroing)
- [x] Screenshots blocked (FLAG_SECURE)

**T3: Malware on device**
- [x] Seccomp blocks ptrace, process_vm_readv (Linux)
- [x] Vault file encrypted at rest
- [x] Autofill credentials bypass Binder transit (P0-2 closed)

**T4: Network attacker (for sync)**
- [x] All sync traffic encrypted (Noise Protocol)
- [x] TOFU prevents MITM after first connection

**T5: Coercion attack**
- [x] Duress vault provides plausible denial
- [x] Cannot prove existence of primary vault

---

## 15. Honest Limitations (Documented)

1. `V4VaultEntry.password` is Dart `String` in UI model (Flutter limitation). Crypto core never holds it as String.
2. Mutation testing covers only encoded mutations. Not a substitute for external audit.
3. Wayland global-shortcut portal requires user to grant permission in OS settings.
4. P2P sync requires both devices online simultaneously (no async).
5. BLE 10m range physical, not software-enforced.
6. TOFU first-pairing vulnerable to MITM.
7. Native Android CredentialManager (Passkeys) requires Android 14+.

---

## 16. Accepted Security Boundaries (Part III / Phase 3.2)

These are deliberate, documented trade-offs — not hidden gaps. Each is the
"line" the design draws, and each is enforced by a test or tool.

### 16.1 String-on-heap boundary (post-unlock entry passwords)

**Accepted trade-off:** after unlock, entry passwords are immutable Dart
`String`s in the UI model. They persist until non-deterministic GC, and a
memory dump of an *unlocked* session reveals them. This is the honest boundary:
KDF + at-rest encryption + process hardening (`PR_SET_DUMPABLE=0`, `mlockall`,
seccomp) + `SecureBuffer` for key material is the line. The crypto core never
holds a password as a `String`; only the UI model does.

**Mitigations in place:** `SecureBuffer` for VRK/MK; service-layer key
zeroization (CWE-226, Part II item 2); `memory_dump` CI gate.

**Backlog:** decrypt-on-demand (Phase 3.4) would remove this limitation by
decrypting a single entry into secure memory on reveal and wiping it after.

### 16.2 No-browser-extension boundary

**Structural advantage:** this app is NOT a browser extension. The 2025
autofill clickjacking zero-day (1Password/Bitwarden/Dashlane/Keeper/LastPass)
and browser-credential-store harvesting by infostealers are structurally
inapplicable. Credentials live only in the encrypted local blob.

**Rule:** never add a browser extension without per-domain user confirmation on
first fill. If one is ever added, it must go through the dependency-addition
protocol (Part III-C) and the autofill per-event confirmation flow.

### 16.3 Decoy-vault-vs-coercion threat model

**The decoy vault is the counter-weapon against AI deepfake vishing.** Under
coercion, the user surrenders the duress MP; the coercer gets a plausible fake
vault; the primary stays safe. The write-guard (Part II item 1) makes the
coercer's follow-up demand ("add an entry to prove it's real") safe instead of
catastrophic: a duress session is read-only, so a write cannot relock the
primary region under VRK_duress.

**Layers:** duress write-guard (test `duress session is read-only`), risk-tier
re-auth (Critical demands a fresh MP even mid-session), canary alarms (any
honeypot access locks + flags lockdown).

### 16.4 KDF calibration at creation

`createVault` accepts `kdfMemory`/`kdfIterations`/`kdfParallelism` above the
floor (Phase 3.1). The header records the actual params so unlock/reauth/
export/shares re-derive them consistently. Defaults to the floor (64 MiB / 3
iterations) for compatibility. Enforced by test `KDF calibration at creation`.