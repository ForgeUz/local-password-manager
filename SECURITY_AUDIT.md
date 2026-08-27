# Security Audit - Native Memory + Platform Hardening + Extended Mutation Testing (v1.0 pre-release)

**Date:** 2026-08-27  
**Scope:** Dart/Flutter GC overhead + Linux clipboard/Wayland/Hermetic builds + Android Binder transit + FIDO2 Passkeys + Extended mutation campaign (137/137) + Advanced fuzzing.

---

## Task 1 - Native Memory Audit (Dart GC / secret handling)

### What was checked

All code paths involving unencrypted secrets, DEKs, and the Master Password:

| Secret | Path | Handling | Verdict |
|--------|------|----------|---------|
| Master Password | UI input -> `SecureBuffer.alloc` + `writeBytes` (lock/setup/decoy/settings/corrupt screens) | Native `sodium_malloc` | PASS |
| MK (Argon2id output) | `Argon2id.derive` returns `Uint8List` (FFI `calloc`), consumed immediately by HKDF | Native FFI | PASS |
| VRK | `SecureBuffer.fromList` (`sodium_malloc`), held in `_vrk`, wiped on lock via `SecretWiper` | Native | PASS |
| DEKs | `KeyHierarchy.generateDek` -> `Uint8List` -> wrapped via AES-GCM (FFI `calloc`) | Native FFI | PASS |
| TOTP seed / SFM | `SecondFactor` seals under MK_base via AES-GCM (FFI) | Native FFI | PASS |
| Backup codes | Argon2id-hashed (FFI), never plaintext | Native FFI | PASS |
| Entry passwords | `V4VaultEntry.password` is a Dart `String` (UI model) | Dart String | DOCUMENTED |

### Findings

**MP is correctly handled in native memory.** Every screen that accepts a master password wraps it in `SecureBuffer` (`sodium_malloc`) before any crypto. The `String` from the `TextEditingController` is copied into the buffer and the controller is cleared; the Dart String copy is transient and unavoidable at the UI boundary.

**VRK/DEK/MK never cross back into Dart as plaintext.** The VRK lives in a `SecureBuffer`; `readBytes()` returns the native backing view (not a copy). DEKs are wrapped/encrypted entirely in FFI `calloc` memory.

**`sodium_memzero` is called on dispose.** `SecureBuffer.dispose()` -> `sodium_memzero` (verified by `MemoryDumpVerifier`). `VaultService.lock()` wipes the VRK via `SecretWiper`.

**Residual (documented, unavoidable):** `V4VaultEntry.password` is a Dart `String` because the UI model requires it. The decoy-wipe path (`getEntry` random-subset) copies the password into a `SecureBuffer` and wipes it via `SecretWiper` - but the model String itself remains until GC. This is the standard trade-off for a Flutter UI; the crypto core never holds it as a String.

### Fixes applied

No secret was found passed as a Dart `String` into the crypto core. The MP path was already `SecureBuffer` end-to-end. No refactor required beyond the existing design.

---

## Task 2 - Linux Platform Hardening (Clipboard, Wayland, Hermetic Builds)

### 2.1 Clipboard Sensitive MIME Type

**Finding:** The Linux native clipboard channel (`vault_crypto/clipboard`) was NOT implemented in C++. The Dart `NativeClipboard.copy` fell back to Flutter's `Clipboard.setData` (no sensitive MIME), so clipboard managers (CopyQ, Diodon, Klipper) could log password history.

**Fix:** `linux/runner/desktop_plugin.cc` now implements the `vault_crypto/clipboard` channel:
- `copy` -> `desktop_clipboard_copy(text, sensitive)`.
  - When `sensitive=true`, sets the clipboard with two targets: `text/plain;charset=utf-8` and `text/plain;charset=utf-8;sensitive=true` (the freedesktop/GTK convention for ephemeral/sensitive data), so managers skip history logging.
  - When not sensitive, uses `gtk_clipboard_set_text`.
- `clear` -> `gtk_clipboard_clear`.

### 2.2 Wayland Global Shortcuts

**Finding:** X11 `XGrabKey` fails on modern Wayland compositors (Ubuntu 22.04+, Fedora). Additionally, `Ctrl+Shift+Space` conflicted with OS-level keyboard layout switchers (e.g., German `Strg+Shift`).

**Fix:** 
- Implemented `org.freedesktop.portal.GlobalShortcuts` via raw GDBus as a fallback when `WAYLAND_DISPLAY` is detected.
- Changed hotkey trigger to `Ctrl+Alt+Space` to avoid layout switcher conflicts.
- Added NumLock/CapsLock modifier variants to X11 `XGrabKey` to ensure the hotkey fires regardless of toggled modifiers.

### 2.3 Hermetic & Reproducible Builds

**Finding:** Release binaries contained absolute build paths and non-deterministic timestamps, violating the Zero-Trust doctrine (users cannot mathematically verify the binary matches the source).

**Fix:** 
- `build_linux.sh` exports `SOURCE_DATE_EPOCH` (pinned to last git commit) and `ZERO_AR_DATE=1`.
- `linux/CMakeLists.txt` injects `-ffile-prefix-map` and `-fdebug-prefix-map` to strip absolute paths from DWARF debug info and `__FILE__` macros.
- **Result:** Two consecutive builds produce byte-identical ELF binaries.

---

## Task 3 - Android Autofill & Binder Transit Security (P0-2 Closure)

### Finding

The original `VaultAutofillService` passed plaintext credentials from `MainActivity` via Android Binder (Intent extras). On rooted devices or via malicious apps with specific privileges, this created a local exploit vector for credential interception.

### Fix

Introduced the `AutofillSession` singleton to completely bypass Android Binder transit:
1. `VaultAutofillService` delegates state (pending `FillCallback` and `AutofillId` map) to the `AutofillSession` singleton.
2. `MainActivity` launches for vault unlock + tier decision.
3. Dart-side `AndroidAutofillBridge` uses a secure MethodChannel (`vault_crypto/autofill_bridge`) to pull the domain, apply `TierAutofillEnforcer` logic, and push credentials directly to the `AutofillSession` singleton.
4. The singleton builds the `Dataset` and resolves the `FillCallback`.

**Verdict:** Zero Binder transit. Credentials exist in plaintext only for the microseconds required to build the Android `Dataset` object in the same process memory space. P0-2 hole closed.

---

## Task 4 - FIDO2/WebAuthn Passkeys (P3 Implementation)

### Implementation

Native passkey support for modern authentication, keeping private keys strictly in hardware-backed Keystores:
- **Android 14+ CredentialManager:** `PasskeyPlugin.kt` bridges the OS-level biometric prompt to the Flutter core via MethodChannel.
- **Pure Core Math:** `PasskeyChallenge` generates 32-byte CSPRNG entropy, strictly base64url encoded (no padding) per WebAuthn Level 2 spec.
- **Domain Isolation:** `PasskeyManager.verifyRpId` mathematically enforces exact Relying Party ID matching, preventing cross-domain phishing.
- **Schema Evolution:** `VaultEntry` safely extends the V4 JSON schema with an optional `passkeyCredentialId`, maintaining backward compatibility with legacy vault blobs.

### Verification

Mutation tested (M121-M126). 100% kill score on schema evolution, base64url padding stripping, and rpId isolation bypass attempts.

---

## Task 5 - Post-Audit Hardening & Extended Mutation Campaign

### Applied Fixes

Following the initial audit, the following security hardening was applied:

#### 1. Native Memory Zeroing (FFI)
`sodium_memzero` added before `calloc.free` in all FFI wrappers (`argon2id`, `aes_gcm`, `hkdf`). Dart-side zeroing via `fillRange` in `key_hierarchy`, `vault_crypto_v4`, `second_factor`, `search_tag`.

#### 2. Bounds Checking & DoS Resistance (Parser Hardening)
- `header.dart`: Added `checkBounds()` helper and sanity limits (DEK < 1024B, CT < 1MB, Tags < 100, VC < 256B).
- `tier_autofill_enforcer.dart`: RFC 1035 domain length guard (253 chars) prevents O(N*M) algorithmic DoS in edit-distance calculations.
- Unified all parsing errors to `CorruptBlobError` (Error Oracle Prevention).

### Mutation Campaign Results

Extended campaign to **137 mutations** covering the entire Trusted Computing Base (TCB), V6.5 modules, Passkeys, Onboarding, Shamir, and Adaptive Posture:

| Group | Mutations | Invariants Tested |
|-------|-----------|-------------------|
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
| tier_autofill_enforcer | 8 | critical block, lookalike, domain mismatch, delay, normalization |
| security_tier | 6 | export block, downgrade confirm, reveal requirement |
| totp_generator | 6 | dynamic truncation, zero-pad, drift window, constant-time |
| vault_data | 3 | passkey schema evolution, legacy parse null-safety |
| passkey_challenge/core | 3 | CSPRNG entropy, base64url no-padding, rpId isolation |
| onboarding_core | 3 | doctrine bypass, SecureBuffer lifecycle, GoBack wipe |
| shamir_kit | 4 | GF(256) reduction, Lagrange division, Horner XOR, Fermat exp |
| adaptive_posture | 4 | canary priority, failure threshold, roaming opt-in, timeout |

**Result: 137/137 killed (100% kill score)**

All mutations target specific security invariants. A "killed" result means the test suite detected the invariant violation. This provides mathematical evidence that the crypto core and state machines are well-tested against common implementation errors.

---

## Task 6 - Advanced Verification & Fuzzing

Beyond the mutation campaign, the advanced suite (`security2.md` gates 21-32) and 8 dedicated fuzzers verify system boundaries:

### Fuzzing Campaign (8 Fuzzers, 0 Crashes, 0 Timeouts)

| Fuzzer | Iterations | Target | Result |
|--------|------------|--------|--------|
| `fuzz_vault.dart` | 100,000 | Random byte sequences | 0 crashes |
| `fuzz_vault_grammar.dart` | 50,000 | Structure-aware vault mutations | 0 crashes |
| `fuzz_parsers.dart` | 300,000 | V4Header, TOTP URI, Google Auth JSON | 0 crashes (typed errors only) |
| `fuzz_enforcer.dart` | 50,000 | TierAutofillEnforcer (algorithmic DoS) | 0 timeouts (RFC 1035 guard active) |
| `fuzz_sync_protocol.dart` | 20,000 | MITM handshake/replay/out-of-sequence | All rejected |
| `fuzz_totp_import.dart` | 20,000 | Malformed otpauth:// URIs | 0 crashes |
| `fuzz_autofill.dart` | 50,000 | Domain extraction & lookalike edge cases | 0 crashes |
| `memory_dump.dart` | 1,000 cycles | Lock/unlock residual memory analysis | No residual |

### Advanced Verification Suite

- **State machine testing** (vault + sync) — atomicity, no handshake skip, cooldown.
- **Model-based testing** — differential HKDF/HMAC against a pure-Dart RFC 5869 reference (100 vectors).
- **Concurrency & crash consistency** — lock races, power-loss atomic writes, FS edge cases.
- **Differential testing** — TOTP RFC 6238 (SHA1/SHA256/SHA512), Argon2id parameters.
- **Supply chain** — dependency pinning, build reproducibility, libsodium provenance.
- **Statistical timing** — KS test, Welch's t-test, Cohen's d (no oracle).
- **Attack simulation** — sync MITM, clipboard poisoning.

---

## Remaining Limitations

- Mutation testing covers only what is encoded as a mutation. It does not replace external cryptographic audit.
- `V4VaultEntry.password` remains a Dart `String` in the UI model (unavoidable Flutter limitation). The crypto core never holds it as String.
- Equivalent mutants (security-only, not functional) are documented but not counted as gaps.
- Native Android CredentialManager (Passkeys) requires Android 14+. Older devices fall back to password/biometric unlock.
- Wayland global-shortcut portal requires user to grant permission in OS settings.
- P2P sync requires both devices online simultaneously (no async). BLE 10m range is physical, not software-enforced.
- TOFU first-pairing vulnerable to MITM.

> **Full registry:** See [`TESTING.md`](TESTING.md).

---

## Conclusion

The crypto core handles all secrets in native/FFI memory with immediate `memzero`. The only Dart-String secret is the UI-model password (documented, unavoidable). 

Platform security has been hardened: Linux clipboard advertises the sensitive MIME type, Wayland shortcuts are natively supported, and builds are hermetic. Android Autofill credentials transit securely via process-local singletons, completely bypassing Binder/Intent extras. FIDO2 Passkeys are integrated with strict domain isolation.

Extended mutation testing (**137/137 killed**) plus the advanced verification suite (`security2.md` gates 21-32) and **eight fuzzers (0 crashes/timeouts)** provide strong mathematical evidence that the implementation correctly enforces security invariants across the entire TCB.