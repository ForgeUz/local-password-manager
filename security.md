# Vault Crypto Security Verification Plan

## 1. Cryptographic Core Invariants

### 1.1 Argon2id KDF

```
File: lib/src/crypto/argon2id.dart
Test file: test/security/crypto/test_argon2id.dart

VERIFY:
[ ] Output length is exactly 32 bytes (256 bits)
[ ] Parameters: memory_cost = 65536 (64 MiB), time_cost = 3, parallelism = 1
[ ] Same input (password + salt) → identical output (determinism)
[ ] Different salt → completely different output (avalanche)
[ ] Different password → completely different output
[ ] Salt is 16+ bytes, cryptographically random
[ ] No hardcoded salt or password in test vectors
[ ] FFI wrapper correctly passes parameters to libsodium
[ ] FFI wrapper zeroes password buffer after use (sodium_memzero)
[ ] FFI wrapper zeroes salt buffer after use
[ ] FFI wrapper zeroes output buffer when disposed
[ ] Function throws on empty password
[ ] Function throws on empty salt
[ ] Function throws on invalid parameters

METHOD:
- Property-based testing with 10,000 random password/salt pairs
- Verify determinism by running same input 1000 times
- Verify avalanche effect: flip 1 bit in password, compare outputs
- Manual FFI review: check calloc/free, sodium_memzero calls
- Run with AddressSanitizer to detect FFI leaks
```
### 1.2 AES-256-GCM Encryption/Decryption

```
File: lib/src/crypto/aes_gcm.dart
Test file: test/security/crypto/test_aes_gcm.dart

VERIFY:
[ ] Uses crypto_aead_aes256gcm_encrypt from libsodium (not custom AES)
[ ] Key is exactly 32 bytes
[ ] Nonce is exactly 12 bytes
[ ] Nonce is cryptographically random (never counter-based)
[ ] Nonce is NEVER reused with same key (verify with nonce tracking)
[ ] Authenticated data (AAD) is used where appropriate
[ ] Encryption adds 16-byte tag to ciphertext
[ ] Decryption fails on tampered ciphertext (authentication)
[ ] Decryption fails on tampered tag
[ ] Decryption fails on tampered AAD
[ ] Decryption fails on truncated ciphertext
[ ] Decryption fails on extended ciphertext
[ ] Error messages are uniform (no oracle about what failed)
[ ] AES-NI availability check implemented (crypto_aead_aes256gcm_is_available)
[ ] Fail-closed when AES-NI unavailable
[ ] FFI wrapper zeroes key buffer after use
[ ] FFI wrapper zeroes plaintext buffer after use
[ ] FFI wrapper zeroes ciphertext buffer after use
[ ] FFI wrapper zeroes decrypted output when disposed

METHOD:
- Property-based testing: encrypt → tamper → decrypt for 10,000 iterations
- Tamper each byte position individually (byte-by-byte mutation)
- Verify authentication always catches tampering
- Track nonces in a HashSet, assert no collision over 1M operations
- Timing attack: measure decrypt success vs failure time (should be uniform)
```

### 1.3 HKDF Key Derivation

```
File: lib/src/crypto/hkdf.dart
Test file: test/security/crypto/test_hkdf.dart

VERIFY:
[ ] Uses HMAC-SHA-256 as PRF (not SHA-1)
[ ] Salt is 32 bytes minimum
[ ] IKM (Input Keying Material) is zeroed after use
[ ] PRK (Pseudo-Random Key) is zeroed after use
[ ] Output key length is 32 bytes
[ ] Domain separation info strings are unique and unambiguous
[ ] Info string for VRK derivation: "vault-crypto/v4/vrk"
[ ] Info string for DEK wrap key: "vault-crypto/v4/dek-wrap"
[ ] Info string for search key: "vault-crypto/v4/search"
[ ] Info string for TOTP sealing: "vault-crypto/v4/totp-seal"
[ ] Different info strings produce completely different outputs
[ ] Info strings do not prefix-collide
[ ] Output does not leak IKM length or content
[ ] Empty IKM throws exception
[ ] Empty salt throws exception

METHOD:
- Property-based: 10,000 random IKM/salt/info combinations
- Verify all info strings are pairwise distinct
- Verify prefix-free property: no info string is prefix of another
- Manual review of all hardcoded info strings in codebase
```

### 1.4 Key Hierarchy (VRK → DEK)

```
File: lib/src/vault/key_hierarchy.dart
Test file: test/security/crypto/test_key_hierarchy.dart

VERIFY:
[ ] VRK derived from MK via HKDF with domain separation
[ ] Each DEK is independently generated CSPRNG (not derived from VRK)
[ ] DEK is wrapped (encrypted) under VRK using AES-256-GCM
[ ] DEK unwrap: decrypt with VRK → verify auth tag → return DEK
[ ] DEK is 32 bytes
[ ] DEK wrap uses unique nonce for each encryption
[ ] DEK unwrap failure does not reveal which DEK failed
[ ] Destroying one DEK does not affect other DEKs
[ ] Destroying VRK makes all DEKs unrecoverable
[ ] IKM (MK || TOTP) is zeroed after VRK derivation
[ ] VRK is stored in SecureBuffer, never as Dart Uint8List
[ ] DEK exists in plaintext only during use, then zeroed
[ ] DEK is never written to disk in plaintext
[ ] DEK is never logged
[ ] DEK is never included in error messages

METHOD:
- Create vault with 1000 entries, verify each has unique DEK
- Unwrap each DEK, verify all succeed
- Destroy single DEK, verify others still accessible
- Attempt unwrap with wrong VRK, verify failure
- Memory dump after lock: search for DEK bytes (should be zeroed)
- Property-based: generate 10,000 DEK wrap/unwrap cycles, verify roundtrip
```

### 1.5 Nonce Management

```
Files: lib/src/crypto/aes_gcm.dart, all files using AES-GCM

VERIFY:
[ ] No two encryptions under same key use same nonce
[ ] Nonce generation uses Sodium.randombytes_buf (CSPRNG)
[ ] Nonce is never derived from counter or timestamp
[ ] Nonce is never hardcoded
[ ] Nonce is never reused across different keys (acceptable, but verify no same-key reuse)
[ ] For per-entry DEK: each entry has unique DEK, nonce reuse across entries is OK
[ ] For VRK (same key used multiple times): nonces MUST be unique
[ ] Nonce collision probability < 2^-32 for 10^9 operations (birthday bound)

METHOD:
- Instrument AES-GCM to record (key_hash, nonce) pairs
- Perform 1,000,000 encryption operations
- Verify no duplicate (key_hash, nonce) pair
- Calculate collision probability based on observed data
- Review all code paths that generate nonces
```

---

## 2. File Format Security (GEN4)

### 2.1 Format Parsing

```
File: lib/src/vault/vault_crypto_v4.dart
Test file: test/security/format/test_gen4_parser.dart

VERIFY:
[ ] Parser handles files of size 0 bytes
[ ] Parser handles files of size 1 byte (should fail cleanly)
[ ] Parser handles files with invalid magic bytes
[ ] Parser handles files with valid magic but corrupted version
[ ] Parser handles truncated header
[ ] Parser handles header with length fields exceeding file size
[ ] Parser handles header with negative length fields
[ ] Parser handles DEK count = 0
[ ] Parser handles DEK count = negative
[ ] Parser handles DEK count > 10000 (sanity limit)
[ ] Parser handles ciphertext length = 0
[ ] Parser handles ciphertext length > 1MB (sanity limit)
[ ] Parser handles tag count = 0
[ ] Parser handles tag count > 100 (sanity limit)
[ ] Parser handles vector clock length > 256 (sanity limit)
[ ] Parser always throws CorruptBlobError (not FormatException, RangeError, etc.)
[ ] Parser never accesses memory out of bounds
[ ] Parser validates all length fields before using them
[ ] Parser checks total expected size vs actual file size

METHOD:
- Fuzzing: generate 100,000 random byte sequences, parse, verify no crash
- Byte-by-byte mutation: take valid file, flip each byte individually, verify no crash
- Truncation testing: valid file truncated at every length, verify no crash
- Extension testing: valid file with appended bytes, verify no crash
- Boundary testing: lengths at 0, 1, max-1, max, max+1
```

### 2.2 Decoy Vault

```
File: lib/src/vault/vault_crypto_v4.dart (decoy logic)
Test file: test/security/format/test_decoy.dart

VERIFY:
[ ] Decoy vault uses completely different key derivation path
[ ] Decoy vault password produces different VRK than primary
[ ] Primary password cannot open decoy vault
[ ] Decoy password cannot open primary vault
[ ] Decoy vault has identical file structure to primary (indistinguishable)
[ ] Accessing decoy vault does not modify primary vault
[ ] Accessing primary vault does not leak decoy vault existence
[ ] Decoy vault entries are realistic (plausible fake data)
[ ] Decoy vault access pattern identical to primary (no timing difference)
[ ] Decoy vault is stored in same file, not separate file
[ ] File size does not reveal presence of decoy (padding)
[ ] Error messages for wrong password are identical for both vaults

METHOD:
- Create vault with both primary and decoy
- Attempt to open decoy with primary password (should fail)
- Attempt to open primary with decoy password (should fail)
- Compare file sizes: with and without decoy vault
- Time password verification for both vaults (should be uniform)
- Fuzzing on file containing both vaults
- Verify no cross-contamination: modify decoy, check primary unchanged
```

### 2.3 Header Structure

```
File: lib/src/vault/header.dart
Test file: test/security/format/test_header.dart

VERIFY:
[ ] Header magic bytes are validated first
[ ] Version field validated against supported versions
[ ] All length fields are 4-byte big-endian unsigned integers
[ ] No signed integer parsing (prevent negative lengths)
[ ] Header size is fixed and validated
[ ] Unknown header fields are skipped (forward compatibility)
[ ] Header parsing does not allocate unbounded memory
[ ] DEK entries in header have validated structure
[ ] Tag entries in header have validated structure
[ ] checkBounds() helper is called before every array access
[ ] No direct array indexing without bounds check

METHOD:
- Property-based fuzzing on header specifically (10,000 iterations)
- Verify every field access goes through checkBounds()
- Static analysis: grep for direct array indexing in header.dart
- Verify no try-catch swallows RangeError silently
```

---

## 3. Memory Safety

### 3.1 SecureBuffer Usage

```
File: lib/src/security/secure_buffer.dart
Test file: test/security/memory/test_secure_buffer.dart

VERIFY:
[ ] SecureBuffer.alloc() uses sodium_malloc (not calloc directly)
[ ] SecureBuffer.fromList() copies data to sodium_malloc'd memory
[ ] SecureBuffer.readBytes() returns view, not copy
[ ] SecureBuffer.dispose() calls sodium_memzero
[ ] SecureBuffer.dispose() is idempotent (safe to call twice)
[ ] SecureBuffer.dispose() frees native memory
[ ] No path from SecureBuffer creation to GC without dispose
[ ] SecureBuffer.length is immutable after creation
[ ] SecureBuffer does not implement toString() (no accidental logging)
[ ] SecureBuffer does not implement == or hashCode (no accidental comparison)
[ ] All crypto operations accept SecureBuffer, not Uint8List

METHOD:
- Memory dump before and after dispose: verify zeroed
- Run with GC stress testing (dart --gc-strategy=all)
- Track allocation/deallocation pairs, verify no leaks
- Attempt to use SecureBuffer after dispose (should throw)
- Verify no Uint8List in crypto core signatures
```

### 3.2 Secret Zeroing

```
Files: All files in lib/src/crypto/, lib/src/vault/
Test file: test/security/memory/test_zeroing.dart

VERIFY EVERY SECRET IS ZEROED:

Master Password:
[ ] UI input: TextEditingController cleared after copy to SecureBuffer
[ ] Dart String from TextEditingController exists briefly, documented limitation
[ ] SecureBuffer.zero() called on lock

MK (Master Key from Argon2id):
[ ] argon2id.dart: password buffer zeroed after use
[ ] argon2id.dart: salt buffer zeroed after use
[ ] argon2id.dart: output (MK) zeroed after copied to SecureBuffer

VRK (Vault Root Key):
[ ] key_hierarchy.dart: IKM (MK || TOTP) zeroed after VRK derivation
[ ] vault_crypto_v4.dart: VRK zeroed on lock
[ ] vault_crypto_v4.dart: VRK zeroed on dispose

DEK (Data Encryption Key):
[ ] key_hierarchy.dart: DEK zeroed after wrapping
[ ] key_hierarchy.dart: DEK zeroed after unwrapping and use
[ ] vault_crypto_v4.dart: all DEKs zeroed on lock

TOTP Secret:
[ ] second_factor.dart: TOTP secret zeroed after KDF folding
[ ] second_factor.dart: candidate hash zeroed after comparison
[ ] second_factor.dart: SFM (Second Factor Material) zeroed after use

Search Key:
[ ] search_tag.dart: SearchKey zeroed after tag generation

Clipboard Content:
[ ] Clipboard cleared after timeout (30 seconds)
[ ] Clipboard cleared on vault lock
[ ] Sensitive MIME type set (text/plain;charset=utf-8;sensitive=true)

METHOD:
- Create vault, unlock, access all entries, lock
- Dump process memory using /proc/self/maps
- Search memory dump for known plaintext secrets
- Assert secrets not found (or found only in Dart String UI layer)
- Instrument sodium_memzero calls, verify all are reached
- Property-based: repeat 1000 lock/unlock cycles, check for accumulation
```

### 3.3 Dart GC Interaction

```
Files: All crypto code using Uint8List or String

VERIFY:
[ ] No Uint8List in crypto core (all in SecureBuffer)
[ ] Dart String only in UI layer (V4VaultEntry.password)
[ ] V4VaultEntry.password is never serialized to JSON
[ ] V4VaultEntry.password is never written to disk in plaintext
[ ] V4VaultEntry.password is never logged
[ ] V4VaultEntry.password is never included in error messages
[ ] No .toString() calls on crypto objects
[ ] No String interpolation with crypto values (${} on Uint8List/SecureBuffer)

METHOD:
- Static analysis: grep for Uint8List in lib/src/crypto/
- Static analysis: grep for toString() in crypto files
- Static analysis: grep for ${} interpolation in crypto files
- Runtime: enable assertions, run full test suite
- Check V4VaultEntry serialization: no JSON encode/decode of password field
```

---

## 4. Authentication Flows

### 4.1 Master Password Verification

```
File: lib/src/vault/vault_crypto_v4.dart (unlock path)
Test file: test/security/auth/test_master_password.dart

VERIFY:
[ ] Password comparison uses constant-time algorithm
[ ] Failed verification time equals successful verification time (±5%)
[ ] Rate limiting on failed attempts (exponential backoff)
[ ] Lockout after N failed attempts (N = configurable, default 5)
[ ] Lockout duration increases with each lockout
[ ] No information leaked in error messages (wrong password vs corrupt vault)
[ ] Password never logged on failure
[ ] Password never included in exception stack traces

METHOD:
- Timing test: 1000 correct + 1000 incorrect passwords, compare mean time
- Timing variance test: standard deviation of verification times
- Verify rate limiting: attempt N wrong passwords, measure delay increase
- Verify lockout: after 5 failures, next attempt blocked
- Grep codebase for logging of password input
```

### 4.2 TOTP Integration

```
File: lib/src/auth/second_factor.dart
Test file: test/security/auth/test_totp.dart

VERIFY:
[ ] TOTP is folded into KDF (mathematically affects key derivation)
[ ] TOTP verification is constant-time (no early exit)
[ ] TOTP window tolerance: ±1 time step (30 seconds)
[ ] TOTP secret is sealed under MK_base via AES-GCM
[ ] TOTP secret never exists in plaintext after import
[ ] Failed TOTP attempts are rate-limited
[ ] TOTP code not logged on failure
[ ] Backup codes release second-factor material through real KDF path
[ ] Backup codes are single-use
[ ] Backup codes are Argon2id-hashed before storage

METHOD:
- RFC 6238 compliance: verify against test vectors (SHA1/SHA256/SHA512)
- Timing test: 1000 valid + 1000 invalid TOTP codes, compare times
- Verify TOTP affects key: correct MP + wrong TOTP → decryption fails
- Verify TOTP secret sealed: no plaintext in memory dump
- Property-based: 10,000 TOTP generation/verification cycles
- Clock skew testing: ±30s, ±60s, ±90s offsets
```

### 4.3 Biometric Authentication

```
File: android/app/src/main/kotlin/.../MainActivity.kt
Test file: test/security/auth/test_biometric.dart

VERIFY:
[ ] Biometric prompt uses BiometricPrompt API (not deprecated)
[ ] Biometric authentication gates crypto operation, not just UI
[ ] Failed biometric attempts are rate-limited by system
[ ] Biometric failure does not lock vault (fallback to password)
[ ] Biometric data never leaves secure enclave
[ ] No biometric data stored in app
[ ] FLAG_SECURE set on biometric prompt (no screenshots)

METHOD:
- Manual testing on real device
- Verify biometric bypass: attempt to access vault without biometric
- Verify FLAG_SECURE in AndroidManifest
- Attempt screenshot during biometric prompt (should be black)
```

---

## 5. Duress Vault Security

```
File: lib/src/vault/duress.dart
Test file: test/security/duress/test_duress.dart

VERIFY:
[ ] Duress password produces different VRK than primary password
[ ] Duress vault is cryptographically isolated from primary
[ ] Domain separation: different HKDF info string for duress
[ ] Empty salt for duress (if implemented) is intentional and documented
[ ] Key size for duress vault matches primary (32 bytes)
[ ] Duress vault contains realistic-looking entries
[ ] Duress vault access does not trigger alert/canary
[ ] UI does not reveal duress mechanism (no hints, no visual differences)
[ ] Access pattern for duress vault identical to primary (timing)
[ ] Duress vault can be independently locked/unlocked

METHOD:
- Timing comparison: unlock duress vs primary, verify no difference
- Memory analysis: verify different keys derived
- Behavioral testing: ensure no UI indication of duress access
- Cryptographic verification: same MP + duress flag → different VRK
```

---

## 6. P2P Sync Security

### 6.1 Noise Protocol Handshake

```
File: lib/src/sync/noise_session.dart
Test file: test/security/sync/test_noise.dart

VERIFY:
[ ] Noise NNpsk0 pattern implemented correctly
[ ] Pre-shared key (PSK) derived via Argon2id(passphrase, salt, 64MiB, 3 iterations)
[ ] PSK is 32 bytes minimum
[ ] Handshake messages are properly authenticated
[ ] Session keys derived after successful handshake
[ ] Failed handshake does not leak key material
[ ] Handshake failure produces uniform error (no oracle)
[ ] TOFU (Trust-On-First-Use) pinning implemented for subsequent connections
[ ] TOFU failure (different key) produces clear warning
[ ] 60-second pairing window enforced
[ ] Maximum 3 pairing attempts before cooldown
[ ] Cooldown period is enforced (exponential backoff)

METHOD:
- Property-based: 10,000 handshake attempts with valid/invalid PSK
- MITM simulation: intercept handshake, attempt to substitute keys
- Verify TOFU: first connection pins key, second connection with different key fails
- Timing analysis: handshake time does not reveal PSK validity
```

### 6.2 Replay Prevention

```
File: lib/src/sync/replay_counter.dart, lib/src/sync/vector_clock.dart
Test file: test/security/sync/test_replay.dart

VERIFY:
[ ] Vector clock detects concurrent modifications
[ ] Replay counter increments monotonically
[ ] Duplicate messages rejected
[ ] Old messages rejected
[ ] Counter overflow handled gracefully
[ ] Vector clock comparison is deterministic
[ ] Conflict detection triggers manual resolution (no auto-merge)
[ ] Traffic padding applied to prevent traffic analysis

METHOD:
- Property-based: 10,000 message sequences, verify no replay accepted
- Send same message twice, verify second rejected
- Send message with lower counter, verify rejected
- Verify padding: message sizes not correlated with content
```

### 6.3 Conflict Resolution

```
File: lib/src/sync/conflict_resolver.dart
Test file: test/security/sync/test_conflict.dart

VERIFY:
[ ] Conflicts detected via vector clock
[ ] User prompted to choose (no automatic merge)
[ ] User choice is final (no retry ambiguity)
[ ] Conflict resolution does not leak which entry conflicted (to attacker)
[ ] Resolution propagated to all peers
[ ] Offline conflicts deferred, not lost

METHOD:
- Create conflicting modifications on two devices
- Sync, verify conflict detected
- Resolve, verify propagation
- Test with network interruption mid-resolution
```

---

## 7. Android-Specific Security

### 7.1 Autofill Service

```
File: android/app/src/main/kotlin/.../VaultAutofillService.kt
Test file: test/security/android/test_autofill.dart

VERIFY:
[ ] Domain extracted from AssistStructure.webDomain (trusted source)
[ ] Domain NOT extracted from page title or URL bar (spoofable)
[ ] Lookalike detection: homoglyph check (0/o, 1/l/i, 5/s)
[ ] Lookalike detection: edit distance ≤1
[ ] Lookalike detection: subdomain impersonation (microsoft.com.evil.io)
[ ] Lookalike detection: punycode/unicode normalization
[ ] Critical tier entries NEVER autofill (hard stop)
[ ] Sensitive tier entries require re-authentication
[ ] Standard tier entries autofill immediately
[ ] Vault must be unlocked before credentials released
[ ] FillResponse for critical tier returns null (no data)
[ ] Digital Asset Links verified for app-domain association
[ ] No credentials logged by AutofillService
[ ] AutofillService does not cache credentials in memory beyond use

METHOD:
- Manual testing on real Android 13+ device
- Test with known phishing domains (homoglyphs, lookalikes)
- Test critical tier entry: verify no autofill
- Test sensitive tier entry: verify re-auth required
- Memory dump during autofill: verify no credential caching
```

### 7.2 Manifest Security

```
File: android/app/src/main/AndroidManifest.xml

VERIFY:
[ ] allowBackup="false" (prevents Android auto-backup to Google Drive)
[ ] No INTERNET permission
[ ] BLUETOOTH_CONNECT, BLUETOOTH_SCAN, BLUETOOTH_ADVERTISE only if BLE sync used
[ ] NEARBY_WIFI_DEVICES only if WiFi Direct used
[ ] USE_BIOMETRIC for biometric unlock
[ ] CAMERA for TOTP QR import only
[ ] No ACCESS_NETWORK_STATE (unless needed for sync)
[ ] No READ_EXTERNAL_STORAGE or WRITE_EXTERNAL_STORAGE
[ ] android:exported="false" for all non-launcher activities
[ ] android:exported="true" only for AutofillService (required by system)
[ ] FLAG_SECURE set on all activities (prevents screenshots)

METHOD:
- Static analysis of AndroidManifest.xml
- Verify permissions match actual functionality
- Attempt screenshot of app (should be black)
- Verify no backup with: adb shell bmgr backupnow
```

### 7.3 BLE Transport

```
File: android/app/src/main/kotlin/.../BleTransportPlugin.kt
Test file: test/security/android/test_ble.dart

VERIFY:
[ ] BLE only used for discovery, not data transfer
[ ] Data transfer uses WiFi Direct (Nearby Connections API)
[ ] BLE advertising not used when sync disabled
[ ] BLE scanning not used when sync disabled
[ ] No BLE when app in background (unless active sync)
[ ] Bluetooth permissions requested at runtime, not install time
[ ] BLE connection uses Noise protocol (encrypted)
[ ] BLE range ~10m (physical limitation, not software-enforced)

METHOD:
- Manual testing: verify BLE only active during sync
- Verify app works with Bluetooth disabled
- Verify sync fails gracefully when out of range
```

---

## 8. Search Functionality (SSE)

```
File: lib/src/vault/search_tag.dart
Test file: test/security/search/test_sse.dart

VERIFY:
[ ] Search tags use Searchable Symmetric Encryption (SSE)
[ ] Search tags never decrypt domain during search
[ ] Search tags are bucket-padded (no size leakage)
[ ] Bucket padding is consistent (same query → same bucket size)
[ ] URL normalization: strips http://, https://, ftp://
[ ] Minimum query length: 3 characters
[ ] Search key is zeroed after use
[ ] Search index stored in encrypted vault (not separate file)
[ ] Search does not modify vault (read-only operation)
[ ] Search results do not leak entry count beyond bucket padding
[ ] Tags are not reversible without vault key

METHOD:
- Property-based: 10,000 search queries, verify no plaintext leakage
- Bucket analysis: search for common terms, verify bucket sizes consistent
- Verify search key zeroing: memory dump after search
- Verify tags stored encrypted: file dump shows no readable tags
```

---

## 9. Recovery Mechanisms

### 9.1 Shamir Secret Sharing

```
File: lib/src/recovery/shamir.dart (if exists)
Test file: test/security/recovery/test_shamir.dart

VERIFY:
[ ] Uses standard Shamir Secret Sharing scheme (not custom)
[ ] Threshold K of N shares reconstruct secret
[ ] K-1 shares reveal NOTHING about secret (information-theoretic security)
[ ] Share generation uses CSPRNG
[ ] Share reconstruction is deterministic (same shares → same secret)
[ ] Invalid shares (wrong polynomial) produce wrong secret (detected)
[ ] Share format includes checksum/validation
[ ] Shares can be exported to paper/print
[ ] Reconstruction works across different app versions

METHOD:
- Property-based: generate 1000 (K,N) combinations, verify reconstruction
- Test with K-1 shares: verify no information leaked
- Test with corrupted shares: verify detection
- Test reconstruction after app update
```

### 9.2 Recovery Flow

```
File: lib/src/screens/recovery_screen.dart (if exists)
Test file: test/security/recovery/test_recovery_flow.dart

VERIFY:
[ ] Recovery flow does not weaken security
[ ] Recovery does not create backdoor
[ ] Recovery shares are not stored in vault
[ ] Recovery shares are not transmitted anywhere
[ ] Successful recovery produces identical vault key
[ ] Failed recovery does not lock out user permanently
[ ] Recovery UI guides user clearly (no ambiguous steps)

METHOD:
- End-to-end test: create vault → generate shares → destroy password → recover → verify access
- Verify vault contents identical after recovery
- Test with partial shares (K-1): verify graceful failure
```

---

## 10. Clipboard Security

```
File: lib/src/clipboard/native_clipboard.dart, linux/runner/desktop_plugin.cc
Test file: test/security/clipboard/test_clipboard.dart

VERIFY:
[ ] Clipboard cleared after 30-second timeout
[ ] Clipboard cleared on vault lock
[ ] Sensitive MIME type set: text/plain;charset=utf-8;sensitive=true
[ ] Linux: freedesktop/GTK convention implemented
[ ] CopyQ, Diodon, Klipper (Linux clipboard managers) respect sensitive flag
[ ] Android: clipboard not accessible to other apps when sensitive flag set
[ ] Clipboard content not logged
[ ] Clipboard does not persist after app close

METHOD:
- Manual testing: copy password, wait 30s, verify clipboard cleared
- Manual testing: lock vault, verify clipboard cleared
- Linux: verify CopyQ does not log sensitive clipboard
- Android: attempt to read clipboard from another app (should fail)
```

---

## 11. Seccomp Sandbox (Linux)

```
File: linux/runner/seccomp_policy.cc (if exists)
Test file: test/security/sandbox/test_seccomp.dart

VERIFY:
[ ] Seccomp deny-list blocks: ptrace, process_vm_readv, process_vm_writev
[ ] Seccomp deny-list blocks: kcmp, perf_event_open
[ ] Seccomp policy does not block legitimate Flutter VM operations
[ ] Seccomp is applied after Flutter engine initialization
[ ] Seccomp failure causes app to abort (fail-closed)
[ ] No syscalls blocked that Flutter needs (verified by full test suite)

METHOD:
- Run app with strace, verify blocked syscalls return EPERM
- Attempt to ptrace the process (should fail)
- Run full test suite with seccomp enabled (should pass)
- Verify app still functions normally with seccomp
```

---

## 12. Error Handling & Information Leakage

```
Files: All files in lib/src/crypto/, lib/src/vault/
Test file: test/security/errors/test_error_leakage.dart

VERIFY:
[ ] All parsing errors → CorruptBlobError (uniform)
[ ] All decryption errors → DecryptionFailedError (uniform)
[ ] Error messages do not contain: entry IDs, field names, key material
[ ] Error messages do not contain: stack traces in release builds
[ ] Error messages do not differ based on WHERE decryption failed
[ ] No FormatException, RangeError, StateError leaks to UI
[ ] Logging framework does not log sensitive data
[ ] Crash reports (if any) do not include vault contents

METHOD:
- Trigger every error path, capture error message
- Verify all messages from same category are identical
- Attempt to distinguish error cause from message content
- Run with debug logging enabled, search for sensitive data
- Release build: verify no debug information in errors
```

---

## 13. Fuzzing Campaign

### 13.1 Vault File Fuzzing

```
File: tool/fuzz_vault.dart
Run: dart run tool/fuzz_vault.dart --iterations 100000

VERIFY:
[ ] Parser handles arbitrary byte sequences without crash
[ ] Parser never throws unexpected exception types
[ ] Parser never causes memory corruption
[ ] Parser never enters infinite loop
[ ] Corrupted input always produces CorruptBlobError or DecryptionFailedError

METHOD:
- Generate random bytes of sizes: 0, 1, 10, 100, 1000, 10000, 100000
- Take valid vault file, mutate each byte to every possible value (0-255) for first 1000 bytes
- Truncate valid file at every position
- Append random bytes to valid file
- Run for minimum 100,000 iterations
- Log any crash or unexpected exception
```

### 13.2 TOTP Input Fuzzing

```
File: tool/fuzz_totp.dart
Run: dart run tool/fuzz_totp.dart --iterations 50000

VERIFY:
[ ] TOTP parser handles malformed otpauth:// URIs
[ ] TOTP generator handles edge case timestamps (0, negative, max)
[ ] TOTP verification handles malformed codes (non-numeric, wrong length)
[ ] No integer overflow in time calculations

METHOD:
- Generate malformed otpauth:// URIs (missing parameters, invalid base32, etc.)
- Test time values: 0, -1, 2^63-1, 2^64, NaN
- Test code inputs: empty, non-numeric, wrong length, unicode
```

### 13.3 Autofill Domain Fuzzing

```
File: tool/fuzz_autofill.dart
Run: dart run tool/fuzz_autofill.dart --iterations 50000

VERIFY:
[ ] Domain extraction handles arbitrary strings
[ ] Lookalike detection does not crash on edge cases
[ ] No false positives on legitimate domains
[ ] No false negatives on obvious lookalikes

METHOD:
- Generate random Unicode strings as domains
- Test with: homoglyphs, mixed scripts, punycode, very long domains, empty strings
- Verify legitimate domains (google.com, microsoft.com) never flagged
- Verify lookalikes (rnicrosoft.com, g00gle.com) always flagged
```

---

## 14. Integration Testing

### 14.1 Full Lifecycle

```
File: test/security/integration/test_full_lifecycle.dart

VERIFY:
[ ] Create vault → add 100 entries → lock → unlock → verify all entries accessible
[ ] Create vault → add entries → change master password → unlock with new → verify entries
[ ] Create vault → add entries → enable TOTP → lock → unlock with MP+TOTP → verify
[ ] Create vault → add entries → set up duress → unlock with duress → verify decoy entries
[ ] Create vault → add entries → generate Shamir shares → recover → verify entries
[ ] Create vault → add entries → sync to second device → verify on second device

METHOD:
- Automated end-to-end tests for each scenario
- Verify data integrity at each step (checksum entries)
- Verify no data loss or corruption
- Verify performance: lifecycle completes in reasonable time
```

### 14.2 Concurrent Operations

```
File: test/security/integration/test_concurrent.dart

VERIFY:
[ ] Multiple entries added concurrently do not corrupt vault
[ ] Search during save does not cause inconsistency
[ ] Lock during operation cleans up properly
[ ] Sync during modification handles conflict correctly

METHOD:
- Run 100 concurrent entry additions
- Run search while save in progress
- Attempt lock during decrypt operation
- Sync while entry being modified
```

---

## 15. Static Analysis

### 15.1 Code Review Checklist

```
Run: dart analyze --fatal-infos --fatal-warnings

VERIFY:
[ ] Zero analyzer errors
[ ] Zero analyzer warnings
[ ] All info-level lints reviewed and justified

Manual code review of all crypto files:
[ ] No inline cryptography (all through libsodium FFI)
[ ] No hardcoded keys, salts, or nonces
[ ] No debug print/log statements in crypto path
[ ] No TODO/FIXME/HACK comments in crypto files
[ ] All public APIs documented with security implications
[ ] All crypto classes have @visibleForTesting only where appropriate
[ ] No dynamic type usage (List<dynamic>, Map<String, dynamic>) in crypto
[ ] All crypto parameters validated before use
```

### 15.2 Dependency Security

```
File: pubspec.yaml, pubspec.lock

VERIFY:
[ ] All dependencies pinned to exact versions
[ ] No dependencies with known vulnerabilities (check Snyk, Dependabot)
[ ] ffi package: ^2.1.0 (latest stable)
[ ] pointycastle: ^3.7.3 (if used, verify no crypto through it)
[ ] local_auth: ^2.2.0 (latest stable)
[ ] No dependencies with unnecessary permissions (INTERNET, etc.)
[ ] Dependency lock file committed to git

METHOD:
- Run: dart pub deps --style=compact
- Check each dependency on pub.dev for security advisories
- Run: flutter pub outdated (check for security updates)
```

---

## 16. Runtime Verification

### 16.1 Memory Dump Analysis

```
File: tool/memory_dump.dart
Run: dart run tool/memory_dump.dart

VERIFY:
[ ] After vault lock: no MK, VRK, DEK in memory
[ ] After entry access: no DEK for other entries in memory
[ ] After clipboard copy: password not in memory after timeout
[ ] After search: SearchKey not in memory
[ ] No accumulation of secrets over multiple lock/unlock cycles

METHOD:
- Instrument app to dump /proc/self/maps at critical points
- Search memory dump for known plaintext patterns:
  - Master password (test string)
  - Known entry passwords
  - Known TOTP secrets
  - Known salts
- Run 1000 lock/unlock cycles, dump memory, check for accumulation
```

### 16.2 Timing Analysis

```
File: tool/timing_analysis.dart
Run: dart run tool/timing_analysis.dart

VERIFY:
[ ] Password verification: mean time correct vs wrong (difference < 5%)
[ ] TOTP verification: mean time valid vs invalid (difference < 5%)
[ ] Decryption: mean time valid vs corrupt data (difference < 5%)
[ ] Duress vault access: same timing as primary vault
[ ] Search: timing does not correlate with result count

METHOD:
- 10,000 iterations of each operation
- Record execution time (microsecond precision)
- Calculate mean, median, standard deviation
- Compare distributions (t-test or KS test)
- Verify no statistical significance (p > 0.05)
```

---

## 17. Threat Model Verification

```
File: SECURITY.md (update with verification results)

VERIFY AGAINST EACH THREAT:

T1: Attacker steals vault file
  [ ] Cannot decrypt without master password
  [ ] Cannot determine vault contents from file structure
  [ ] Cannot determine entry count from file size
  [ ] Cannot distinguish primary from decoy vault

T2: Attacker has physical access to unlocked device
  [ ] Vault auto-locks after inactivity (configured timeout)
  [ ] Memory dump reveals no useful secrets (SecureBuffer zeroing)
  [ ] Clipboard does not contain password (timeout)
  [ ] Screenshots blocked (FLAG_SECURE)

T3: Attacker observes user typing (shoulder surfing)
  [ ] Password field masked
  [ ] TOTP code masked after brief display
  [ ] Duress password not visually distinguishable

T4: Malware on device
  [ ] Seccomp blocks ptrace, process_vm_readv (Linux)
  [ ] Vault file encrypted at rest
  [ ] No plaintext secrets in memory during lock
  [ ] Clipboard managers cannot log sensitive content (MIME type)

T5: Network attacker (for sync)
  [ ] All sync traffic encrypted (Noise protocol)
  [ ] TOFU prevents MITM after first connection
  [ ] First connection MITM possible (documented limitation)

T6: Coercion attack
  [ ] Duress vault provides plausible denial
  [ ] Cannot prove existence of primary vault
  [ ] Can access decoy vault without revealing mechanism

METHOD:
- Simulate each threat scenario
- Document actual attack surface
- Verify mitigations work as designed
- Update SECURITY.md with verified threat model
```

---

## 18. Cryptographic Test Vectors

```
File: test/security/vectors/test_vectors.dart

VERIFY WITH KNOWN TEST VECTORS:

Argon2id:
[ ] RFC 9106 test vectors pass
[ ] Parameters: m=65536, t=3, p=1, 32-byte output

AES-256-GCM:
[ ] NIST test vectors pass
[ ] 12-byte nonce, 16-byte tag

HKDF-SHA-256:
[ ] RFC 5869 test vectors pass
[ ] Extract and expand operations

TOTP (RFC 6238):
[ ] SHA1 test vectors pass
[ ] SHA256 test vectors pass
[ ] SHA512 test vectors pass
[ ] Various time steps and digits

Shamir Secret Sharing:
[ ] Known (K,N) combinations produce correct shares
[ ] Reconstruction produces original secret
[ ] K-1 shares reveal nothing

Noise NNpsk0:
[ ] Noise protocol framework test vectors pass
[ ] Handshake produces expected session keys

METHOD:
- Include all test vectors in test suite
- Run as part of continuous integration
- Never remove test vectors (regression protection)
```

---

## 19. Performance Under Adversarial Load

```
File: tool/performance_test.dart

VERIFY:
[ ] Vault with 10,000 entries: unlock < 5 seconds
[ ] Vault with 10,000 entries: search < 1 second
[ ] Vault with 10,000 entries: save < 10 seconds
[ ] 1000 lock/unlock cycles: no memory leak (heap size stable)
[ ] Fuzzing with 1M inputs: completes without OOM

METHOD:
- Create vault with 10,000 random entries
- Measure operation times (10 runs, take median)
- Monitor memory usage over 1000 operations
- Run with --observe flag to check for leaks
- Profile with Dart DevTools
```

---

## 20. Documentation Cross-Check

```
Files: README.md, SECURITY.md, SECURITY_AUDIT.md, status.md

VERIFY:
[ ] All security claims in README are backed by tests
[ ] All "DONE" items in status.md have corresponding tests
[ ] All "documented limitations" are actually documented
[ ] SECURITY.md threat model matches implementation
[ ] No security claims made that aren't true
[ ] Honest Limitations section is complete and accurate
[ ] Audit status clearly states "internal only, external pending"
[ ] No overclaiming of security guarantees

METHOD:
- Cross-reference each claim in README with test file
- Verify each "DONE" in status.md has passing test
- Review each limitation for accuracy
- Have another person review claims vs reality
```

---

## Execution Priority

```
Phase 1 (Critical Path):
  1.1 Argon2id verification
  1.2 AES-GCM verification
  1.4 Key hierarchy verification
  1.5 Nonce management
  2.1 Format parsing fuzzing
  13.1 Vault file fuzzing

Phase 2 (High Priority):
  3.1 SecureBuffer verification
  3.2 Secret zeroing verification
  4.1 Master password verification
  4.2 TOTP integration
  12. Error handling verification

Phase 3 (Medium Priority):
  2.2 Decoy vault
  5. Duress vault
  6.1-6.3 P2P sync security
  7.1-7.3 Android security
  8. Search SSE

Phase 4 (Lower Priority):
  9. Recovery mechanisms
  10. Clipboard security
  11. Seccomp sandbox
  16. Runtime verification
  19. Performance testing
  20. Documentation cross-check
```
