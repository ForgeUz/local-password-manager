# Vault Crypto — Advanced Verification Suite (Post-Pass)

## 21. State Machine Testing

### 21.1 Vault State Transitions

```
File: test/security/statemachine/test_vault_states.dart
Model file: test/security/statemachine/vault_state_model.dart

STATES:
  LOCKED → UNLOCKING → UNLOCKED → LOCKING → LOCKED
  UNLOCKED → SAVING → UNLOCKED
  UNLOCKED → ENTRY_DECRYPTING → UNLOCKED
  LOCKED → RECOVERY_MODE → UNLOCKED
  UNLOCKED → DURESS_TRIGGERED → DECOY_UNLOCKED

VERIFY TRANSITIONS:
[ ] Every state transition is atomic (no partial states)
[ ] Lock during UNLOCKING: rolls back cleanly, no key material in memory
[ ] Lock during SAVING: vault file not corrupted (atomic write via temp+rename)
[ ] Lock during ENTRY_DECRYPTING: DEK wiped, partial plaintext wiped
[ ] Crash (process kill) during SAVING: vault file remains in previous valid state
[ ] Crash during LOCKING: no key material persists (SecureBuffer destructors)
[ ] Recovery mode cannot be entered from UNLOCKED state
[ ] Duress trigger only from UNLOCKED state, not from LOCKED
[ ] After DECOY_UNLOCKED, primary vault keys are not in memory

METHOD:
- Implement state machine model with valid/invalid transition table
- Property-based: generate 10,000 random transition sequences
- Verify no sequence reaches invalid state
- Inject crash at every transition boundary (SIGKILL in test harness)
- Verify vault file integrity after every crash injection
- Run with `dart --enable-vm-service` to inspect memory at state boundaries
```

### 21.2 Sync Session State Machine

```
File: test/security/statemachine/test_sync_states.dart

STATES:
  IDLE → DISCOVERING → PAIRING → HANDSHAKING → SYNCING → COMPLETE
  PAIRING → PAIRING_FAILED → COOLDOWN
  HANDSHAKING → HANDSHAKE_FAILED
  SYNCING → CONFLICT → RESOLVING → SYNCING
  SYNCING → INTERRUPTED → DISCOVERING (retry)

VERIFY:
[ ] No transition skips handshake (cannot go PAIRING → SYNCING directly)
[ ] Conflict state always leads to user resolution (never auto-merge)
[ ] Cooldown cannot be bypassed by restarting session
[ ] INTERRUPTED state preserves sync state (vector clock) for retry
[ ] Max 3 pairing attempts enforced across process restarts
[ ] Session keys destroyed on COMPLETE and on INTERRUPTED

METHOD:
- Model-based testing with 5,000 random valid/invalid sequences
- Inject network failure at each state
- Verify session key material zeroed on exit from any state
- Test process kill during SYNCING, restart, verify state recovery
```

---

## 22. Model-Based Testing (Formal Model)

### 22.1 Cryptographic Model Conformance

```
File: test/security/model/test_crypto_model.dart
Reference: test/security/model/reference_crypto.dart (pure Dart implementation)

CREATE REFERENCE IMPLEMENTATION:
- Argon2id: use `dart_argon2` package or hand-write for testing
- AES-GCM: use `cryptography` package (different from libsodium)
- HKDF: implement from RFC 5869 in pure Dart

VERIFY DIFFERENTIAL:
[ ] libsodium Argon2id output == reference implementation output (100 vectors)
[ ] libsodium AES-GCM output == reference implementation (100 vectors)
[ ] libsodium HKDF output == reference implementation (100 vectors)
[ ] Empty input handling matches
[ ] Maximum length input handling matches
[ ] Edge case parameters match

METHOD:
- Generate random test vectors
- Run through both implementations
- Compare outputs byte-for-byte
- If mismatch: potential FFI bug (parameter marshalling error)
- This catches: wrong parameter order, wrong endianness, wrong sizes
```

### 22.2 Vault File Format Model

```
File: test/security/model/test_format_model.dart

CREATE FORMAL MODEL:
- GEN4 format as dataclass in test
- Valid ranges for every field
- Invariants (e.g., sum of DEK sizes == header size)

VERIFY:
[ ] Generated valid vault files always parse successfully
[ ] Generated invalid files (violating model) always throw CorruptBlobError
[ ] Round-trip: create → serialize → parse → serialize → identical bytes
[ ] Header invariants maintained after every save operation
[ ] Entry count in header matches actual entries in vault

METHOD:
- Property-based generation from formal model
- 10,000 random valid vault files, verify round-trip
- 10,000 invalid files (model violation), verify rejection
- Serialization determinism: same vault state → same bytes
```

---

## 23. Advanced Fuzzing (Structure-Aware)

### 23.1 Grammar-Based Vault Fuzzer

```
File: tool/fuzz_vault_grammar.dart
Run: dart run tool/fuzz_vault_grammar.dart --iterations 50000

IMPLEMENT STRUCTURE-AWARE FUZZING:
- Not random bytes, but structured mutations of valid vault
- Grammar:
  vault := magic(4) + version(2) + flags(1) + reserved(1) +
           entry_count(4) + dek_table +
           primary_slot + decoy_slot + search_index
  dek_table := { nonce(12) + ciphertext(len) + tag(16) } * entry_count

MUTATION STRATEGIES:
[ ] Field-level: mutate single field to boundary values (0, max, max+1, -1)
[ ] Structural: remove/add DEK entries, swap slot order
[ ] Semantic: valid structure, invalid cryptographic content
[ ] Cross-field: entry_count = 5, but 3 DEK entries present

VERIFY:
[ ] No crash on any mutation
[ ] All rejections are CorruptBlobError or DecryptionFailedError
[ ] Parser never loops infinitely on crafted input
[ ] No memory leak during fuzzing (RSS stable over 50k iterations)

METHOD:
- libFuzzer-style coverage instrumentation (if available)
- Track code coverage: aim for >95% of parser code covered
- Corpus management: save interesting inputs (crashes, timeouts, new paths)
- Dictionary-based mutations: valid magic bytes, version numbers, etc.
```

### 23.2 Protocol Fuzzer (Sync)

```
File: tool/fuzz_sync_protocol.dart
Run: dart run tool/fuzz_sync_protocol.dart --iterations 20000

IMPLEMENT:
- Man-in-the-middle simulator
- Intercept and modify Noise handshake messages
- Replay old messages with modified counters
- Inject messages out of sequence

VERIFY:
[ ] Modified handshake messages: rejected (MAC failure)
[ ] Replayed messages: rejected (nonce/counter)
[ ] Out-of-sequence messages: rejected (state machine)
[ ] No information leaked in rejection (uniform error)
[ ] No state corruption from malicious peer

METHOD:
- Implement fake peer that violates protocol
- Test: truncated messages, extended messages, wrong types
- Test: valid handshake, then garbage data
- Test: valid handshake, then valid-looking but malicious sync data
```

### 23.3 TOTP Secret Import Fuzzer

```
File: tool/fuzz_totp_import.dart
Run: dart run tool/fuzz_totp_import.dart --iterations 20000

INPUT SPACE:
- otpauth:// URIs with:
  - Missing parameters (secret, issuer, algorithm)
  - Invalid base32 encoding
  - Invalid algorithm names (MD5, unknown)
  - Invalid periods (0, negative, very large)
  - Invalid digits (0, 1, 5, 7, 9, 100)
  - Unicode in issuer/account
  - Very long secrets (100KB+)
  - Nested URI encoding

VERIFY:
[ ] Malformed URIs rejected gracefully
[ ] No crash on any input
[ ] Valid imports always produce working TOTP
[ ] Secret never logged during parsing
[ ] Invalid algorithm falls back to SHA1 (or rejects, document which)

METHOD:
- Generate malformed otpauth:// URIs programmatically
- Test with real QR code contents from various authenticators
- Verify imported secrets generate correct codes
```

---

## 24. Concurrency & Race Condition Testing

### 24.1 Lock During Cryptographic Operation

```
File: test/security/concurrency/test_lock_race.dart

SCENARIOS:
[ ] Call lock() while entry decryption in progress
[ ] Call lock() while vault save in progress
[ ] Call lock() while TOTP generation in progress
[ ] Call lock() while search in progress
[ ] Call lock() while sync in progress

VERIFY:
[ ] Lock always completes (no deadlock)
[ ] After lock: no key material in memory (even from in-progress operation)
[ ] In-progress operation either completes safely or aborts cleanly
[ ] No partial writes to vault file
[ ] UI reflects locked state immediately

METHOD:
- Use Isolates to simulate concurrent operations
- Spawn operation, immediately call lock()
- Memory dump after lock completes
- Verify no exception leaks to UI
- Test with stress: 100 concurrent operations + lock
```

### 24.2 Concurrent Entry Access

```
File: test/security/concurrency/test_concurrent_access.dart

SCENARIOS:
[ ] Decrypt entry A and entry B simultaneously
[ ] Save vault while decrypting entry
[ ] Search while saving vault
[ ] Sync while modifying entry

VERIFY:
[ ] No data corruption in vault file
[ ] No key material from entry A leaks during entry B access
[ ] Save operations are serialized (no interleaved writes)
[ ] Sync sees consistent state (not mid-save)

METHOD:
- Run operations in separate isolates
- Use barriers to synchronize start
- Verify vault file integrity after all operations
- Run 1000 iterations of concurrent scenarios
```

---

## 25. Crash Consistency & Data Integrity

### 25.1 Power Loss Simulation

```
File: test/security/crash/test_power_loss.dart

SCENARIOS:
[ ] Kill process during vault save (temp file written, rename not yet)
[ ] Kill process during rename (atomic operation)
[ ] Kill process during entry encryption
[ ] Kill process during Shamir share generation
[ ] Kill process during sync conflict resolution

VERIFY:
[ ] Vault file is never in corrupted state
[ ] Either old state or new state (atomicity)
[ ] No partial temp files left (cleanup on startup)
[ ] Recovery from interrupted save: vault opens correctly
[ ] No key material in temp files after crash

METHOD:
- Use SIGKILL at strategic points (before/after rename)
- Simulate by copying vault file at each step, killing process
- On restart: verify vault parses, all entries accessible
- Check for orphaned temp files in app directory
- Test with full disk condition (temp write fails)
```

### 25.2 File System Edge Cases

```
File: test/security/crash/test_fs_edge_cases.dart

SCENARIOS:
[ ] Vault file on read-only filesystem
[ ] Vault file with permissions changed to 000
[ ] Vault file truncated externally
[ ] Vault file replaced with symlink
[ ] Two vault files at same path (race)
[ ] Disk full during save

VERIFY:
[ ] Graceful error handling (not crash)
[ ] User informed of failure
[ ] No data loss (original vault untouched if save failed)
[ ] Symlink attack: vault writes to target, not symlink path
[ ] No partial state persisted

METHOD:
- Create various filesystem conditions
- Attempt save operation
- Verify error handling and data integrity
- Test on Linux (ext4) and Android (emulated storage)
```

---

## 26. Differential Testing Against Known Implementations

### 26.1 TOTP Cross-Implementation

```
File: test/security/differential/test_totp_differential.dart

REFERENCE IMPLEMENTATIONS:
- Python: pyotp library
- JavaScript: otpauth package (or similar)
- Test vectors from RFC 6238

VERIFY:
[ ] Same secret + timestamp → same code (your impl vs pyotp)
[ ] Test with secrets from Google Authenticator export
[ ] Test with secrets from Microsoft Authenticator
[ ] Test with various algorithms: SHA1, SHA256, SHA512
[ ] Test with various periods: 30s (standard), 60s, 90s
[ ] Test with various digits: 6, 8

METHOD:
- Generate test cases in Python, save to JSON
- Load in Dart test, run your implementation
- Compare outputs
- This catches: endianness bugs, time calculation errors, base32 issues
```

### 26.2 Argon2id Parameter Compatibility

```
File: test/security/differential/test_argon2_differential.dart

VERIFY:
[ ] Your Argon2id output matches reference implementation
[ ] Parameters: m=65536, t=3, p=1
[ ] Same password/salt → same output as `argon2` CLI tool
[ ] Test vector from Argon2 reference implementation repo

METHOD:
- Generate test vectors using `argon2` CLI tool
- Run same inputs through your FFI implementation
- Compare outputs byte-for-byte
- This catches: FFI parameter marshalling bugs, wrong memory units
```

---

## 27. Supply Chain & Build Integrity

### 27.1 Dependency Pinning & Verification

```
File: tool/verify_deps.dart
Run: dart run tool/verify_deps.dart

VERIFY:
[ ] pubspec.lock contains exact versions (no ^)
[ ] SHA-256 hashes for all dependencies (if available)
[ ] No dependencies added since last audit without review
[ ] All transitive dependencies documented
[ ] No dependency has network permissions in its Android manifest

METHOD:
- dart pub deps --style=compact > dependency_tree.txt
- Compare against committed baseline
- Check each dependency for security advisories:
  - dart pub outdated
  - Manual check on pub.dev
- Verify libsodium version and build provenance
```

### 27.2 Build Reproducibility

```
File: tool/verify_build.dart
Run: ./build_linux.sh && dart run tool/verify_build.dart

VERIFY:
[ ] Two consecutive builds produce identical binaries
[ ] build_hash.txt matches actual binary hash
[ ] libsodium.so hash matches known-good hash
[ ] No debug symbols in release build
[ ] No debug logging compiled into release

METHOD:
- Build twice, compare SHA-256 of binaries
- If different: investigate non-determinism (timestamps, paths)
- strip binary, verify no symbols
- strings binary | grep -i "debug\|log\|password"
```

### 27.3 libsodium Provenance

```
File: android/app/src/main/jniLibs/

VERIFY:
[ ] arm64-v8a/libsodium.so: hash matches official release
[ ] armeabi-v7a/libsodium.so: hash matches official release
[ ] No modified libsodium (compare with official binary)
[ ] libsodium version documented
[ ] Security advisories checked for this version

METHOD:
- Download official libsodium release for Android
- Compare hashes with committed .so files
- Document libsodium version in SECURITY.md
- Subscribe to libsodium security announcements
```

---

## 28. Advanced Timing Analysis

### 28.1 Statistical Timing (Beyond Mean)

```
File: tool/timing_statistical.dart
Run: dart run tool/timing_statistical.dart

VERIFY:
[ ] Password verification: distribution overlap correct/wrong > 95%
[ ] TOTP verification: no bimodal distribution (early exit detection)
[ ] Vault decryption: variance in failure time < threshold
[ ] Search: timing does not correlate with bucket contents

STATISTICAL TESTS:
[ ] Kolmogorov-Smirnov test: distributions identical (p > 0.05)
[ ] Welch's t-test: no significant difference (p > 0.05)
[ ] Effect size (Cohen's d): < 0.2 (negligible)
[ ] No outliers (> 3σ) in either distribution

METHOD:
- 10,000 samples per condition
- Use dart:math for statistical calculations (or export to Python)
- Plot histograms (save to file)
- Run KS test, t-test on the two distributions
- If p < 0.05: investigate and fix timing leak
```

### 28.2 Cache Timing (Advanced)

```
File: tool/timing_cache.dart
Run: dart run tool/timing_cache.dart

NOTE: Difficult in Dart (no direct cache control)
      Best effort: measure timing variance under different memory layouts

VERIFY:
[ ] AES-GCM with AES-NI: timing independent of key content
[ ] Argon2id: timing independent of password content (memory access patterns)
[ ] No cache-line collision attack possible (documented limitation if not)

METHOD:
- Measure AES-GCM with keys differing in 1 bit
- Compare timing distributions
- For Dart: acknowledge as limitation, rely on AES-NI constant-time guarantees
- Document in SECURITY.md: "constant-time properties delegated to libsodium"
```

---

## 29. Multi-Vault & Edge Case Scenarios

### 29.1 Multiple Vault Files

```
File: test/security/multivault/test_multiple_vaults.dart

SCENARIOS:
[ ] Two vault files, different master passwords
[ ] Unlock vault A, then attempt to unlock vault B with A's password
[ ] Switch between vaults without lock in between
[ ] Sync between two different vaults (should be rejected)
[ ] Shamir recovery from vault A applied to vault B (should fail)

VERIFY:
[ ] Vault B rejects vault A's password (different salts/KDF)
[ ] No key material from vault A persists when unlocking vault B
[ ] Sync protocol verifies vault identity (prevents cross-vault sync)
[ ] Shamir shares are vault-specific (share from A doesn't recover B)
[ ] UI clearly indicates which vault is active

METHOD:
- Create two vaults with known different passwords
- Attempt all cross-vault operations
- Memory dump between vault switches
- Verify error messages don't reveal existence of other vault
```

### 29.2 Empty & Minimal Vaults

```
File: test/security/multivault/test_edge_vaults.dart

SCENARIOS:
[ ] Vault with 0 entries
[ ] Vault with 1 entry
[ ] Vault with maximum theoretical entries (10,000+)
[ ] Entry with empty username, empty URL, minimal fields
[ ] Entry with maximum field length (1MB notes field)
[ ] Vault with only decoy entries (no primary entries)

VERIFY:
[ ] Empty vault: save/load works, search returns nothing
[ ] 1 entry: all operations work correctly
[ ] 10,000 entries: performance acceptable, no memory issues
[ ] 1MB notes: encrypt/decrypt works, no truncation
[ ] Decoy-only: primary unlock fails gracefully

METHOD:
- Create vaults at boundaries (0, 1, 100, 1000, 10000 entries)
- Time all operations
- Verify data integrity (round-trip)
- Memory profiling for large vaults
```

---

## 30. Pre-Audit Preparation

### 30.1 Security Documentation Package

```
Files to create/update:
  AUDIT_PACKAGE/
  ├── CRYPTO_SPEC.md          # Full cryptographic specification
  ├── THREAT_MODEL.md         # Complete threat model
  ├── ATTACK_SURFACE.md       # All attack surfaces enumerated
  ├── TEST_COVERAGE.md        # Coverage of security gates
  ├── KNOWN_LIMITATIONS.md    # Current limitations
  ├── BUILD_REPRODUCIBILITY.md # How to verify builds
  └── DIFFERENTIAL_ANALYSIS.md # Comparison with reference impls

CRYPTO_SPEC.md MUST INCLUDE:
[ ] Exact byte layout of GEN4 format (all fields, offsets, sizes)
[ ] Key derivation diagram (MK → VRK → DEK)
[ ] All domain separation strings (exact bytes)
[ ] Argon2id parameters (exact values)
[ ] AES-GCM usage patterns (nonce generation, AAD usage)
[ ] Noise protocol details (pattern, PSK derivation)
[ ] Shamir implementation details (field, polynomial generation)
[ ] Search tag algorithm (SSE construction)
[ ] TOTP folding into KDF (exact mechanism)

METHOD:
- Document everything an auditor needs to review without reading code
- Include diagrams (Mermaid or ASCII art)
- Reference test files that verify each spec point
- This package is what you send to potential auditors
```

### 30.2 Attack Surface Enumeration

```
File: AUDIT_PACKAGE/ATTACK_SURFACE.md

ENUMERATE EVERY INPUT:
[ ] Vault file (user-selected, potentially malicious)
[ ] Master password (user input)
[ ] Duress password (user input)
[ ] TOTP secret (from QR code or manual entry)
[ ] TOTP code (user input)
[ ] Backup codes (user input)
[ ] Shamir shares (user input during recovery)
[ ] Autofill request (from Android system)
[ ] Sync peer (network, potentially malicious)
[ ] Search query (user input)
[ ] Entry data (user input: URLs, usernames, notes)

FOR EACH INPUT DOCUMENT:
- Where it enters the system
- What validation is applied
- What happens with malformed input
- What happens with adversarial input
- Which tests verify this
```

### 30.3 Auditor-Friendly Repository Structure

```
VERIFY:
[ ] SECURITY.md: clear, current threat model
[ ] AUDIT_BRIEF_V65.md: what auditor should focus on
[ ] test/security/: all security tests, organized, passing
[ ] tool/: all verification tools, documented usage
[ ] No dead code in crypto core
[ ] No TODO/FIXME in crypto files
[ ] All public APIs documented
[ ] Code coverage report generated and committed

METHOD:
- Generate coverage: dart test --coverage=coverage
- Format report: dart pub global activate coverage
- Commit HTML report
- Review repository as if you were an external auditor
- Fix anything that would raise questions
```

---

## 31. Continuous Security Verification

### 31.1 GitHub Actions Security Workflow

```
File: .github/workflows/security.yml

CREATE WORKFLOW:
name: Security Verification
on: [push, pull_request, schedule]

jobs:
  crypto-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: subosito/flutter-action@v2
      - run: flutter test test/security/crypto/
      - run: flutter test test/security/format/
      - run: flutter test test/security/memory/

  fuzzing:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: subosito/flutter-action@v2
      - run: dart run tool/fuzz_vault.dart --iterations 10000
      - run: dart run tool/fuzz_vault_grammar.dart --iterations 10000
      - run: dart run tool/fuzz_totp_import.dart --iterations 5000

  timing:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: subosito/flutter-action@v2
      - run: dart run tool/timing_analysis.dart
      - run: dart run tool/timing_statistical.dart

  memory:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: subosito/flutter-action@v2
      - run: dart run tool/memory_dump.dart

  static-analysis:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: subosito/flutter-action@v2
      - run: dart analyze --fatal-infos --fatal-warnings
      - run: dart format --set-exit-if-changed lib/

VERIFY:
[ ] All security tests run on every PR
[ ] Fuzzing runs on schedule (nightly)
[ ] Timing tests run (with threshold for flaky detection)
[ ] Memory dump test runs
[ ] Static analysis with zero warnings
```

### 31.2 Regression Protection

```
File: test/security/regression/test_regression_suite.dart

VERIFY FIXES STAY FIXED:
[ ] Header parser RangeError fix (from fuzzing bug): regression test
[ ] Any future security fix: mandatory regression test
[ ] Regression tests reference the issue/PR that fixed them

METHOD:
- For every security bug found, add test that reproduces it
- Test must fail before fix, pass after fix
- Never remove regression tests
- Tag tests with issue numbers
```

---

## 32. Protocol-Level Attack Simulation

### 32.1 Active MITM During Sync

```
File: test/security/attacks/test_sync_mitm.dart

ATTACK SCENARIOS:
[ ] Intercept Noise handshake, substitute keys
[ ] Replay handshake with modified PSK
[ ] Inject sync data during established session
[ ] Downgrade attack: attempt older protocol version
[ ] Split brain: sync with two different peers simultaneously

VERIFY:
[ ] Key substitution: detected by TOFU (different key hash)
[ ] Modified PSK: handshake MAC failure
[ ] Injected data: rejected by session MAC
[ ] Downgrade: version check rejects older versions
[ ] Split brain: conflict detection, no data loss

METHOD:
- Implement attacker proxy between two sync instances
- Proxy modifies messages according to attack scenario
- Verify legitimate peers detect and reject
- Verify no data corruption on legitimate side
```

### 32.2 Clipboard History Poisoning

```
File: test/security/attacks/test_clipboard_attack.dart

ATTACK SCENARIOS:
[ ] Clipboard manager with sensitive flag disabled (simulated)
[ ] Malicious app reads clipboard during 30-second window
[ ] Clipboard content persists after app kill

VERIFY:
[ ] Sensitive MIME type prevents most managers from logging
[ ] On Android: FLAG_CLIPBOARD_PRIMARY_ACCESS restricts access
[ ] Clipboard cleared on app termination (best effort)
[ ] Documented limitation: OS-level clipboard may persist

METHOD:
- On Linux: simulate CopyQ without sensitive flag support
- On Android: attempt clipboard read from another app
- Document actual behavior in SECURITY.md
```

---

## Execution Priority (Post-Pass)

```
Immediate (before any external discussion):
  21.1 Vault state transitions
  21.2 Sync state machine
  23.1 Grammar-based vault fuzzer
  24.1 Lock during crypto operation
  25.1 Power loss simulation
  31.2 Regression protection

Short-term (next sprint):
  22.1 Crypto model conformance
  22.2 Format model
  23.2 Sync protocol fuzzer
  26.1 TOTP differential
  26.2 Argon2 differential
  28.1 Statistical timing

Medium-term (next month):
  27.1 Dependency verification
  27.2 Build reproducibility
  27.3 libsodium provenance
  29.1 Multi-vault scenarios
  29.2 Edge case vaults
  30.1-30.3 Audit package preparation

Ongoing:
  31.1 CI/CD security workflow
  32.1-32.2 Active attack simulation
```
