# Vault Crypto — Zero-Cloud, Zero-Trust, Zero-Recovery Password Manager

A local-first password manager for Linux and Android. No cloud, no server, no telemetry. Your vault is a single encrypted file on your device; nothing ever leaves it unless you explicitly opt in to prefix-only breach monitoring.

**Zero-Recovery by design:** if you lose your master password AND your Shamir recovery shares, your data is gone. There is no backdoor, no vendor reset, no cloud copy. This is a feature, not a bug.

---

## Doctrine

- **Zero-Cloud** — the only egress is opt-in breach monitoring (5-char SHA-1 prefix, or an offline corpus). No server, no relay, no telemetry.
- **Zero-Trust** — every input (MP, TOTP, backup code, PIN, peer, clock, file) is treated as hostile until math proves otherwise.
- **Zero-Recovery-by-design** — no backdoor. Inheritance is opt-in and fully self-custodied.
- **No home-rolled crypto** — audited bindings only (libsodium FFI).
- **Sync optional** — removing the entire sync module leaves a fully working offline password manager.

---

## Features (V4/V5)

- **Per-entry DEK hierarchy** — each entry has its own CSPRNG DEK wrapped under a VRK derived from your master password. Destroying one DEK shreds exactly one entry.
- **Single-file GEN4 format** — one encrypted file, two slots (primary + decoy), structurally deniable. No separate decoy file exists on disk, ever.
- **Duress vault** — a secondary password opens an isolated, plausible-looking vault. The UI never reveals the mechanism.
- **KDF-bound 2FA** — TOTP is folded into the key derivation (math, not a check). Backup codes release the second-factor material through the real KDF path.
- **Companion-device push approval** — 2-digit number-matching challenge with 3 options, rate-limited (defeats relay/phishing).
- **FIDO2 hardware-key factor** — a P-256 signature is folded into the KDF (keylogger-immune; wrong key fails at GCM).
- **Shamir recovery kit** — split your master key into N shares; any K reconstruct it. Fully offline.
- **True SSE search** — searchable symmetric encryption with bucket-padded tags; no domain decryption during search.
- **Honeypot canaries** — realistic fake entries that trigger lock + lockdown on access.
- **Atomic MP change** — re-wraps all DEKs + recomputes all search tags in one temp-file-then-rename save.
- **Group shred + deferral** — duress shred is a group operation across paired devices, with cancellation propagation and offline deferral.
- **Liveness/inheritance** — signed epoch tokens + K-of-N shares + friction chain for opt-in inheritance.
- **Sensitive clipboard MIME** — Linux copies set `text/plain;charset=utf-8;sensitive=true` so clipboard managers (CopyQ/Diodon/Klipper) don't log password history.
- **Local security dashboard** — duplicate/weak/old password analysis, fully local.
- **Seccomp deny-list** — blocks only the scraping/attach syscalls (ptrace, process_vm_*, kcmp, perf_event_open); Dart-VM-safe.

---

## What's New in V6.5 (Mass-User Readiness)

V6.5 adds features required for mass adoption while preserving the zero-cloud doctrine. The full suite is 240 tests, all passing.

### Security Tiers (Standard / Sensitive / Critical)

Per-entry security classification with progressive authentication requirements:

- **Standard** (streaming, forums): Autofill immediate, reveal with single tap, edit requires biometric.
- **Sensitive** (email, shopping): Autofill with 5-second delay + re-auth prompt, reveal requires biometric, edit requires biometric.
- **Critical** (banking, crypto, government): **Manual autofill only** (user must type), reveal requires master password + biometric, export blocked.

Tier assignment is user-controlled (advisory suggestions based on domain). Downgrades require explicit confirmation. Tiers are stored in the encrypted vault blob (attacker cannot silently downgrade).

**Enforcement points:**
- Android Autofill Service respects tier (critical entries never autofill)
- UI blocks export for critical entries
- TOTP auto-copy disabled for critical tier

### Built-in TOTP Generator (RFC 6238)

Native TOTP (Time-based One-Time Password) generator compliant with RFC 6238:

- **Import methods:** QR code scanner (otpauth:// URI), manual entry, bulk import from Google Authenticator export format
- **Algorithms:** SHA1 (default), SHA256, SHA512
- **Digits:** 6 or 8 (configurable per entry)
- **Period:** 30 seconds (configurable)
- **Display:** Current code with circular countdown timer, next code preview, copy to clipboard with 30-second auto-clear
- **Validation:** ±1 window tolerance for clock drift
- **Security:** TOTP secrets stored in vault (encrypted with per-entry DEK), never logged or exposed in plaintext after import

**Doctrine compliance:** No cloud dependency. TOTP codes generated locally. Secrets stored in encrypted vault.

### P2P BLE Sync (Offline Pairing)

Peer-to-peer device synchronization via Bluetooth Low Energy (10-meter range):

- **Pairing protocol:** High-entropy passphrase (≥12 characters, zxcvbn score ≥3) shared between devices
- **PSK derivation:** Argon2id(passphrase, salt, 64 MiB, 3 iterations) raises offline dictionary cost
- **Transport:** BLE for discovery + WiFi Direct for bulk transfer (Android Nearby Connections API)
- **Security:** Noise NNpsk0 handshake with TOFU (Trust-On-First-Use) pinning, 60-second pairing window, max 3 attempts before cooldown
- **Conflict resolution:** Manual (user chooses which version to keep), no auto-merge
- **Tombstones:** Deleted entries stay deleted (30-day TTL prevents resurrection)

**Honest limitations:**
- Both devices must be online simultaneously (no async sync)
- 10-meter BLE range enforced by physics (not software)
- Pairing passphrase must be kept secret (if leaked, nearby attacker could sync)

**Doctrine compliance:** No cloud relay. Data never leaves local network. User controls pairing.

### Android Autofill Service (Android 13+)

Native Android Autofill Framework integration:

- **Domain extraction:** Trusted source (`AssistStructure.webDomain`), not spoofable page title
- **Lookalike detection:** Homoglyph check (0/o, 1/l/i, 5/s), edit distance ≤1, subdomain impersonation detection
- **Tier enforcement:** Critical tier → null FillResponse (hard stop, user must type manually)
- **Security:** Vault must be unlocked (biometric/master) before credentials released
- **Digital Asset Links:** App-domain association prevents phishing

**Permissions (Android 13+):**
- `BLUETOOTH_CONNECT`, `BLUETOOTH_SCAN`, `BLUETOOTH_ADVERTISE` (BLE sync)
- `NEARBY_WIFI_DEVICES` (WiFi Direct bulk transfer)
- `USE_BIOMETRIC` (fingerprint unlock)
- `CAMERA` (TOTP QR import)

**Doctrine compliance:** `allowBackup=false` in manifest prevents Android auto-backup to Google Drive.

---

## Security Hardening (Post-Audit)

Following the initial security audit, the following hardening was applied to the Trusted Computing Base (TCB):

### Native Memory Zeroing (FFI)

`sodium_memzero` added before `calloc.free` in all FFI wrappers:
- `argon2id.dart`: MK, password copy, salt copy
- `aes_gcm.dart`: key, plaintext, ciphertext buffers
- `hkdf.dart`: PRK (native path), IKM (native path)

Dart-side zeroing via `fillRange(0, length, 0)`:
- `key_hierarchy.dart`: IKM (MK || TOTP)
- `vault_crypto_v4.dart`: MK, VRK, DEK after use
- `second_factor.dart`: candidate hash, SFM
- `search_tag.dart`: SearchKey

### Bounds Checking (Parser Hardening)

- `header.dart`: Added sanity checks for DEK length (max 1024), ciphertext length (max 1MB), tag count (max 100), vector clock length (max 256)
- `header.dart`: Added `checkBounds()` helper to prevent buffer overflow on malformed input
- `second_factor.dart`: Added bounds validation for SFM file structure

### AES-NI Hardware Check

- `aes_gcm.dart`: Added `crypto_aead_aes256gcm_is_available()` check, fail-closed if unsupported

### Error Oracle Prevention

- Unified all parsing/decryption errors to `CorruptBlobError` or `DecryptionFailedError` (no information leakage via exception types)
- `padding.dart`: All `FormatException` replaced with `CorruptBlobError`

### URL Normalization (Search Tags)

- `search_tag.dart`: Added stripping of `http://`, `https://`, `ftp://` schemes
- Added minimum query length (3 chars) to prevent FP flood

---

## Build & Run

### Linux (Mint/Ubuntu)

Install dependencies (see `linux/DEPS.md`):

```bash
sudo apt update && sudo apt install -y \
  clang cmake ninja-build pkg-config \
  libgtk-3-dev liblzma-dev libstdc++-12-dev \
  libsodium-dev libseccomp-dev \
  libx11-dev libxtst-dev libayatana-appindicator3-dev libportal-dev
```

Run (dev):

```bash
flutter pub get
flutter run -d linux
```

**Install as a desktop app** (builds release, installs to `/opt/vault_crypto`, creates a menu launcher + icon):

```bash
./install_linux.sh
# Launch from the app menu ("Vault Crypto"), or run: /opt/vault_crypto/vault_crypto
```

Release build with integrity hash:

```bash
./build_linux.sh   # builds --release + writes build_hash.txt
```

> **Note:** P2P BLE sync is **Android-only** (Nearby Connections). On Linux the
> Sync screen shows a "not available" message; the rest of the app is fully
> functional.

### Android (13+)

Install dependencies (see `android/DEPS.md`):

```bash
sudo apt install openjdk-17-jdk
# Install Android SDK, NDK, platform-tools
# Set ANDROID_HOME, JAVA_HOME
```

**Bundle libsodium (required — Android has no system libsodium).** The Dart
crypto layer loads `libsodium.so` via `dart:ffi`; it must be present in
`android/app/src/main/jniLibs/<abi>/`. Prebuilt `.so` for `arm64-v8a` and
`armeabi-v7a` are committed. To rebuild them from source (uses your NDK):

```bash
./build_android_sodium.sh
```

Build APK:

```bash
flutter pub get
flutter build apk --release
```

Install on device:

```bash
adb install build/app/outputs/flutter-apk/app-release.apk
```

**First-run setup:**
1. Enable Autofill Service: Settings → System → Languages & input → Autofill service → Vault Crypto
2. Grant permissions: Biometric, Bluetooth, Camera (for TOTP QR import)
3. Create master password (zxcvbn score ≥3 recommended)
4. Setup recovery (Shamir shares or encrypted backup)

---

## Tests

```bash
flutter test        # 240 tests (all pass)
flutter analyze     # 0 errors (remaining items are pre-existing info/warnings)
dart run tool/mutation_campaign.dart   # mutation kill score (100%, 51/51 applied)
```

**Test coverage:**
- 240 unit + integration tests (all passing)
- 51 mutations covering the entire Trusted Computing Base (TCB)
- 100% mutation kill score (all security invariants verified)
- RFC 6238 compliance tests for TOTP (SHA1/SHA256/SHA512)
- Security tier policy tests (21 tests)
- P2P pairing protocol tests (state machine, PSK derivation)
- Lookalike domain detection tests

---

## Roadmap (V6)

See `v6_delta.md` for detailed roadmap:

- **P0:** External cryptographic audit (recruiting auditors)
- **P1:** Publish project + gather community feedback
- **P2:** Onboarding flow design (progressive disclosure)
- **P3:** Recovery UX design (guided Shamir reconstruction)
- **P4-P5:** Android device verification (real hardware testing)
- **P6:** TPM sealing (Linux hardware-backed key storage)
- **P7:** Noise PQ-hybrid transport (post-quantum future-proofing)
- **P8:** Runtime integrity attestation (advisory)

---

## Honest Limitations

- A knowledgeable attacker can suspect deniability exists but cannot prove it.
- A coercer holding BOTH passwords defeats the scheme.
- Wayland global-shortcut portal is a documented limitation (X11 grab is the working path).
- Behavioral biometrics is an anomaly deterrent, never authentication; FP/FN are measured empirically, not fabricated.
- Mutation testing covers only what is encoded as a mutation. It does not replace external cryptographic audit.
- `V4VaultEntry.password` remains a Dart `String` in the UI model (unavoidable Flutter limitation). The crypto core never holds it as String.
- **V6.5:** P2P sync requires both devices online simultaneously (no async sync). BLE range ~10m is a physical limitation, not software-enforced. TOTP secrets stored in vault (single point of failure if vault compromised). Security tiers are advisory (determined user can bypass UI).

---

## Contributing

See `CONTRIBUTING.md` for development discipline and how to contribute.

---

## License

MIT License. See `LICENSE` for details.

---

## Security Policy

See `SECURITY.md` for threat model, vulnerability reporting, and security contacts.

---

## Audit Status

See `SECURITY_AUDIT.md` for internal audit results and hardening applied.

**Current status:** Internal audit complete (51/51 mutation kill). External audit pending (recruiting auditors).

---

## Links

- **GitHub:** https://github.com/ForgeUz/local-password-manager
- **Issues:** https://github.com/ForgeUz/local-password-manager/issues
- **Security:** See `SECURITY.md`
- **Audit Brief:** See `AUDIT_BRIEF_V65.md`