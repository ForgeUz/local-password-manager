# Security Policy

## Local-first, no servers

This is a local-first application. There are no servers, no cloud sync, no telemetry, and no vendor-controlled infrastructure. The only network egress is opt-in breach monitoring, which sends a 5-character SHA-1 prefix of a password hash to the HIBP k-anonymity API (or uses a fully offline corpus).

## Zero-Recovery warning

If you lose your master password AND your Shamir recovery shares, your data is permanently gone. There is no backdoor, no reset, no cloud copy, and no vendor assistance path. This is by design (zero-recovery-by-design). Back up your Shamir shares physically and keep them separate from the device.

## Threat model

- **File-only attacker:** learns entry count and (before padding) domain length. Tags are opaque pseudorandom blobs without the SearchKey (requires the VRK, requires the MP).
- **Memory attacker:** mitigated by native secure memory (`sodium_malloc`/`mlock`), zero-wipe on lock, and a seccomp deny-list blocking `ptrace`/`process_vm_*`.
- **Coercion:** duress vault + honeypot canaries + group shred. A coercer holding BOTH passwords defeats the scheme (stated honestly in the UI).
- **Patched build:** device-enforced policies (cooldowns, time-locks) are honest-path enforcement, not math. A patched build can bypass them.

## Reporting a vulnerability

Please report security vulnerabilities **privately** via GitHub private advisories (Security → Advisories → New draft advisory) or by emailing the maintainer (address in the repository profile).

Please include:
- Affected version / commit.
- A minimal reproduction (steps, inputs).
- Impact assessment (what an attacker gains).

We will acknowledge within 5 business days and aim for a fix + advisory within 30 days. **Do not open a public issue for a security vulnerability.**

## Responsible disclosure

- No public disclosure until a fix is released.
- No exploitation beyond demonstrating the vulnerability.
- We credit reporters in the advisory (unless anonymity is requested).

## Supported versions

| Version | Status |
|---------|--------|
| v1.0.0 (current) | Supported |
| Older | Not supported |

## Build integrity

Release builds publish `build_hash.txt` (SHA-256 of the release binary). The `IntegrityHeartbeat` can verify the running binary against this manifest at runtime (advisory). Community members can rebuild from source and compare hashes (see [`tool_versions`](tool_versions) for the pinned toolchain).

## Post-audit hardening

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

## Mutation testing

The crypto core is covered by an extended mutation campaign with **51 mutations** across the entire Trusted Computing Base:

| Group | Mutations | Invariants Tested |
|-------|-----------|-------------------|
| vault_crypto_v4 | 15 | format, outer GCM, MP change, duress, memory zeroing |
| key_hierarchy | 5 | VRK derivation, DEK wrap/unwrap, CSPRNG |
| header | 8 | parser, bounds checks, endianness |
| padding | 4 | bucket masking, CSPRNG |
| second_factor | 6 | rate-limit, single-use, constant-time, memory zeroing |
| duress | 2 | domain separation |
| search_tag | 5 | SearchKey zeroing, bucket padding, normalization |
| argon2id | 3 | FFI memory zeroing, fail-closed |
| aes_gcm | 2 | FFI memory zeroing, AES-NI check |
| hkdf | 1 | PRK zeroing |

**Result: 51/51 killed (100% kill score)**

All mutations target specific security invariants. A "killed" result means the test suite detected the invariant violation. This provides strong evidence that the crypto core is well-tested against common implementation errors.

**Limitations:**
- Mutation testing covers only what is encoded as a mutation. It does not replace external cryptographic audit.
- `V4VaultEntry.password` remains a Dart `String` in the UI model (unavoidable Flutter limitation). The crypto core never holds it as String.
- Equivalent mutants (security-only, not functional) are documented but not counted as gaps.

## Security audit

See [`SECURITY_AUDIT.md`](SECURITY_AUDIT.md) for:
- The pre-release native-memory audit (all secrets handled in `SecureBuffer`/FFI memory with immediate `memzero`)
- The Linux clipboard sensitive-MIME fix (password copies set `text/plain;charset=utf-8;sensitive=true` so clipboard managers do not log history)
- Post-audit hardening details and extended mutation campaign results (51/51 killed)