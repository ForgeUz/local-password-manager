# Vault Crypto — Differential Analysis

**Version:** V6.5.1

## Purpose

Differential testing compares our implementation against independent reference
implementations to catch FFI parameter-marshalling bugs, endianness errors, and
time-calculation bugs.

## 1. HKDF-SHA256 (RFC 5869)

- **Reference:** Pure-Dart RFC 5869 implementation in
  `test/security/model/reference_crypto.dart` (over `package:crypto` HMAC).
- **Test:** `test/security/model/test_crypto_model.dart` — 100 random vectors,
  empty/max-length inputs, edge-case output lengths.
- **Result:** libsodium HKDF output == reference output (byte-for-byte).

## 2. HMAC-SHA256 (RFC 4231)

- **Reference:** `package:crypto` HMAC.
- **Test:** `test/security/model/test_crypto_model.dart` — 100 random vectors.
- **Result:** libsodium HMAC output == reference output.

## 3. TOTP (RFC 6238)

- **Reference:** RFC 6238 Appendix B test vectors (the canonical
  cross-implementation source, equivalent to pyotp/otpauth).
- **Test:** `test/security/differential/test_totp_differential.dart` — SHA1,
  SHA256, SHA512; 6 and 8 digits; 30/60/90s periods.
- **Result:** All RFC 6238 vectors match.

## 4. Argon2id

- **Reference:** Standard parameters (m=65536, t=3, p=1) with deterministic
  output.
- **Test:** `test/security/differential/test_argon2_differential.dart`.
- **Result:** Deterministic, 32-byte output, avalanche on salt/password change.

## How to extend

To add a new differential test:
1. Generate test vectors in the reference implementation (Python/JS/CLI).
2. Save to a JSON fixture.
3. Load in a Dart test, run our implementation, compare byte-for-byte.
4. Any mismatch indicates an FFI marshalling bug — investigate parameter order,
   endianness, and sizes.
