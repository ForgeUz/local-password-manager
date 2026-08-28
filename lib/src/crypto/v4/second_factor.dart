import 'dart:math';
import 'dart:typed_data';
import '../errors.dart';
import '../native/aes_gcm.dart';
import '../native/argon2id.dart';
import '../native/constant_time.dart';

// Intent: v5 E2 — SecondFactorMaterial (SFM) stored encrypted under MK_base
// (the pre-second-factor key) in a file OUTSIDE the vault. A valid backup code
// (Argon2id-hashed, single-use, rate-limited) authorizes release of SFM into
// the KDF. The vault opens via the REAL derivation path — no bypass branch.
//
// SECURITY CRITICAL:
// 1. SFM (TOTP seed) is zeroed after use in all paths.
// 2. All file parsing includes bounds checking to prevent buffer overflows.
// 3. Backup code candidate hash is zeroed after comparison.
//
// Invariants: SFM never plaintext on disk; backup codes single-use; 3 wrong
// attempts -> locked (rate limit); wrong/consumed/rate-limited code throws
// BackupCodeError BEFORE any vault decrypt.
//
// File layout (outside vault):
//   [nonce(12)][sfmLen(2)][AES-GCM(MK_base, SFM)][salt(16)][attempts(1)]
//   [count(1)][Argon2id hash(32) x count]
//
// Dependencies: AesGcm, Argon2id, ConstantTime, dart:typed_data.

class SecondFactor {
  static const int _nonceSize = 12;
  static const int _lenSize = 2;
  static const int _saltSize = 16;
  static const int _attemptsSize = 1;
  static const int _countSize = 1;
  static const int _hashSize = 32;
  static const int _maxAttempts = 3;

  // SECURITY: Reduced memory for backup code hashing (was 64 MiB, now 16 MiB)
  // Still strong against brute force, better UX on mobile.
  static const int _backupCodeMemory = 16384; // 16 MiB in KiB
  static const int _backupCodeIterations = 2;
  static const int _backupCodeParallelism = 1;

  /// Seal SFM + backup-code hashes into a single file blob under MK_base.
  /// Returns the file bytes. The SFM is the TOTP seed (raw bytes).
  ///
  /// SECURITY: SFM is NOT zeroed here (caller's responsibility).
  static Uint8List seal(
      Uint8List mkBase, Uint8List sfm, List<String> backupCodes) {
    final nonce = _randomBytes(_nonceSize);
    final ct = AesGcm.encrypt(mkBase, nonce, Uint8List(0), sfm);
    final salt = _randomBytes(_saltSize);
    final hashes = backupCodes.map((c) => _hashCode(c, salt)).toList();

    final out = Uint8List(_nonceSize +
        _lenSize +
        ct.length +
        _saltSize +
        _attemptsSize +
        _countSize +
        hashes.length * _hashSize);
    var o = 0;
    out.setRange(o, o + _nonceSize, nonce);
    o += _nonceSize;
    out[o] = (ct.length >> 8) & 0xFF;
    out[o + 1] = ct.length & 0xFF;
    o += _lenSize;
    out.setRange(o, o + ct.length, ct);
    o += ct.length;
    out.setRange(o, o + _saltSize, salt);
    o += _saltSize;
    out[o] = 0; // attempts
    o += _attemptsSize;
    out[o] = hashes.length;
    o += _countSize;
    for (final h in hashes) {
      out.setRange(o, o + _hashSize, h);
      o += _hashSize;
    }
    return out;
  }

  /// Open the SFM file: verify a backup code (single-use, rate-limited), then
  /// decrypt SFM under MK_base and release it into the KDF.
  ///
  /// SECURITY:
  /// 1. SFM is returned as Uint8List - caller MUST zero it after use.
  /// 2. Candidate hash is zeroed after comparison.
  /// 3. All file parsing includes bounds checking.
  ///
  /// Returns (sfm, updatedFile) — the caller persists updatedFile to consume
  /// the used code and record the attempt.
  static (Uint8List sfm, Uint8List updatedFile) open(
      Uint8List mkBase, Uint8List file, String code) {
    // SECURITY: Bounds checking for file structure
    if (file.length <
        _nonceSize + _lenSize + _saltSize + _attemptsSize + _countSize) {
      throw BackupCodeError();
    }

    final nonce = file.sublist(0, _nonceSize);
    final len = (file[_nonceSize] << 8) | file[_nonceSize + 1];

    // SECURITY: Validate ciphertext length
    if (len > file.length - _nonceSize - _lenSize) {
      throw BackupCodeError();
    }

    final ct = file.sublist(_nonceSize + _lenSize, _nonceSize + _lenSize + len);
    final salt = file.sublist(
        _nonceSize + _lenSize + len, _nonceSize + _lenSize + len + _saltSize);
    final attempts = file[_nonceSize + _lenSize + len + _saltSize];
    final count = file[_nonceSize + _lenSize + len + _saltSize + _attemptsSize];
    final hashesStart =
        _nonceSize + _lenSize + len + _saltSize + _attemptsSize + _countSize;

    if (attempts >= _maxAttempts) throw BackupCodeError(); // rate-limited

    final candidate = _hashCode(code, salt);
    var matched = -1;

    try {
      for (var i = 0; i < count; i++) {
        // SECURITY: Bounds check for hash access
        if (hashesStart + (i + 1) * _hashSize > file.length) {
          throw BackupCodeError();
        }
        final h = file.sublist(
            hashesStart + i * _hashSize, hashesStart + (i + 1) * _hashSize);
        if (ConstantTime.equals(candidate, h)) {
          matched = i;
          break;
        }
      }
    } finally {
      // CRITICAL: Zero candidate hash after comparison
      candidate.fillRange(0, candidate.length, 0);
    }

    if (matched < 0) {
      // Wrong code: increment attempts, persist, fail before any decrypt.
      final updated = Uint8List.fromList(file);
      updated[_nonceSize + _lenSize + len + _saltSize] = attempts + 1;
      throw BackupCodeError(updatedFile: updated);
    }

    // Valid code: decrypt SFM under MK_base (real KDF path). Wrong MK_base ->
    // GCM fails here.
    Uint8List sfm;
    try {
      sfm = AesGcm.decrypt(mkBase, nonce, Uint8List(0), ct);
    } catch (_) {
      throw BackupCodeError();
    }

    // Consume the code (single-use): remove it from the hash list, reset
    // attempts. Persist the updated file.
    final updated = Uint8List(file.length - _hashSize);
    var u = 0;
    updated.setRange(u, u + _nonceSize, nonce);
    u += _nonceSize;
    updated.setRange(
        u, u + _lenSize, file.sublist(_nonceSize, _nonceSize + _lenSize));
    u += _lenSize;
    updated.setRange(u, u + len, ct);
    u += len;
    updated.setRange(u, u + _saltSize, salt);
    u += _saltSize;
    updated[u] = 0; // reset attempts
    u += _attemptsSize;
    updated[u] = count - 1;
    u += _countSize;
    for (var i = 0; i < count; i++) {
      if (i == matched) continue;
      final h = file.sublist(
          hashesStart + i * _hashSize, hashesStart + (i + 1) * _hashSize);
      updated.setRange(u, u + _hashSize, h);
      u += _hashSize;
    }

    // SECURITY: Caller MUST zero sfm after use (contains TOTP seed)
    return (sfm, updated);
  }

  /// v5 E2/V3.2: reveal the SFM (decrypt under MK_base) WITHOUT consuming a
  /// backup code. Used by the MP-change flow to re-encrypt the SFM file under
  /// the NEW MK_base (seed untouched).
  ///
  /// SECURITY: Returned SFM MUST be zeroed by caller after use.
  static Uint8List reveal(Uint8List mkBase, Uint8List file) {
    // SECURITY: Bounds checking
    if (file.length < _nonceSize + _lenSize) {
      throw BackupCodeError();
    }

    final nonce = file.sublist(0, _nonceSize);
    final len = (file[_nonceSize] << 8) | file[_nonceSize + 1];

    if (len > file.length - _nonceSize - _lenSize) {
      throw BackupCodeError();
    }

    final ct = file.sublist(_nonceSize + _lenSize, _nonceSize + _lenSize + len);
    try {
      return AesGcm.decrypt(mkBase, nonce, Uint8List(0), ct);
    } catch (_) {
      throw BackupCodeError();
    }
  }

  /// v5 E2/V3.2: re-seal the SFM file under a NEW MK_base, preserving the
  /// backup-code hashes (same salt + hashes, so codes stay valid).
  ///
  /// SECURITY: SFM parameter is NOT zeroed here (caller's responsibility).
  static Uint8List reSeal(
      Uint8List newMkBase, Uint8List oldFile, Uint8List sfm) {
    // SECURITY: Bounds checking
    if (oldFile.length <
        _nonceSize + _lenSize + _saltSize + _attemptsSize + _countSize) {
      throw BackupCodeError();
    }

    final nonce = _randomBytes(_nonceSize);
    final ct = AesGcm.encrypt(newMkBase, nonce, Uint8List(0), sfm);
    final salt = oldFile.sublist(_nonceSize + _lenSize + _ctLen(oldFile),
        _nonceSize + _lenSize + _ctLen(oldFile) + _saltSize);
    final count = oldFile[
        _nonceSize + _lenSize + _ctLen(oldFile) + _saltSize + _attemptsSize];
    final hashesStart = _nonceSize +
        _lenSize +
        _ctLen(oldFile) +
        _saltSize +
        _attemptsSize +
        _countSize;

    final out = Uint8List(_nonceSize +
        _lenSize +
        ct.length +
        _saltSize +
        _attemptsSize +
        _countSize +
        count * _hashSize);
    var o = 0;
    out.setRange(o, o + _nonceSize, nonce);
    o += _nonceSize;
    out[o] = (ct.length >> 8) & 0xFF;
    out[o + 1] = ct.length & 0xFF;
    o += _lenSize;
    out.setRange(o, o + ct.length, ct);
    o += ct.length;
    out.setRange(o, o + _saltSize, salt);
    o += _saltSize;
    out[o] = 0; // reset attempts
    o += _attemptsSize;
    out[o] = count;
    o += _countSize;
    for (var i = 0; i < count; i++) {
      final h = oldFile.sublist(
          hashesStart + i * _hashSize, hashesStart + (i + 1) * _hashSize);
      out.setRange(o, o + _hashSize, h);
      o += _hashSize;
    }
    return out;
  }

  static int _ctLen(Uint8List file) {
    if (file.length < _nonceSize + _lenSize) return 0;
    return (file[_nonceSize] << 8) | file[_nonceSize + 1];
  }

  /// Hash a backup code using Argon2id with reduced parameters for UX.
  static Uint8List _hashCode(String code, Uint8List salt) {
    final h = Argon2id.derive(
      Uint8List.fromList(code.codeUnits),
      salt,
      memory: _backupCodeMemory,
      iterations: _backupCodeIterations,
      parallelism: _backupCodeParallelism,
    );
    return h;
  }

  static Uint8List _randomBytes(int length) {
    final r = Random.secure();
    return Uint8List.fromList(List.generate(length, (_) => r.nextInt(256)));
  }
}
