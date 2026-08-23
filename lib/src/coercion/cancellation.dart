import 'dart:math';
import 'dart:typed_data';
import '../crypto/native/argon2id.dart';
import '../crypto/native/constant_time.dart';

// Intent: v5 E21 — duress cancellation code storage + rate limiting.
// The 8-digit code is stored Argon2id-hashed (never plaintext). 3 wrong
// attempts -> full duress re-setup required. No session-path cancellation
// exists: the decoy session cannot cancel; only this code path can.
// Invariants: code never plaintext on disk; 3 wrong attempts -> locked;
// verification is constant-time.
// State Transition: setup(code) -> stored hash + attempts=0; verify(code) ->
// true | attempts++ | locked (>=3).
// Dependencies: Argon2id, ConstantTime, dart:math, dart:typed_data.

class CancellationCode {
  static const int _maxAttempts = 3;
  static const int _saltSize = 16;
  static const int _hashSize = 32;

  // Hash the 8-digit code with a fresh salt. Returns the stored blob:
  //   [salt(16)][attempts(1)][Argon2id hash(32)]
  static Uint8List setup(String code) {
    final salt = _randomBytes(_saltSize);
    final hash = _hashCode(code, salt);
    final out = Uint8List(_saltSize + 1 + _hashSize);
    out.setRange(0, _saltSize, salt);
    out[_saltSize] = 0; // attempts
    out.setRange(_saltSize + 1, out.length, hash);
    return out;
  }

  // Verify a submitted code against the stored blob. Returns true on match.
  // On wrong code, increments the attempt counter (persisted in the returned
  // updated blob). Throws CancellationLockedError when attempts >= 3.
  static bool verify(String code, Uint8List stored) {
    final salt = stored.sublist(0, _saltSize);
    final attempts = stored[_saltSize];
    final hash = stored.sublist(_saltSize + 1);
    if (attempts >= _maxAttempts) throw CancellationLockedError();
    final candidate = _hashCode(code, salt);
    if (ConstantTime.equals(candidate, hash)) return true;
    // Wrong code: increment attempts. The caller persists the updated blob.
    stored[_saltSize] = attempts + 1;
    if (attempts + 1 >= _maxAttempts) throw CancellationLockedError();
    return false;
  }

  static Uint8List _hashCode(String code, Uint8List salt) {
    return Argon2id.derive(
      Uint8List.fromList(code.codeUnits),
      salt,
      memory: 65536,
      iterations: 3,
      parallelism: 1,
    );
  }

  static Uint8List _randomBytes(int length) {
    final r = Random.secure();
    return Uint8List.fromList(List.generate(length, (_) => r.nextInt(256)));
  }
}

// E21: 3 wrong attempts -> full duress re-setup required.
class CancellationLockedError implements Exception {}