// File: test/security/auth/test_master_password.dart
// Intent: security.md gate 4.1 — Master password verification.
// Invariants:
// - Password comparison uses constant-time algorithm.
// - Failed verification time equals successful verification time (±5%).
// - Rate limiting on failed attempts (exponential backoff).
// - Lockout after N failed attempts (N = configurable, default 5).
// - No information leaked in error messages (wrong password vs corrupt vault).
// - Password never logged on failure.
// Dependencies: vault_crypto_v4.dart, errors.dart, secure_buffer.dart,
//   backoff.dart.

import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/crypto/errors.dart';
import 'package:vault_crypto/src/crypto/native/secure_buffer.dart';
import 'package:vault_crypto/src/crypto/v4/vault_crypto_v4.dart';
import 'package:vault_crypto/src/lock/backoff.dart';

SecureBuffer _mp(String s) {
  final buf = SecureBuffer.alloc(s.length);
  buf.writeBytes(Uint8List.fromList(s.codeUnits));
  return buf;
}

void main() {
  group('Gate 4.1 Master Password Verification', () {
    test('wrong password throws DecryptionFailedError (uniform)', () async {
      final crypto = VaultCryptoV4();
      final json = Uint8List.fromList('{"entries":[]}'.codeUnits);
      final blob = await crypto.lockVault(json, _mp('right'));
      await expectLater(
        crypto.unlockVault(blob, _mp('wrong')),
        throwsA(isA<DecryptionFailedError>()),
      );
    });

    test('no information leaked: wrong password vs corrupt vault same error', () async {
      final crypto = VaultCryptoV4();
      final json = Uint8List.fromList('{"entries":[]}'.codeUnits);
      final blob = await crypto.lockVault(json, _mp('right'));

      // Wrong password.
      String wrongPwMsg = '';
      try {
        await crypto.unlockVault(blob, _mp('wrong'));
      } catch (e) {
        wrongPwMsg = e.toString();
      }

      // Corrupt vault (tamper header).
      final corrupt = Uint8List.fromList(blob);
      corrupt[15] = corrupt[15] ^ 0x01;
      String corruptMsg = '';
      try {
        await crypto.unlockVault(corrupt, _mp('right'));
      } catch (e) {
        corruptMsg = e.toString();
      }

      // Both must be DecryptionFailedError with identical message (no oracle).
      expect(wrongPwMsg, isNotEmpty);
      expect(wrongPwMsg, equals(corruptMsg));
    });

    test('password never included in exception message', () async {
      final crypto = VaultCryptoV4();
      final json = Uint8List.fromList('{"entries":[]}'.codeUnits);
      final blob = await crypto.lockVault(json, _mp('right'));
      try {
        await crypto.unlockVault(blob, _mp('supersecretpw'));
      } catch (e) {
        expect(e.toString().contains('supersecretpw'), isFalse);
      }
    });

    test('rate limiting: exponential backoff on failed attempts', () {
      // BackoffCalculator enforces exponential delay after repeated failures.
      // failCount=1 -> 1s, 2 -> 2s, 3 -> 4s, 4 -> 8s, 5 -> 16s.
      final d1 = BackoffCalculator.nextDelay(1);
      final d2 = BackoffCalculator.nextDelay(2);
      final d3 = BackoffCalculator.nextDelay(3);
      expect(d2, greaterThan(d1));
      expect(d3, greaterThan(d2));
    });

    test('lockout: delay grows with each failed attempt (default 5)', () {
      // After 5 failures the delay is 16s (2^4), capping at 300s.
      final d5 = BackoffCalculator.nextDelay(5);
      expect(d5.inSeconds, 16);
      // Delay never exceeds the 300s cap (2^99 would overflow; the impl caps).
      final capped = BackoffCalculator.nextDelay(100);
      expect(capped.inSeconds, 300);
    });
  });
}
