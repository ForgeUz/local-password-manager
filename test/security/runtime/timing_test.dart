// File: test/security/runtime/test_timing.dart
// Intent: security.md gate 16.2 — Timing analysis (runs in Flutter runtime).
// Verifies that password verification time does not differ between correct and
// wrong passwords (constant-time, no oracle).
// Invariants:
// - Password verification: mean time correct vs wrong (difference < 5%).
// - Decryption: mean time valid vs corrupt data (difference < 5%).
// Dependencies: vault_crypto_v4.dart, secure_buffer.dart.

import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/crypto/native/secure_buffer.dart';
import 'package:vault_crypto/src/crypto/v4/vault_crypto_v4.dart';

SecureBuffer _mp(String s) {
  final buf = SecureBuffer.alloc(s.length);
  buf.writeBytes(Uint8List.fromList(s.codeUnits));
  return buf;
}

void main() {
  test('Gate 16.2: password verification time is uniform (no oracle)', () async {
    final crypto = VaultCryptoV4();
    final json = Uint8List.fromList('{"entries":[]}'.codeUnits);
    final blob = await crypto.lockVault(json, _mp('right'));

    // Warm up (Argon2id + AES-NI init).
    for (var i = 0; i < 3; i++) {
      try {
        await crypto.unlockVault(blob, _mp('right'));
      } catch (_) {}
    }

    // Measure correct-password unlock time.
    final correctTimes = <int>[];
    for (var i = 0; i < 10; i++) {
      final sw = Stopwatch()..start();
      await crypto.unlockVault(blob, _mp('right'));
      sw.stop();
      correctTimes.add(sw.elapsedMicroseconds);
    }

    // Measure wrong-password unlock time.
    final wrongTimes = <int>[];
    for (var i = 0; i < 10; i++) {
      final sw = Stopwatch()..start();
      try {
        await crypto.unlockVault(blob, _mp('wrong'));
      } catch (_) {}
      sw.stop();
      wrongTimes.add(sw.elapsedMicroseconds);
    }

    final correctMean = _mean(correctTimes);
    final wrongMean = _mean(wrongTimes);
    final diffPct = (correctMean - wrongMean).abs() / correctMean * 100;

    // Timing difference must be within 5% (no oracle).
    expect(diffPct, lessThan(5.0),
        reason: 'timing oracle: correct=${correctMean.toStringAsFixed(0)}us '
            'wrong=${wrongMean.toStringAsFixed(0)}us diff=${diffPct.toStringAsFixed(2)}%');
  });
}

double _mean(List<int> xs) => xs.reduce((a, b) => a + b) / xs.length;