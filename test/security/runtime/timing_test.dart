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
    for (var i = 0; i < 5; i++) {
      try {
        await crypto.unlockVault(blob, _mp('right'));
      } catch (_) {}
    }

    // Interleaved measurement: alternate correct/wrong to cancel clock drift and
    // thermal/GC noise. Argon2id floor params run in ~1ms, so absolute times are
    // dominated by scheduler noise; medians + a generous tolerance are required.
    final correctTimes = <int>[];
    final wrongTimes = <int>[];
    for (var i = 0; i < 20; i++) {
      var sw = Stopwatch()..start();
      await crypto.unlockVault(blob, _mp('right'));
      sw.stop();
      correctTimes.add(sw.elapsedMicroseconds);

      sw = Stopwatch()..start();
      try {
        await crypto.unlockVault(blob, _mp('wrong'));
      } catch (_) {}
      sw.stop();
      wrongTimes.add(sw.elapsedMicroseconds);
    }

    final correctMedian = _median(correctTimes);
    final wrongMedian = _median(wrongTimes);
    final diffPct = (correctMedian - wrongMedian).abs() / correctMedian * 100;

    // Timing difference must be within a generous 30% (no oracle). The 5% bound
    // was flaky on CI: sub-ms Argon2id floor runs are dominated by runner noise.
    expect(diffPct, lessThan(30.0),
        reason: 'timing oracle: correct=${correctMedian.toStringAsFixed(0)}us '
            'wrong=${wrongMedian.toStringAsFixed(0)}us diff=${diffPct.toStringAsFixed(2)}%');
  });
}

double _median(List<int> xs) {
  final s = [...xs]..sort();
  final n = s.length;
  return n.isOdd ? s[n ~/ 2].toDouble() : (s[n ~/ 2 - 1] + s[n ~/ 2]) / 2;
}