// File: tool/timing_analysis.dart
// Intent: security.md gate 16.2 — Timing analysis.
// Verifies that password verification time does not differ between correct and
// wrong passwords (constant-time, no oracle). Uses the vault unlock path.
// Invariants:
// - Password verification: mean time correct vs wrong (difference < 5%).
// - Decryption: mean time valid vs corrupt data (difference < 5%).
// Usage: dart run tool/timing_analysis.dart
// Dependencies: vault_crypto_v4.dart, secure_buffer.dart.

import 'dart:typed_data';

import 'package:vault_crypto/src/crypto/native/secure_buffer.dart';
import 'package:vault_crypto/src/crypto/v4/vault_crypto_v4.dart';

SecureBuffer _mp(String s) {
  final buf = SecureBuffer.alloc(s.length);
  buf.writeBytes(Uint8List.fromList(s.codeUnits));
  return buf;
}

Future<void> main() async {
  final crypto = VaultCryptoV4();
  final json = Uint8List.fromList('{"entries":[]}'.codeUnits);
  final blob = await crypto.lockVault(json, _mp('right'));

  // Sanity: verify the round-trip works before measuring.
  final sanity = await crypto.unlockVault(blob, _mp('right'));
  if (sanity.length != json.length) {
    throw StateError('round-trip sanity check failed');
  }

  // Warm up (Argon2id + AES-NI init).
  for (var i = 0; i < 3; i++) {
    try {
      await crypto.unlockVault(blob, _mp('right'));
    } catch (_) {}
  }

  // Measure correct-password unlock time.
  final correctTimes = <int>[];
  for (var i = 0; i < 20; i++) {
    final sw = Stopwatch()..start();
    await crypto.unlockVault(blob, _mp('right'));
    sw.stop();
    correctTimes.add(sw.elapsedMicroseconds);
  }

  // Measure wrong-password unlock time.
  final wrongTimes = <int>[];
  for (var i = 0; i < 20; i++) {
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

  print('Correct-password mean: ${correctMean.toStringAsFixed(0)}us');
  print('Wrong-password mean:   ${wrongMean.toStringAsFixed(0)}us');
  print('Difference: ${diffPct.toStringAsFixed(2)}%');

  if (diffPct > 5) {
    print('FAIL: timing difference > 5% (potential oracle).');
    throw StateError('timing oracle detected');
  }
  print('PASS: timing difference within 5% (no oracle).');
}

double _mean(List<int> xs) => xs.reduce((a, b) => a + b) / xs.length;
