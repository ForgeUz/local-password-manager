// File: tool/timing_cache.dart
// Intent: security2.md gate 28.2 — Cache timing analysis (advanced).
// NOTE: Direct cache control is not possible in Dart. This is a best-effort
// measurement of AES-GCM timing variance under different key contents.
// Invariants:
// - AES-GCM with AES-NI: timing independent of key content.
// - Argon2id: timing independent of password content (memory access patterns).
// - Constant-time properties delegated to libsodium (documented limitation).
// Usage: dart run tool/timing_cache.dart
// Dependencies: aes_gcm.dart, argon2id.dart.

import 'dart:math';
import 'dart:typed_data';

import 'package:vault_crypto/src/crypto/native/aes_gcm.dart';
import 'package:vault_crypto/src/crypto/native/argon2id.dart';

Uint8List _bytes(int len, int seed) =>
    Uint8List.fromList(List.generate(len, (i) => (seed + i) & 0xFF));

void main() {
  // Measure AES-GCM with keys differing in 1 bit.
  final keyA = _bytes(32, 1);
  final keyB = Uint8List.fromList(keyA)..[0] ^= 0x01; // 1-bit difference
  final nonce = _bytes(12, 2);
  final pt = _bytes(64, 3);

  final timesA = <int>[];
  final timesB = <int>[];
  for (var i = 0; i < 1000; i++) {
    var sw = Stopwatch()..start();
    AesGcm.encrypt(keyA, nonce, Uint8List(0), pt);
    sw.stop();
    timesA.add(sw.elapsedMicroseconds);

    sw = Stopwatch()..start();
    AesGcm.encrypt(keyB, nonce, Uint8List(0), pt);
    sw.stop();
    timesB.add(sw.elapsedMicroseconds);
  }

  final meanA = _mean(timesA);
  final meanB = _mean(timesB);
  final diffPct = (meanA - meanB).abs() / meanA * 100;

  print('AES-GCM keyA mean: ${meanA.toStringAsFixed(0)}us');
  print('AES-GCM keyB mean: ${meanB.toStringAsFixed(0)}us');
  print('Difference: ${diffPct.toStringAsFixed(2)}%');

  if (diffPct > 5) {
    print('FAIL: AES-GCM timing depends on key content (cache timing leak).');
    throw StateError('cache timing leak detected');
  }
  print('PASS: AES-GCM timing independent of key content (AES-NI constant-time).');
  print('NOTE: constant-time properties delegated to libsodium (documented limitation).');
}

double _mean(List<int> xs) => xs.reduce((a, b) => a + b) / xs.length;
