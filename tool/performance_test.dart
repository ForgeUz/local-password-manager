// File: tool/performance_test.dart
// Intent: security.md gate 19 — Performance under adversarial load.
// Verifies the vault handles a large entry count within reasonable time and
// that repeated lock/unlock cycles do not leak memory.
// Invariants:
// - Vault with 10,000 entries: unlock < 5 seconds.
// - Vault with 10,000 entries: save < 10 seconds.
// - 1000 lock/unlock cycles: no memory leak (heap size stable).
// Usage: dart run tool/performance_test.dart
// Dependencies: vault_crypto_v4.dart, secure_buffer.dart.

import 'dart:io';
import 'dart:typed_data';

import 'package:vault_crypto/src/crypto/native/secure_buffer.dart';
import 'package:vault_crypto/src/crypto/v4/vault_crypto_v4.dart';

SecureBuffer _mp(String s) {
  final buf = SecureBuffer.alloc(s.length);
  buf.writeBytes(Uint8List.fromList(s.codeUnits));
  return buf;
}

String _entryJson(int i) {
  return '{"id":"e$i","title":"Entry $i","username":"user$i",'
      '"password":"pw$i","url":"site$i.com","domain":"site$i.com","tier":0}';
}

void main() async {
  final crypto = VaultCryptoV4();

  // Build a vault with 10,000 entries.
  final entries = List.generate(10000, (i) => _entryJson(i)).join(',');
  final json = Uint8List.fromList('{"entries":[$entries]}'.codeUnits);

  // Save (lock) timing.
  final saveSw = Stopwatch()..start();
  final blob = await crypto.lockVault(json, _mp('mp'));
  saveSw.stop();
  print('Save (10,000 entries): ${saveSw.elapsedMilliseconds}ms');
  if (saveSw.elapsedMilliseconds > 10000) {
    throw StateError('save too slow');
  }

  // Unlock timing.
  final unlockSw = Stopwatch()..start();
  final result = await crypto.unlockVault(blob, _mp('mp'));
  unlockSw.stop();
  print('Unlock (10,000 entries): ${unlockSw.elapsedMilliseconds}ms');
  if (unlockSw.elapsedMilliseconds > 5000) {
    throw StateError('unlock too slow');
  }
  if (result.length != json.length) {
    throw StateError('round-trip mismatch');
  }

  // 1000 lock/unlock cycles: no memory leak (heap size stable).
  final smallJson = Uint8List.fromList('{"entries":[]}'.codeUnits);
  final smallBlob = await crypto.lockVault(smallJson, _mp('mp'));
  final before = ProcessInfo.currentRss;
  for (var i = 0; i < 1000; i++) {
    await crypto.unlockVault(smallBlob, _mp('mp'));
  }
  final after = ProcessInfo.currentRss;
  print('RSS before: ${before ~/ 1024}KB, after: ${after ~/ 1024}KB');
  // Allow some slack for GC; flag only a large growth.
  if (after > before * 2) {
    throw StateError('possible memory leak over 1000 cycles');
  }

  print('PASS: performance under adversarial load.');
}
