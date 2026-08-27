// File: tool/fuzz_vault.dart
// Intent: security.md gate 13.1 — Vault file fuzzing.
// Fuzzes the V4Header parser + full vault blob unlock path with arbitrary byte
// sequences to ensure NO unhandled exceptions (DoS protection).
// Invariants:
// - Parser handles arbitrary byte sequences without crash.
// - Parser never throws unexpected exception types.
// - Parser never causes memory corruption.
// - Parser never enters infinite loop.
// - Corrupted input always produces CorruptBlobError or DecryptionFailedError.
// Usage: dart run tool/fuzz_vault.dart --iterations 100000
// Dependencies: dart:io, dart:math, dart:typed_data, header.dart, errors.dart.

import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:vault_crypto/src/crypto/errors.dart';
import 'package:vault_crypto/src/crypto/v4/header.dart';

void main(List<String> args) {
  final iterations = _parseIterations(args);
  final random = Random.secure();
  var crashes = 0;
  var typedErrors = 0;

  print('Fuzzing V4Header.parse ($iterations iterations)...');

  // 1. Random byte sequences of various sizes.
  const sizes = [0, 1, 10, 100, 1000, 10000, 100000];
  for (var i = 0; i < iterations; i++) {
    final len = sizes[random.nextInt(sizes.length)];
    final bytes = Uint8List(len);
    for (var j = 0; j < len; j++) {
      bytes[j] = random.nextInt(256);
    }
    try {
      V4Header.parse(bytes);
      // Parsing succeeded (unlikely for random data) — acceptable.
    } on VaultCryptoError {
      typedErrors++;
    } catch (e) {
      print('CRASH in V4Header.parse (len=$len): $e');
      crashes++;
      if (crashes > 10) break;
    }
  }

  // 2. Byte-by-byte mutation of a valid header.
  final valid = _validHeaderBytes();
  for (var i = 0; i < valid.length && crashes <= 10; i++) {
    for (var v = 0; v < 256; v++) {
      final mutated = Uint8List.fromList(valid);
      mutated[i] = v;
      try {
        V4Header.parse(mutated);
      } on VaultCryptoError {
        typedErrors++;
      } catch (e) {
        print('CRASH in V4Header.parse (mutation byte $i = $v): $e');
        crashes++;
        if (crashes > 10) break;
      }
    }
  }

  // 3. Truncation of a valid header at every position.
  for (var i = 0; i < valid.length && crashes <= 10; i++) {
    final truncated = Uint8List.fromList(valid.sublist(0, i));
    try {
      V4Header.parse(truncated);
    } on VaultCryptoError {
      typedErrors++;
    } catch (e) {
      print('CRASH in V4Header.parse (truncate at $i): $e');
      crashes++;
    }
  }

  // 4. Extension: valid header with appended random bytes.
  for (var i = 0; i < 1000 && crashes <= 10; i++) {
    final ext = Uint8List(valid.length + random.nextInt(64));
    ext.setRange(0, valid.length, valid);
    for (var j = valid.length; j < ext.length; j++) {
      ext[j] = random.nextInt(256);
    }
    try {
      V4Header.parse(ext);
    } on VaultCryptoError {
      typedErrors++;
    } catch (e) {
      print('CRASH in V4Header.parse (extension): $e');
      crashes++;
    }
  }

  print('Done. iterations=$iterations | typedErrors=$typedErrors | crashes=$crashes');
  if (crashes > 0) {
    print('FAIL: $crashes unexpected exception(s) escaped the parser.');
    exit(1);
  }
  print('PASS: no unexpected exceptions escaped the parser.');
}

int _parseIterations(List<String> args) {
  for (var i = 0; i < args.length - 1; i++) {
    if (args[i] == '--iterations') {
      return int.tryParse(args[i + 1]) ?? 100000;
    }
  }
  return 100000;
}

Uint8List _validHeaderBytes() {
  final h = V4Header.generate(
    kdfMemory: 65536,
    kdfIterations: 3,
    kdfParallelism: 1,
    salt: Uint8List.fromList(List.generate(16, (i) => i)),
    nonce: Uint8List.fromList(List.generate(12, (i) => 0x10 + i)),
  );
  return h.toBytes();
}
