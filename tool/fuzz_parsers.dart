// File: tool/fuzz_parsers.dart
// Intent: Fuzz parsers to ensure NO unhandled exceptions (DoS protection).
// Invariants: Parsers MUST throw typed errors (CorruptBlobError, TotpImportError),
// NEVER unhandled exceptions (RangeError, TypeError, FormatException).
// Usage: dart run tool/fuzz_parsers.dart

import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:vault_crypto/src/crypto/v4/header.dart';
import 'package:vault_crypto/src/crypto/errors.dart';
import 'package:vault_crypto/src/totp/totp_import.dart';

void main() {
  final random = Random.secure();
  const iterations = 100000;
  var crashes = 0;

  print('Fuzzing V4Header.parse ($iterations iterations)...');
  for (var i = 0; i < iterations; i++) {
    final len = random.nextInt(512);
    final bytes = Uint8List(len);
    for (var j = 0; j < len; j++) {
      bytes[j] = random.nextInt(256);
    }
    try {
      V4Header.parse(bytes);
    } on VaultCryptoError {
      // Expected typed error
    } catch (e) {
      print('CRASH in V4Header.parse: $e');
      crashes++;
      if (crashes > 10) break;
    }
  }

  print('Fuzzing TotpUriParser.parse ($iterations iterations)...');
  for (var i = 0; i < iterations; i++) {
    final len = random.nextInt(256);
    final chars = List.generate(len, (_) => random.nextInt(128))
        .map((c) => String.fromCharCode(c))
        .join();
    try {
      TotpUriParser.parse(chars);
    } catch (e) {
      print('CRASH in TotpUriParser.parse: $e');
      crashes++;
      if (crashes > 10) break;
    }
  }

  print('Fuzzing GoogleAuthExportParser.parse ($iterations iterations)...');
  for (var i = 0; i < iterations; i++) {
    final len = random.nextInt(256);
    final chars = List.generate(len, (_) => random.nextInt(128))
        .map((c) => String.fromCharCode(c))
        .join();
    try {
      GoogleAuthExportParser.parse(chars);
    } catch (e) {
      print('CRASH in GoogleAuthExportParser.parse: $e');
      crashes++;
      if (crashes > 10) break;
    }
  }

  if (crashes > 0) {
    print('FAILED: $crashes unhandled exceptions found.');
    exit(1);
  } else {
    print('PASSED: 0 unhandled exceptions.');
    exit(0);
  }
}
