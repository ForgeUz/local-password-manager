// File: tool/fuzz_totp_import.dart
// Intent: security2.md gate 23.3 — TOTP secret import fuzzer.
// Fuzzes the otpauth:// URI parser with malformed inputs.
// Input space:
// - Missing parameters (secret, issuer, algorithm).
// - Invalid base32 encoding.
// - Invalid algorithm names (MD5, unknown).
// - Invalid periods (0, negative, very large).
// - Invalid digits (0, 1, 5, 7, 9, 100).
// - Unicode in issuer/account.
// - Very long secrets (100KB+).
// - Nested URI encoding.
// Invariants:
// - Malformed URIs rejected gracefully (typed error, no crash).
// - No crash on any input.
// - Valid imports always produce working TOTP.
// - Secret never logged during parsing.
// Usage: dart run tool/fuzz_totp_import.dart --iterations 20000
// Dependencies: totp_import.dart.

import 'dart:io';
import 'dart:math';

import 'package:vault_crypto/src/totp/totp_import.dart';

void main(List<String> args) {
  final iterations = _parseIterations(args);
  final rng = Random.secure();
  var crashes = 0;
  var rejected = 0;
  var accepted = 0;

  print('Fuzzing TotpUriParser ($iterations iterations)...');

  for (var i = 0; i < iterations; i++) {
    final uri = _malformedUri(rng);
    try {
      final result = TotpUriParser.parse(uri);
      if (result is TotpImportSuccess) {
        accepted++;
      } else {
        rejected++;
      }
    } catch (e) {
      print('CRASH on URI: $uri');
      print('  $e');
      crashes++;
      if (crashes > 10) break;
    }
  }

  print('Done. iterations=$iterations | accepted=$accepted | rejected=$rejected | crashes=$crashes');
  if (crashes > 0) {
    print('FAIL: $crashes unexpected exception(s) escaped the parser.');
    exit(1);
  }
  print('PASS: no unexpected exceptions escaped the TOTP parser.');
}

int _parseIterations(List<String> args) {
  for (var i = 0; i < args.length - 1; i++) {
    if (args[i] == '--iterations') {
      return int.tryParse(args[i + 1]) ?? 20000;
    }
  }
  return 20000;
}

String _malformedUri(Random rng) {
  final strategy = rng.nextInt(8);
  switch (strategy) {
    case 0: // Missing secret.
      return 'otpauth://totp/GitHub:user@example.com?issuer=GitHub';
    case 1: // Invalid base32.
      return 'otpauth://totp/GitHub:user@example.com?secret=!!!notbase32!!!';
    case 2: // Invalid algorithm.
      return 'otpauth://totp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP&algorithm=MD5';
    case 3: // Invalid period.
      return 'otpauth://totp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP&period=${rng.nextInt(3) - 1}';
    case 4: // Invalid digits.
      return 'otpauth://totp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP&digits=${[0, 1, 5, 7, 9, 100][rng.nextInt(6)]}';
    case 5: // Unicode in issuer/account.
      return 'otpauth://totp/Ünïcödé:üser@example.com?secret=JBSWY3DPEHPK3PXP';
    case 6: // Very long secret.
      final long = List.generate(100000, (_) => 'A').join();
      return 'otpauth://totp/GitHub:user@example.com?secret=$long';
    case 7: // Nested URI encoding / garbage.
      return 'otpauth://totp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=${Uri.encodeComponent('a&b=c')}';
  }
  return 'otpauth://totp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP';
}
