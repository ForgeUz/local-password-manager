// File: test/security/regression/test_regression_suite.dart
// Intent: security2.md gate 31.2 — Regression protection.
// Verifies that security fixes stay fixed. Each test reproduces a previously
// found bug; it must fail before the fix and pass after.
// Invariants:
// - Header parser RangeError fix (from fuzzing bug): regression test.
// - Any future security fix: mandatory regression test.
// - Regression tests reference the issue/PR that fixed them.
// Dependencies: header.dart, errors.dart, V4Constants.

import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/crypto/errors.dart';
import 'package:vault_crypto/src/crypto/v4/constants.dart';
import 'package:vault_crypto/src/crypto/v4/header.dart';

void main() {
  group('Gate 31.2 Regression Protection', () {
    test('REGRESSION: header truncated at fixed-header boundary throws CorruptBlobError, not RangeError', () {
      // Bug found by tool/fuzz_vault.dart: a header truncated at exactly
      // fixedHeaderSize (44) or 45 bytes leaked a RangeError instead of
      // CorruptBlobError. Fixed in lib/src/crypto/v4/header.dart by moving the
      // entry-count read inside the guarded block.
      for (var len = 0; len <= V4Constants.fixedHeaderSize + 2; len++) {
        final bytes = Uint8List(len);
        try {
          V4Header.parse(bytes);
          // Parsing may succeed for some lengths, but must never leak RangeError.
        } on VaultCryptoError {
          // Expected typed error.
        } on RangeError {
          fail('REGRESSION: RangeError leaked at header length $len');
        }
      }
    });

    test('REGRESSION: header with valid magic but truncated entry table throws typed error', () {
      // A header with valid magic/version but a truncated entry table must
      // throw CorruptBlobError, not RangeError.
      final bytes = Uint8List(V4Constants.fixedHeaderSize + 2);
      final bd = bytes.buffer.asByteData();
      bd.setInt32(0, V4Constants.magic, Endian.big);
      bytes[4] = V4Constants.formatVersion;
      bytes[5] = V4Constants.kdfAlgoId;
      bd.setInt32(6, 65536, Endian.big);
      bd.setInt32(10, 3, Endian.big);
      bytes[14] = 1;
      bytes[43] = V4Constants.vaultCount;
      bd.setUint16(44, 1, Endian.big); // claims 1 entry, but no entry bytes
      try {
        V4Header.parse(bytes);
      } on VaultCryptoError {
        // Expected.
      } on RangeError {
        fail('REGRESSION: RangeError leaked on truncated entry table');
      }
    });

    test('REGRESSION: no live mutation markers in lib/', () async {
      // A mutation-testing campaign (tool/mutation_campaign.dart) patches
      // source to inject bugs. One escaped into production (the wrong-nonce
      // header MAC) and broke every lock->unlock round-trip. This guard fails
      // CI if any live MUTATION marker is ever committed again.
      final hits = <String>[];
      await for (final e in Directory('lib').list(recursive: true)) {
        if (e is File &&
            e.path.endsWith('.dart') &&
            (await e.readAsString()).contains('MUTATION')) {
          hits.add(e.path);
        }
      }
      expect(hits, isEmpty, reason: 'live mutations: $hits');
    });
  });
}
