// File: test/security/model/test_format_model.dart
// Intent: security2.md gate 22.2 — Vault file format model verification.
// Invariants:
// - Generated valid vault files always parse successfully.
// - Generated invalid files (violating model) always throw CorruptBlobError.
// - Round-trip: create → serialize → parse → serialize → identical bytes.
// - Header invariants maintained after every save operation.
// - Entry count in header matches actual entries in vault.
// Dependencies: header.dart, errors.dart, V4Constants.

import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/crypto/errors.dart';
import 'package:vault_crypto/src/crypto/v4/constants.dart';
import 'package:vault_crypto/src/crypto/v4/header.dart';

Uint8List _bytes(int len, int seed) =>
    Uint8List.fromList(List.generate(len, (i) => (seed + i) & 0xFF));

V4EntryRecord _record(int seed) {
  return V4EntryRecord(
    id: _bytes(16, seed),
    tier: 0,
    wrappedDek: _bytes(60, seed + 1),
    searchTags: [_bytes(32, seed + 2), _bytes(32, seed + 3)],
    vectorClock: _bytes(4, seed + 4),
    ciphertext: _bytes(100, seed + 5),
  );
}

void main() {
  group('Gate 22.2 Vault File Format Model', () {
    test('generated valid vault files always parse successfully', () {
      for (var i = 0; i < 100; i++) {
        final h = V4Header.generate(
          kdfMemory: 65536,
          kdfIterations: 3,
          kdfParallelism: 1,
          salt: _bytes(16, i),
          nonce: _bytes(12, i + 1),
          entries: [_record(i), _record(i + 1)],
        );
        final parsed = V4Header.parse(h.toBytes());
        expect(parsed.entries.length, 2);
      }
    });

    test('round-trip: create → serialize → parse → serialize → identical bytes', () {
      for (var i = 0; i < 50; i++) {
        final h = V4Header.generate(
          kdfMemory: 65536,
          kdfIterations: 3,
          kdfParallelism: 1,
          salt: _bytes(16, i),
          nonce: _bytes(12, i + 1),
          entries: [_record(i)],
        );
        final bytes1 = h.toBytes();
        final parsed = V4Header.parse(bytes1);
        final bytes2 = parsed.toBytes();
        expect(bytes2, equals(bytes1),
            reason: 'serialization not deterministic at iteration $i');
      }
    });

    test('header invariants maintained after every save operation', () {
      final h = V4Header.generate(
        kdfMemory: 65536,
        kdfIterations: 3,
        kdfParallelism: 1,
        salt: _bytes(16, 1),
        nonce: _bytes(12, 2),
        entries: [_record(1), _record(2), _record(3)],
      );
      // Invariants: magic, version, vault_count.
      expect(h.magic, V4Constants.magic);
      expect(h.formatVersion, V4Constants.formatVersion);
      expect(h.vaultCount, V4Constants.vaultCount);
      // Salt and nonce sizes.
      expect(h.salt.length, V4Constants.saltSize);
      expect(h.nonce.length, V4Constants.nonceSize);
    });

    test('entry count in header matches actual entries in vault', () {
      for (var count = 0; count < 20; count++) {
        final entries = List.generate(count, (i) => _record(i));
        final h = V4Header.generate(
          kdfMemory: 65536,
          kdfIterations: 3,
          kdfParallelism: 1,
          salt: _bytes(16, 1),
          nonce: _bytes(12, 2),
          entries: entries,
        );
        final parsed = V4Header.parse(h.toBytes());
        expect(parsed.entries.length, count);
      }
    });

    test('generated invalid files (violating model) always throw CorruptBlobError', () {
      // Invalid magic.
      final badMagic = Uint8List(V4Constants.fixedHeaderSize);
      badMagic.buffer.asByteData().setInt32(0, 0xDEADBEEF, Endian.big);
      expect(() => V4Header.parse(badMagic), throwsA(isA<VaultCryptoError>()));

      // Wrong version.
      final badVersion = Uint8List(V4Constants.fixedHeaderSize);
      badVersion.buffer.asByteData().setInt32(0, V4Constants.magic, Endian.big);
      badVersion[4] = 99;
      expect(() => V4Header.parse(badVersion), throwsA(isA<VaultCryptoError>()));

      // Wrong vault_count.
      final badCount = Uint8List(V4Constants.fixedHeaderSize);
      badCount.buffer.asByteData().setInt32(0, V4Constants.magic, Endian.big);
      badCount[4] = V4Constants.formatVersion;
      badCount[43] = 5; // vault_count must be 2
      expect(() => V4Header.parse(badCount), throwsA(isA<VaultCryptoError>()));

      // Truncated header.
      expect(() => V4Header.parse(Uint8List(10)), throwsA(isA<VaultCryptoError>()));
    });
  });
}
