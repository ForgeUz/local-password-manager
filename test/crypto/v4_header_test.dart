import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/crypto/errors.dart';
import 'package:vault_crypto/src/crypto/v4/constants.dart';
import 'package:vault_crypto/src/crypto/v4/header.dart';

// Intent: Verify the v4 header format (GEN4, vault_count=2, per-entry DEK
// table, search_tag, header MAC) serializes and parses round-trip.
// Invariants: magic is GEN4; vault_count always 2; entry records round-trip.
void main() {
  group('V4Header', () {
    test('fixed header has GEN4 magic and vault_count=2', () {
      final h = V4Header.generate(
        kdfMemory: 65536,
        kdfIterations: 3,
        kdfParallelism: 1,
        salt: Uint8List(16),
        nonce: Uint8List(12),
      );
      expect(h.magic, V4Constants.magic);
      expect(h.formatVersion, 4);
      expect(h.vaultCount, 2);
    });

    test('entry record round-trips', () {
      final entry = V4EntryRecord(
        id: Uint8List.fromList(List.generate(16, (i) => i)),
        tier: 2,
        wrappedDek: Uint8List.fromList(List.generate(40, (i) => 0x10 + i)),
        searchTags: [Uint8List(32), Uint8List(32)],
        vectorClock: Uint8List.fromList([0, 0, 0, 1]),
        ciphertext: Uint8List.fromList(List.generate(100, (i) => i)),
      );
      final bytes = entry.toBytes();
      final parsed = V4EntryRecord.parse(bytes);
      expect(parsed.id, equals(entry.id));
      expect(parsed.tier, 2);
      expect(parsed.wrappedDek, equals(entry.wrappedDek));
      expect(parsed.searchTags.length, 2);
      expect(parsed.vectorClock, equals(entry.vectorClock));
      expect(parsed.ciphertext, equals(entry.ciphertext));
    });
  });

  group('v5 non-GEN4 rejection (E22)', () {
    test('non-GEN4 magic is rejected with UnsupportedFormatError', () {
      // A v3-style 'VULT' header must be rejected — no compat branch.
      final bytes = Uint8List(64);
      final bd = bytes.buffer.asByteData();
      bd.setInt32(0, 0x56554c54, Endian.big); // 'VULT'
      bytes[4] = 1; // v3 format version
      expect(() => V4Header.parse(bytes), throwsA(isA<UnsupportedFormatError>()));
    });
  });
}