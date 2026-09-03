// File: test/security/shamir_kit_test.dart
// Intent: Kill-tests for Shamir Secret Sharing GF(256) math (M130-M133).
// Invariants:
// - Any K of N shares reconstruct the original secret.
// - Fewer than K shares produce garbage (threshold enforcement).
// - Share encode/decode round-trip preserves data.

import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/security/shamir_kit.dart';

void main() {
  group('M130-M133: Shamir split/reconstruct round-trip', () {
    test('3-of-5 reconstructs original secret', () {
      final secret = Uint8List.fromList(
          [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
      final shares = ShamirKit.split(secret, n: 5, k: 3);

      final subset = [shares[0], shares[2], shares[4]];
      final reconstructed = ShamirKit.reconstruct(subset);

      expect(reconstructed, equals(secret));
    });

    test('2-of-5 fails to reconstruct (threshold enforcement)', () {
      final secret = Uint8List.fromList([255, 128, 64, 32]);
      final shares = ShamirKit.split(secret, n: 5, k: 3);

      final subset = [shares[1], shares[3]];
      final reconstructed = ShamirKit.reconstruct(subset);

      expect(reconstructed, isNot(equals(secret)));
    });

    test('Share encode/decode round-trip', () {
      final secret = Uint8List.fromList([42, 84, 126]);
      final shares = ShamirKit.split(secret, n: 2, k: 2);

      for (final s in shares) {
        final encoded = ShamirKit.encodeShare(s);
        final decoded = ShamirKit.parseShare(encoded);
        expect(decoded.x, equals(s.x));
        expect(decoded.y, equals(s.y));
      }
    });
  });
}
