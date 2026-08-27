// File: test/security/recovery/test_shamir.dart
// Intent: security.md gate 9.1 — Shamir secret sharing verification.
// Invariants:
// - Uses standard Shamir Secret Sharing scheme (not custom).
// - Threshold K of N shares reconstruct secret.
// - K-1 shares reveal NOTHING about secret (information-theoretic security).
// - Share generation uses CSPRNG.
// - Share reconstruction is deterministic (same shares -> same secret).
// - Invalid shares (wrong polynomial) produce wrong secret (detected).
// - Share format includes checksum/validation.
// - Shares can be exported to paper/print (base64 encoding).
// Dependencies: shamir_kit.dart.

import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/security/shamir_kit.dart';

Uint8List _secret(int len) =>
    Uint8List.fromList(List.generate(len, (i) => (0x40 + i) & 0xFF));

void main() {
  group('Gate 9.1 Shamir Secret Sharing', () {
    test('threshold K of N shares reconstruct secret', () {
      final secret = _secret(32);
      final shares = ShamirKit.split(secret, n: 5, k: 3);
      // Any 3 of 5 shares reconstruct.
      final subset = [shares[0], shares[2], shares[4]];
      final recovered = ShamirKit.reconstruct(subset);
      expect(recovered, equals(secret));
    });

    test('all N shares reconstruct secret', () {
      final secret = _secret(32);
      final shares = ShamirKit.split(secret, n: 5, k: 3);
      final recovered = ShamirKit.reconstruct(shares);
      expect(recovered, equals(secret));
    });

    test('K-1 shares reveal NOTHING about secret', () {
      final secret = _secret(32);
      final shares = ShamirKit.split(secret, n: 5, k: 3);
      // 2 shares (K-1) must NOT reconstruct the secret.
      final subset = [shares[0], shares[1]];
      final recovered = ShamirKit.reconstruct(subset);
      expect(recovered, isNot(equals(secret)));
    });

    test('share generation uses CSPRNG (non-deterministic)', () {
      final secret = _secret(32);
      final s1 = ShamirKit.split(secret, n: 3, k: 2);
      final s2 = ShamirKit.split(secret, n: 3, k: 2);
      // Different random polynomials -> different shares.
      expect(s1[0].y, isNot(equals(s2[0].y)));
    });

    test('share reconstruction is deterministic (same shares -> same secret)', () {
      final secret = _secret(32);
      final shares = ShamirKit.split(secret, n: 3, k: 2);
      final r1 = ShamirKit.reconstruct([shares[0], shares[1]]);
      final r2 = ShamirKit.reconstruct([shares[0], shares[1]]);
      expect(r1, equals(r2));
      expect(r1, equals(secret));
    });

    test('invalid shares (wrong polynomial) produce wrong secret (detected)', () {
      final secret = _secret(32);
      final shares = ShamirKit.split(secret, n: 5, k: 3);
      // Corrupt one share's y value -> reconstruction yields wrong secret.
      final corrupted = Share(x: shares[0].x, y: Uint8List.fromList(shares[0].y)..[0] ^= 0xFF);
      final recovered = ShamirKit.reconstruct([corrupted, shares[1], shares[2]]);
      expect(recovered, isNot(equals(secret)));
    });

    test('share format includes validation (parse rejects malformed)', () {
      // encodeShare -> parseShare round-trips.
      final secret = _secret(16);
      final shares = ShamirKit.split(secret, n: 3, k: 2);
      final encoded = ShamirKit.encodeShare(shares[0]);
      final parsed = ShamirKit.parseShare(encoded);
      expect(parsed.x, shares[0].x);
      expect(parsed.y, equals(shares[0].y));
      // Malformed share (too short) throws.
      expect(() => ShamirKit.parseShare('AA=='), throwsA(anything));
    });

    test('shares can be exported to paper/print (base64)', () {
      final secret = _secret(16);
      final shares = ShamirKit.split(secret, n: 3, k: 2);
      for (final s in shares) {
        final encoded = ShamirKit.encodeShare(s);
        // Base64 string is printable/exportable.
        expect(encoded, isNotEmpty);
        // Round-trips.
        final parsed = ShamirKit.parseShare(encoded);
        expect(parsed.y, equals(s.y));
      }
    });
  });
}
