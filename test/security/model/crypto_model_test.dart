// File: test/security/model/test_crypto_model.dart
// Intent: security2.md gate 22.1 — Cryptographic model conformance.
// Differential testing: libsodium FFI output == pure-Dart reference output.
// This catches FFI parameter-marshalling bugs (wrong order, endianness, sizes).
//
// Invariants:
// - libsodium HKDF output == reference HKDF output (100 vectors).
// - libsodium HMAC-SHA256 output == reference HMAC output (100 vectors).
// - Empty input handling matches.
// - Maximum length input handling matches.
// - Edge case parameters match.
// Dependencies: hkdf.dart, hmac_sha256.dart, reference_crypto.dart.

import 'dart:math';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/crypto/native/hkdf.dart';
import 'package:vault_crypto/src/crypto/native/hmac_sha256.dart';
import 'reference_crypto.dart';

Uint8List _bytes(int len, int seed) =>
    Uint8List.fromList(List.generate(len, (i) => (seed + i) & 0xFF));

void main() {
  group('Gate 22.1 Crypto Model Conformance', () {
    test('HKDF: libsodium == reference (100 random vectors)', () {
      final rng = Random(7);
      for (var i = 0; i < 100; i++) {
        final ikm = _bytes(16 + rng.nextInt(48), i);
        // Salt must be <= 32 bytes (HMAC-SHA256 key constraint).
        final salt = _bytes(1 + rng.nextInt(32), i + 1);
        final info = _bytes(1 + rng.nextInt(32), i + 2);
        final outLen = 16 + rng.nextInt(48);
        final libsodium =
            Hkdf.derive(ikm, salt, String.fromCharCodes(info), outLen);
        final reference = ReferenceHkdf.derive(ikm, salt, info, outLen);
        expect(libsodium, equals(reference),
            reason: 'HKDF mismatch at vector $i');
      }
    });

    test('HMAC-SHA256: libsodium == reference (100 random vectors)', () {
      final rng = Random(11);
      for (var i = 0; i < 100; i++) {
        // HmacSha256 requires a 32-byte key (HMAC-SHA256 standard).
        final key = _bytes(32, i);
        final data = _bytes(1 + rng.nextInt(64), i + 1);
        final libsodium = HmacSha256.compute(key, data);
        final reference = ReferenceHmacSha256.compute(key, data);
        expect(libsodium, equals(reference),
            reason: 'HMAC mismatch at vector $i');
      }
    });

    test('HKDF: empty input handling matches', () {
      // Empty info string.
      final ikm = _bytes(32, 1);
      final salt = _bytes(32, 2);
      final libsodium = Hkdf.derive(ikm, salt, '', 32);
      final reference = ReferenceHkdf.derive(ikm, salt, Uint8List(0), 32);
      expect(libsodium, equals(reference));
    });

    test('HKDF: maximum length input handling matches', () {
      // Large IKM and large output; salt capped at 32 bytes (HMAC key).
      final ikm = _bytes(1024, 1);
      final salt = _bytes(32, 2);
      final info = _bytes(128, 3);
      final libsodium = Hkdf.derive(ikm, salt, String.fromCharCodes(info), 128);
      final reference = ReferenceHkdf.derive(ikm, salt, info, 128);
      expect(libsodium, equals(reference));
    });

    test('HKDF: edge case parameters match (outLen = 1, 32, 33)', () {
      final ikm = _bytes(32, 1);
      final salt = _bytes(32, 2);
      final info = _bytes(8, 3);
      for (final outLen in [1, 32, 33, 64]) {
        final libsodium =
            Hkdf.derive(ikm, salt, String.fromCharCodes(info), outLen);
        final reference = ReferenceHkdf.derive(ikm, salt, info, outLen);
        expect(libsodium, equals(reference), reason: 'outLen=$outLen mismatch');
      }
    });

    test('HKDF: RFC 5869 test vector matches reference', () {
      // RFC 5869 Test Case 1.
      final ikm = Uint8List.fromList(List.generate(22, (_) => 0x0b));
      final salt = Uint8List.fromList(List.generate(13, (i) => i));
      final info = Uint8List.fromList(List.generate(10, (i) => 0xf0 + i));
      final reference = ReferenceHkdf.derive(ikm, salt, info, 42);
      // Expected first bytes: 3c b2 5f 25 fa ac d5 7a...
      expect(reference[0], 0x3c);
      expect(reference[1], 0xb2);
      expect(reference[2], 0x5f);
      expect(reference[3], 0x25);
    });
  });
}
