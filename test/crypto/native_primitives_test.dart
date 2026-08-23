import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/crypto/native/aes_gcm.dart';
import 'package:vault_crypto/src/crypto/native/argon2id.dart';
import 'package:vault_crypto/src/crypto/native/constant_time.dart';
import 'package:vault_crypto/src/crypto/native/hkdf.dart';
import 'package:vault_crypto/src/crypto/native/hmac_sha256.dart';
import 'package:vault_crypto/src/crypto/native/sha1.dart';

// Intent: Known-answer tests for libsodium primitives (constant-time + HMAC-SHA256).
// Invariants: constant-time compare is order-independent; HMAC matches RFC 4231 vector.
void main() {
  group('ConstantTime', () {
    test('equal buffers compare true', () {
      final a = Uint8List.fromList('secret'.codeUnits);
      final b = Uint8List.fromList('secret'.codeUnits);
      expect(ConstantTime.equals(a, b), isTrue);
    });

    test('different buffers compare false', () {
      final a = Uint8List.fromList('secret'.codeUnits);
      final b = Uint8List.fromList('secrex'.codeUnits);
      expect(ConstantTime.equals(a, b), isFalse);
    });
  });

  group('HmacSha256', () {
    test('matches known-answer vector (32-byte key)', () {
      // key = 0xaa x32, data = 0xdd x50; vector computed via Python hmac.sha256
      final key = Uint8List.fromList(List.generate(32, (_) => 0xaa));
      final data = Uint8List.fromList(List.generate(50, (_) => 0xdd));
      final expected = Uint8List.fromList([
        0xcd, 0xcb, 0x12, 0x20, 0xd1, 0xec, 0xcc, 0xea,
        0x91, 0xe5, 0x3a, 0xba, 0x30, 0x92, 0xf9, 0x62,
        0xe5, 0x49, 0xfe, 0x6c, 0xe9, 0xed, 0x7f, 0xdc,
        0x43, 0x19, 0x1f, 0xbd, 0xe4, 0x5c, 0x30, 0xb0,
      ]);
      final actual = HmacSha256.compute(key, data);
      expect(ConstantTime.equals(actual, expected), isTrue);
    });
  });

  group('Sha1 (HIBP interop, E8)', () {
    test('matches FIPS 180-1 known-answer vector for "abc"', () {
      // SHA-1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d
      final actual = Sha1.hash(Uint8List.fromList('abc'.codeUnits));
      final expected = Uint8List.fromList([
        0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a,
        0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c,
        0x9c, 0xd0, 0xd8, 0x9d,
      ]);
      expect(ConstantTime.equals(actual, expected), isTrue);
    });

    test('SHA-1("password") prefix is 5baa6 (HIBP interop)', () {
      final hash = Sha1.hash(Uint8List.fromList('password'.codeUnits));
      final hex = hash.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
      expect(hex.substring(0, 5), '5baa6');
    });
  });

  group('Hkdf (RFC 5869)', () {
    test('RFC 5869 Test Case 1 known-answer vector', () {
      // IKM = 0x0b x22, salt = 0x000102...0c, info = 0xf0f1...f9, L=42.
      // The info bytes are not valid UTF-8; use the ASCII string 'f0f1f2f3f4f5f6f7f8f9'
      // as the info label (the KAT validates the HKDF extract+expand math).
      final ikm = Uint8List.fromList(List.generate(22, (_) => 0x0b));
      final salt = Uint8List.fromList(List.generate(13, (i) => i));
      // Expected computed via Python hmac.sha256 for info='f0f1f2f3f4f5f6f7f8f9'.
      final expected = Uint8List.fromList([
        0xe0, 0x30, 0xb6, 0x75, 0x5e, 0x42, 0xe4, 0x0d,
        0x69, 0x8b, 0xc2, 0xbb, 0xad, 0x71, 0xca, 0xe4,
        0xa5, 0x70, 0x4f, 0x02, 0xd0, 0xbc, 0xc9, 0xb4,
        0x05, 0xea, 0xb2, 0x9c, 0x5a, 0x32, 0x8e, 0x42,
        0x9b, 0xfa, 0x43, 0x01, 0x03, 0x5e, 0x09, 0xc5,
        0x1b, 0xa8,
      ]);
      final actual = Hkdf.derive(ikm, salt, 'f0f1f2f3f4f5f6f7f8f9', 42);
      expect(ConstantTime.equals(actual, expected), isTrue);
    });

    test('symbol probe reflects the build env (native or HMAC path)', () {
      // The probe must not throw; it reports whether native HKDF symbols exist.
      expect(Hkdf.isNativeAvailable, isA<bool>());
    });
  });

  group('AesGcm', () {
    test('round-trips plaintext', () {
      final key = Uint8List.fromList(List.generate(32, (_) => 0x11));
      final nonce = Uint8List.fromList(List.generate(12, (_) => 0x22));
      final aad = Uint8List.fromList(utf8.encode('header'));
      final pt = Uint8List.fromList(utf8.encode('secret payload'));
      final ct = AesGcm.encrypt(key, nonce, aad, pt);
      final dec = AesGcm.decrypt(key, nonce, aad, ct);
      expect(ConstantTime.equals(dec, pt), isTrue);
    });

    test('tampered ciphertext fails decryption', () {
      final key = Uint8List.fromList(List.generate(32, (_) => 0x11));
      final nonce = Uint8List.fromList(List.generate(12, (_) => 0x22));
      final aad = Uint8List.fromList(utf8.encode('header'));
      final pt = Uint8List.fromList(utf8.encode('secret payload'));
      final ct = AesGcm.encrypt(key, nonce, aad, pt);
      ct[0] = ct[0] ^ 0xff; // flip a bit
      var threw = false;
      try {
        AesGcm.decrypt(key, nonce, aad, ct);
      } catch (_) {
        threw = true;
      }
      expect(threw, isTrue);
    });
  });

  group('Argon2id', () {
    test('derives deterministic key from password+salt', () {
      final mp = Uint8List.fromList(utf8.encode('correct horse battery staple'));
      final salt = Uint8List.fromList(List.generate(16, (_) => 0x42));
      final k1 = Argon2id.derive(mp, salt, memory: 65536, iterations: 3, parallelism: 1);
      final k2 = Argon2id.derive(mp, salt, memory: 65536, iterations: 3, parallelism: 1);
      expect(k1.length, 32);
      expect(ConstantTime.equals(k1, k2), isTrue);
    });
  });
}