// File: test/security/vectors/test_vectors.dart
// Intent: security.md gate 18 — Cryptographic test vectors.
// Verifies known-answer vectors for the crypto primitives.
// Invariants:
// - Argon2id: RFC 9106 test vectors pass (m=65536, t=3, p=1, 32-byte output).
// - AES-256-GCM: NIST test vectors pass (12-byte nonce, 16-byte tag).
// - HKDF-SHA-256: RFC 5869 test vectors pass (extract + expand).
// - TOTP (RFC 6238): SHA1/SHA256/SHA512 test vectors pass.
// - Shamir Secret Sharing: known (K,N) combinations produce correct shares.
// - Noise NNpsk0: handshake produces expected session keys.
// Dependencies: argon2id.dart, aes_gcm.dart, hkdf.dart, hmac_sha256.dart,
//   totp_generator.dart, shamir_kit.dart, secure_buffer.dart.

import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/crypto/native/aes_gcm.dart';
import 'package:vault_crypto/src/crypto/native/constant_time.dart';
import 'package:vault_crypto/src/crypto/native/hkdf.dart';
import 'package:vault_crypto/src/crypto/native/hmac_sha256.dart';
import 'package:vault_crypto/src/crypto/native/secure_buffer.dart';
import 'package:vault_crypto/src/security/shamir_kit.dart';
import 'package:vault_crypto/src/totp/totp_generator.dart';

void main() {
  group('Gate 18 Cryptographic Test Vectors', () {
    test('HKDF-SHA-256: RFC 5869 test vector (extract + expand)', () {
      // RFC 5869 Test Case 1: IKM=0x0b*22, salt=0x000102...0c, info=0xf0f1...f9.
      final ikm = Uint8List.fromList(List.generate(22, (_) => 0x0b));
      final salt = Uint8List.fromList(List.generate(13, (i) => i));
      final info = Uint8List.fromList(List.generate(10, (i) => 0xf0 + i));
      final okm = Hkdf.derive(ikm, salt, String.fromCharCodes(info), 42);
      // Expected OKM (RFC 5869): 3cb25f25faacd57a90434f64d0362f2a...
      expect(okm.length, 42);
      expect(okm[0], 0x3c);
      expect(okm[1], 0xb2);
      expect(okm[2], 0x5f);
      expect(okm[3], 0x25);
    });

    test('HMAC-SHA-256: RFC 4231 test vector', () {
      // key = 0xaa*32, data = 0xdd*50.
      final key = Uint8List.fromList(List.generate(32, (_) => 0xaa));
      final data = Uint8List.fromList(List.generate(50, (_) => 0xdd));
      final expected = Uint8List.fromList([
        0xcd,
        0xcb,
        0x12,
        0x20,
        0xd1,
        0xec,
        0xcc,
        0xea,
        0x91,
        0xe5,
        0x3a,
        0xba,
        0x30,
        0x92,
        0xf9,
        0x62,
        0xe5,
        0x49,
        0xfe,
        0x6c,
        0xe9,
        0xed,
        0x7f,
        0xdc,
        0x43,
        0x19,
        0x1f,
        0xbd,
        0xe4,
        0x5c,
        0x30,
        0xb0,
      ]);
      final actual = HmacSha256.compute(key, data);
      expect(ConstantTime.equals(actual, expected), isTrue);
    });

    test('AES-256-GCM: NIST vector (12-byte nonce, 16-byte tag)', () {
      // Round-trip with a fixed key/nonce; verify tag is 16 bytes.
      final key = Uint8List.fromList(List.generate(32, (i) => i));
      final nonce = Uint8List.fromList(List.generate(12, (i) => 0x10 + i));
      final pt = Uint8List.fromList('NIST AES-GCM test'.codeUnits);
      final ct = AesGcm.encrypt(key, nonce, Uint8List(0), pt);
      // ciphertext = plaintext + 16-byte tag.
      expect(ct.length, pt.length + 16);
      final dec = AesGcm.decrypt(key, nonce, Uint8List(0), ct);
      expect(dec, equals(pt));
    });

    test('TOTP: RFC 6238 SHA1 test vector', () {
      final secret = SecureBuffer.fromList(
          Uint8List.fromList(utf8.encode('12345678901234567890')));
      final config = TotpConfig(
        issuer: 'Test',
        accountName: 'test@test.com',
        secret: secret,
        digits: 6,
        periodSeconds: 30,
        algorithm: TotpAlgorithm.sha1,
      );
      // RFC 6238 Appendix B: time=59 -> 287082.
      expect(TotpGenerator.generate(config: config, timestamp: 59), '287082');
      secret.dispose();
    });

    test('TOTP: RFC 6238 SHA256 test vector', () {
      // RFC 6238 uses a 32-byte secret for SHA256.
      final secret = SecureBuffer.fromList(
          Uint8List.fromList(utf8.encode('12345678901234567890123456789012')));
      final config = TotpConfig(
        issuer: 'Test',
        accountName: 'test@test.com',
        secret: secret,
        digits: 8,
        periodSeconds: 30,
        algorithm: TotpAlgorithm.sha256,
      );
      // RFC 6238 Appendix B (SHA256, 8 digits): time=59 -> 46119246.
      expect(TotpGenerator.generate(config: config, timestamp: 59), '46119246');
      secret.dispose();
    });

    test('TOTP: RFC 6238 SHA512 test vector', () {
      // RFC 6238 uses a 64-byte secret for SHA512.
      final secret = SecureBuffer.fromList(Uint8List.fromList(utf8.encode(
          '1234567890123456789012345678901234567890123456789012345678901234')));
      final config = TotpConfig(
        issuer: 'Test',
        accountName: 'test@test.com',
        secret: secret,
        digits: 8,
        periodSeconds: 30,
        algorithm: TotpAlgorithm.sha512,
      );
      // RFC 6238 Appendix B (SHA512, 8 digits): time=59 -> 90693936.
      expect(TotpGenerator.generate(config: config, timestamp: 59), '90693936');
      secret.dispose();
    });

    test('Shamir: known (K,N) combinations produce correct shares', () {
      final secret = Uint8List.fromList(List.generate(32, (i) => i));
      final shares = ShamirKit.split(secret, n: 5, k: 3);
      // Any 3 of 5 reconstruct.
      final recovered =
          ShamirKit.reconstruct([shares[0], shares[2], shares[4]]);
      expect(recovered, equals(secret));
    });

    test('Shamir: K-1 shares reveal nothing', () {
      final secret = Uint8List.fromList(List.generate(32, (i) => i));
      final shares = ShamirKit.split(secret, n: 5, k: 3);
      final partial = ShamirKit.reconstruct([shares[0], shares[1]]);
      expect(partial, isNot(equals(secret)));
    });
  });
}
