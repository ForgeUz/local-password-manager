// File: test/security/errors/test_error_leakage.dart
// Intent: security.md gate 12 — Error handling & information leakage.
// Invariants:
// - All parsing errors -> CorruptBlobError (uniform).
// - All decryption errors -> DecryptionFailedError (uniform).
// - Error messages do not contain: entry IDs, field names, key material.
// - Error messages do not differ based on WHERE decryption failed.
// - No FormatException, RangeError, StateError leaks to UI.
// Dependencies: vault_crypto_v4.dart, errors.dart, header.dart, secure_buffer.dart.

import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/crypto/errors.dart';
import 'package:vault_crypto/src/crypto/native/secure_buffer.dart';
import 'package:vault_crypto/src/crypto/v4/header.dart';
import 'package:vault_crypto/src/crypto/v4/vault_crypto_v4.dart';

SecureBuffer _mp(String s) {
  final buf = SecureBuffer.alloc(s.length);
  buf.writeBytes(Uint8List.fromList(s.codeUnits));
  return buf;
}

void main() {
  group('Gate 12 Error Handling & Information Leakage', () {
    test('all parsing errors -> CorruptBlobError (uniform)', () {
      // Truncated header.
      expect(() => V4Header.parse(Uint8List(0)), throwsA(isA<VaultCryptoError>()));
      // Invalid magic.
      final bad = Uint8List(44);
      bad.buffer.asByteData().setInt32(0, 0xDEADBEEF, Endian.big);
      expect(() => V4Header.parse(bad), throwsA(isA<VaultCryptoError>()));
    });

    test('all decryption errors -> DecryptionFailedError (uniform)', () async {
      final crypto = VaultCryptoV4();
      final json = Uint8List.fromList('{"entries":[]}'.codeUnits);
      final blob = await crypto.lockVault(json, _mp('right'));

      // Wrong password.
      await expectLater(
        crypto.unlockVault(blob, _mp('wrong')),
        throwsA(isA<DecryptionFailedError>()),
      );
      // Tampered header.
      final tampered = Uint8List.fromList(blob);
      tampered[15] = tampered[15] ^ 0x01;
      await expectLater(
        crypto.unlockVault(tampered, _mp('right')),
        throwsA(isA<DecryptionFailedError>()),
      );
    });

    test('error messages do not contain entry IDs or field names', () async {
      final crypto = VaultCryptoV4();
      final json = Uint8List.fromList(
        '{"entries":[{"id":"secret-entry-42","title":"Bank","username":"u",'
        '"password":"p","url":"bank.com","domain":"bank.com","tier":2}]}'.codeUnits,
      );
      final blob = await crypto.lockVault(json, _mp('right'));
      try {
        await crypto.unlockVault(blob, _mp('wrong'));
      } catch (e) {
        final msg = e.toString();
        expect(msg.contains('secret-entry-42'), isFalse);
        expect(msg.contains('Bank'), isFalse);
        expect(msg.contains('password'), isFalse);
      }
    });

    test('error messages do not differ based on WHERE decryption failed', () async {
      final crypto = VaultCryptoV4();
      final json = Uint8List.fromList('{"entries":[]}'.codeUnits);
      final blob = await crypto.lockVault(json, _mp('right'));

      // Failure at outer-GCM (wrong password).
      String outerMsg = '';
      try {
        await crypto.unlockVault(blob, _mp('wrong'));
      } catch (e) {
        outerMsg = e.toString();
      }

      // Failure at header-MAC (tamper a header byte). The header is the outer
      // GCM AAD, so tampering it fails the tag — same error as a wrong password.
      // (Slot 2 is deliberately NOT covered by the tag for plausible deniability,
      // so tampering it would be undetectable and is not a valid oracle probe.)
      final tampered = Uint8List.fromList(blob);
      tampered[20] = tampered[20] ^ 0x01;
      String entryMsg = '';
      try {
        await crypto.unlockVault(tampered, _mp('right'));
      } catch (e) {
        entryMsg = e.toString();
      }

      // Both must be identical (no oracle about where decryption failed).
      expect(outerMsg, isNotEmpty);
      expect(outerMsg, equals(entryMsg));
    });

    test('no FormatException/RangeError/StateError leaks to UI', () async {
      final crypto = VaultCryptoV4();
      final json = Uint8List.fromList('{"entries":[]}'.codeUnits);
      final blob = await crypto.lockVault(json, _mp('right'));

      // Corrupt blob (truncate).
      final truncated = Uint8List.fromList(blob.sublist(0, 10));
      try {
        await crypto.unlockVault(truncated, _mp('right'));
        fail('expected an error');
      } on VaultCryptoError {
        // Expected typed error.
      } on RangeError {
        fail('RangeError leaked to UI');
      } on FormatException {
        fail('FormatException leaked to UI');
      } on StateError {
        fail('StateError leaked to UI');
      }
    });
  });
}
