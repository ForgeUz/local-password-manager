// File: test/security/format/decoy_test.dart
// Intent: security.md gate 2.2 — Decoy vault verification.
// Invariants:
// - Decoy vault uses completely different key derivation path.
// - Decoy vault password produces different VRK than primary.
// - Primary password cannot open decoy vault.
// - Decoy password cannot open primary vault.
// - Decoy vault has identical file structure to primary (indistinguishable).
// - Accessing decoy vault does not modify primary vault.
// - Decoy vault is stored in same file, not separate file.
// - Error messages for wrong password are identical for both vaults.
// Dependencies: vault_crypto_v4.dart, decoy_vault.dart, errors.dart,
//   secure_buffer.dart.

import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/crypto/errors.dart';
import 'package:vault_crypto/src/crypto/native/secure_buffer.dart';
import 'package:vault_crypto/src/crypto/v4/vault_crypto_v4.dart';

SecureBuffer _mp(String s) {
  final buf = SecureBuffer.alloc(s.length);
  buf.writeBytes(Uint8List.fromList(s.codeUnits));
  return buf;
}

void main() {
  group('Gate 2.2 Decoy Vault', () {
    test('decoy vault uses different key derivation path (different VRK)',
        () async {
      final crypto = VaultCryptoV4();
      final primaryJson = Uint8List.fromList('{"entries":[]}'.codeUnits);
      final decoyJson = Uint8List.fromList(
        '{"entries":[{"id":"d1","title":"Old","username":"a","password":"x",'
                '"url":"old.com","domain":"old.com","tier":0}]}'
            .codeUnits,
      );
      final fixedSalt = Uint8List.fromList(List.generate(16, (i) => i));
      final decoy = await crypto.lockDecoy(decoyJson, _mp('duress'), fixedSalt);
      final blob = await crypto.lockVault(primaryJson, _mp('primary'),
          decoyBlob: decoy, fixedSalt: fixedSalt);

      // Primary MP -> primary vault.
      expect(
          await crypto.unlockVault(blob, _mp('primary')), equals(primaryJson));
      // Duress MP -> decoy vault (different key path).
      final session = await crypto.duressUnlockSession(blob, _mp('duress'));
      expect(session.entries.length, 1);
      expect(session.entries.first.id, 'd1');
      session.vrk.dispose();
    });

    test('primary password cannot open decoy vault', () async {
      final crypto = VaultCryptoV4();
      final decoyJson = Uint8List.fromList(
        '{"entries":[{"id":"d1","title":"Old","username":"a","password":"x",'
                '"url":"old.com","domain":"old.com","tier":0}]}'
            .codeUnits,
      );
      final fixedSalt = Uint8List.fromList(List.generate(16, (i) => i));
      final decoy = await crypto.lockDecoy(decoyJson, _mp('duress'), fixedSalt);

      // The decoy blob alone, opened with the primary MP, must fail.
      await expectLater(
        crypto.unlockVault(decoy, _mp('primary')),
        throwsA(isA<DecryptionFailedError>()),
      );
    });

    test('decoy password cannot open primary vault', () async {
      final crypto = VaultCryptoV4();
      final primaryJson = Uint8List.fromList('{"entries":[]}'.codeUnits);
      final decoyJson = Uint8List.fromList(
        '{"entries":[{"id":"d1","title":"Old","username":"a","password":"x",'
                '"url":"old.com","domain":"old.com","tier":0}]}'
            .codeUnits,
      );
      final fixedSalt = Uint8List.fromList(List.generate(16, (i) => i));
      final decoy = await crypto.lockDecoy(decoyJson, _mp('duress'), fixedSalt);
      final blob = await crypto.lockVault(primaryJson, _mp('primary'),
          decoyBlob: decoy, fixedSalt: fixedSalt);

      // Duress MP on the primary blob must NOT open the primary vault.
      await expectLater(
        crypto.unlockVault(blob, _mp('duress')),
        throwsA(isA<DecryptionFailedError>()),
      );
    });

    test('decoy vault is stored in same file, not separate file', () async {
      final crypto = VaultCryptoV4();
      final primaryJson = Uint8List.fromList('{"entries":[]}'.codeUnits);
      final decoyJson = Uint8List.fromList(
        '{"entries":[{"id":"d1","title":"Old","username":"a","password":"x",'
                '"url":"old.com","domain":"old.com","tier":0}]}'
            .codeUnits,
      );
      final fixedSalt = Uint8List.fromList(List.generate(16, (i) => i));
      final decoy = await crypto.lockDecoy(decoyJson, _mp('duress'), fixedSalt);
      final blob = await crypto.lockVault(primaryJson, _mp('primary'),
          decoyBlob: decoy, fixedSalt: fixedSalt);

      // The decoy is embedded in slot 2 of the single blob.
      final slot2 = VaultCryptoV4.slot2Of(blob);
      expect(slot2.length, greaterThan(0));
      // The decoy blob is recoverable from slot 2.
      expect(slot2, equals(decoy));
    });

    test('accessing decoy vault does not modify primary vault', () async {
      final crypto = VaultCryptoV4();
      final primaryJson = Uint8List.fromList('{"entries":[]}'.codeUnits);
      final decoyJson = Uint8List.fromList(
        '{"entries":[{"id":"d1","title":"Old","username":"a","password":"x",'
                '"url":"old.com","domain":"old.com","tier":0}]}'
            .codeUnits,
      );
      final fixedSalt = Uint8List.fromList(List.generate(16, (i) => i));
      final decoy = await crypto.lockDecoy(decoyJson, _mp('duress'), fixedSalt);
      final blob = await crypto.lockVault(primaryJson, _mp('primary'),
          decoyBlob: decoy, fixedSalt: fixedSalt);

      // Access the decoy vault.
      final session = await crypto.duressUnlockSession(blob, _mp('duress'));
      session.vrk.dispose();

      // Primary vault still opens with the primary MP, unchanged.
      expect(
          await crypto.unlockVault(blob, _mp('primary')), equals(primaryJson));
    });

    test('error messages for wrong password are identical for both vaults',
        () async {
      final crypto = VaultCryptoV4();
      final primaryJson = Uint8List.fromList('{"entries":[]}'.codeUnits);
      final decoyJson = Uint8List.fromList(
        '{"entries":[{"id":"d1","title":"Old","username":"a","password":"x",'
                '"url":"old.com","domain":"old.com","tier":0}]}'
            .codeUnits,
      );
      final fixedSalt = Uint8List.fromList(List.generate(16, (i) => i));
      final decoy = await crypto.lockDecoy(decoyJson, _mp('duress'), fixedSalt);
      final blob = await crypto.lockVault(primaryJson, _mp('primary'),
          decoyBlob: decoy, fixedSalt: fixedSalt);

      // Wrong password on primary blob.
      String primaryMsg = '';
      try {
        await crypto.unlockVault(blob, _mp('wrong'));
      } catch (e) {
        primaryMsg = e.toString();
      }
      // Wrong password on decoy blob.
      String decoyMsg = '';
      try {
        await crypto.unlockVault(decoy, _mp('wrong'));
      } catch (e) {
        decoyMsg = e.toString();
      }
      // Identical error messages (no oracle distinguishing vaults).
      expect(primaryMsg, isNotEmpty);
      expect(primaryMsg, equals(decoyMsg));
    });
  });
}
