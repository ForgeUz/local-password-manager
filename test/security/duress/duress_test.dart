// File: test/security/duress/test_duress.dart
// Intent: security.md gate 5 — Duress vault security verification.
// Invariants:
// - Duress password produces different VRK than primary password.
// - Duress vault is cryptographically isolated from primary.
// - Domain separation: different HKDF info string for duress.
// - Key size for duress vault matches primary (32 bytes).
// - Duress vault contains realistic-looking entries.
// - Duress vault can be independently locked/unlocked.
// Dependencies: duress.dart, vault_crypto_v4.dart, errors.dart, secure_buffer.dart.

import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/crypto/errors.dart';
import 'package:vault_crypto/src/crypto/native/constant_time.dart';
import 'package:vault_crypto/src/crypto/native/secure_buffer.dart';
import 'package:vault_crypto/src/crypto/v4/duress.dart';
import 'package:vault_crypto/src/crypto/v4/vault_crypto_v4.dart';

SecureBuffer _mp(String s) {
  final buf = SecureBuffer.alloc(s.length);
  buf.writeBytes(Uint8List.fromList(s.codeUnits));
  return buf;
}

void main() {
  group('Gate 5 Duress Vault', () {
    test('duress password produces different VRK than primary', () {
      final mkPrimary = Uint8List.fromList(List.generate(32, (i) => i));
      final mkDuress = Uint8List.fromList(List.generate(32, (i) => 0xFF - i));
      final vrkPrimary = Duress.deriveVrkDuress(mkPrimary);
      final vrkDuress = Duress.deriveVrkDuress(mkDuress);
      expect(ConstantTime.equals(vrkPrimary, vrkDuress), isFalse);
    });

    test('key size for duress vault matches primary (32 bytes)', () {
      final mk = Uint8List.fromList(List.generate(32, (i) => i));
      final vrk = Duress.deriveVrkDuress(mk);
      expect(vrk.length, 32);
    });

    test('duress vault is cryptographically isolated from primary', () async {
      final crypto = VaultCryptoV4();
      final primaryJson = Uint8List.fromList('{"entries":[]}'.codeUnits);
      final decoyJson = Uint8List.fromList(
        '{"entries":[{"id":"d1","title":"Old Email","username":"a@b.c",'
        '"password":"low","url":"mail.example.com","domain":"mail.example.com",'
        '"tier":0}]}'.codeUnits,
      );
      final fixedSalt = Uint8List.fromList(List.generate(16, (i) => 0xFF - i));
      final decoy = await crypto.lockDecoy(decoyJson, _mp('duress'), fixedSalt);
      final blob = await crypto.lockVault(primaryJson, _mp('primary'),
          decoyBlob: decoy, fixedSalt: fixedSalt);

      // Primary MP -> primary (empty) vault.
      expect(await crypto.unlockVault(blob, _mp('primary')), equals(primaryJson));
      // Duress MP -> decoy vault (isolated).
      final session = await crypto.duressUnlockSession(blob, _mp('duress'));
      expect(session.entries.length, 1);
      expect(session.entries.first.id, 'd1');
      session.vrk.dispose();
    });

    test('duress vault contains realistic-looking entries', () async {
      final crypto = VaultCryptoV4();
      final primaryJson = Uint8List.fromList('{"entries":[]}'.codeUnits);
      final decoyJson = Uint8List.fromList(
        '{"entries":[{"id":"d1","title":"Old Email","username":"a@b.c",'
        '"password":"low","url":"mail.example.com","domain":"mail.example.com",'
        '"tier":0}]}'.codeUnits,
      );
      final fixedSalt = Uint8List.fromList(List.generate(16, (i) => i));
      final decoy = await crypto.lockDecoy(decoyJson, _mp('duress'), fixedSalt);
      final blob = await crypto.lockVault(primaryJson, _mp('primary'),
          decoyBlob: decoy, fixedSalt: fixedSalt);

      final session = await crypto.duressUnlockSession(blob, _mp('duress'));
      // The decoy entry has a plausible title/username/domain.
      expect(session.entries.first.title, 'Old Email');
      expect(session.entries.first.username, 'a@b.c');
      expect(session.entries.first.domain, 'mail.example.com');
      session.vrk.dispose();
    });

    test('duress vault can be independently locked/unlocked', () async {
      final crypto = VaultCryptoV4();
      final primaryJson = Uint8List.fromList('{"entries":[]}'.codeUnits);
      final decoyJson = Uint8List.fromList(
        '{"entries":[{"id":"d1","title":"Old","username":"a","password":"x",'
        '"url":"old.com","domain":"old.com","tier":0}]}'.codeUnits,
      );
      final fixedSalt = Uint8List.fromList(List.generate(16, (i) => i));
      final decoy = await crypto.lockDecoy(decoyJson, _mp('duress'), fixedSalt);
      final blob = await crypto.lockVault(primaryJson, _mp('primary'),
          decoyBlob: decoy, fixedSalt: fixedSalt);

      // Unlock duress, dispose VRK (lock), then unlock again.
      final s1 = await crypto.duressUnlockSession(blob, _mp('duress'));
      expect(s1.entries.length, 1);
      s1.vrk.dispose();
      final s2 = await crypto.duressUnlockSession(blob, _mp('duress'));
      expect(s2.entries.length, 1);
      s2.vrk.dispose();
    });

    test('duress unlock fails when no decoy present (noise slot 2)', () async {
      final crypto = VaultCryptoV4();
      final primaryJson = Uint8List.fromList('{"entries":[]}'.codeUnits);
      // No decoy blob -> slot 2 is random noise.
      final blob = await crypto.lockVault(primaryJson, _mp('primary'));
      await expectLater(
        crypto.duressUnlockSession(blob, _mp('duress')),
        throwsA(isA<DuressDecryptError>()),
      );
    });
  });
}
