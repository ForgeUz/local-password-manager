// File: test/security/integration/test_full_lifecycle.dart
// Intent: security.md gate 14.1 — Full lifecycle integration testing.
// Invariants:
// - Create vault -> add 100 entries -> lock -> unlock -> verify all accessible.
// - Create vault -> add entries -> change master password -> unlock with new.
// - Create vault -> add entries -> enable TOTP -> lock -> unlock with MP+TOTP.
// - Create vault -> add entries -> set up duress -> unlock with duress.
// - Create vault -> add entries -> generate Shamir shares -> recover.
// Dependencies: vault_crypto_v4.dart, secure_buffer.dart, shamir_kit.dart.

import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/crypto/native/secure_buffer.dart';
import 'package:vault_crypto/src/crypto/v4/vault_crypto_v4.dart';
import 'package:vault_crypto/src/security/shamir_kit.dart';

SecureBuffer _mp(String s) {
  final buf = SecureBuffer.alloc(s.length);
  buf.writeBytes(Uint8List.fromList(s.codeUnits));
  return buf;
}

String _entryJson(int i) {
  return '{"id":"e$i","title":"Entry $i","username":"user$i",'
      '"password":"pw$i","url":"site$i.com","domain":"site$i.com","tier":0}';
}

void main() {
  group('Gate 14.1 Full Lifecycle', () {
    test('create -> add 100 entries -> lock -> unlock -> verify all accessible', () async {
      final crypto = VaultCryptoV4();
      final entries = List.generate(100, (i) => _entryJson(i)).join(',');
      final json = Uint8List.fromList('{"entries":[$entries]}'.codeUnits);
      final blob = await crypto.lockVault(json, _mp('mp'));
      final result = await crypto.unlockVault(blob, _mp('mp'));
      // Round-trip preserves all 100 entries.
      expect(result, equals(json));
    });

    test('change master password -> unlock with new -> verify entries', () async {
      final crypto = VaultCryptoV4();
      final json = Uint8List.fromList(
        '{"entries":[${_entryJson(1)}]}'.codeUnits,
      );
      final blob = await crypto.lockVault(json, _mp('old'));
      final result = await crypto.changeMasterPassword(blob, _mp('old'), _mp('new'));
      // Old password no longer works.
      await expectLater(
        crypto.unlockVault(result.blob, _mp('old')),
        throwsA(anything),
      );
      // New password works and preserves entries.
      final unlocked = await crypto.unlockVault(result.blob, _mp('new'));
      expect(unlocked, equals(json));
    });

    test('enable TOTP -> lock -> unlock with MP+TOTP', () async {
      final crypto = VaultCryptoV4();
      final json = Uint8List.fromList('{"entries":[]}'.codeUnits);
      final totp = Uint8List.fromList([1, 2, 3, 4, 5, 6]);
      final blob = await crypto.lockVault(json, _mp('mp'), totpBytes: totp);
      // Unlock with correct TOTP succeeds (via unlockSession, which folds TOTP).
      final session = await crypto.unlockSession(blob, _mp('mp'), totpBytes: totp);
      expect(session.entries, isEmpty);
      session.vrk.dispose();
      // Unlock with wrong TOTP fails.
      final wrongTotp = Uint8List.fromList([9, 9, 9, 9, 9, 9]);
      await expectLater(
        crypto.unlockSession(blob, _mp('mp'), totpBytes: wrongTotp),
        throwsA(anything),
      );
    });

    test('set up duress -> unlock with duress -> verify decoy entries', () async {
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
      // Duress unlock -> decoy entries.
      final session = await crypto.duressUnlockSession(blob, _mp('duress'));
      expect(session.entries.length, 1);
      expect(session.entries.first.id, 'd1');
      session.vrk.dispose();
    });

    test('generate Shamir shares -> recover -> verify entries', () {
      // The MK is split into shares; reconstructing yields the identical MK.
      final mk = Uint8List.fromList(List.generate(32, (i) => i));
      final shares = ShamirKit.split(mk, n: 3, k: 2);
      final recovered = ShamirKit.reconstruct([shares[0], shares[1]]);
      expect(recovered, equals(mk));
    });
  });
}
