import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/crypto/errors.dart';
import 'package:vault_crypto/src/crypto/native/secure_buffer.dart';
import 'package:vault_crypto/src/crypto/v4/constants.dart';
import 'package:vault_crypto/src/crypto/v4/header.dart';
import 'package:vault_crypto/src/crypto/v4/vault_crypto_v4.dart';

// Intent: Verify the v4 vault lock/unlock (per-entry hierarchy + header-as-AAD).
// Invariants: round-trip; wrong MP fails; header tamper fails; vault_count=2.
SecureBuffer createMP(String mp) {
  final buf = SecureBuffer.alloc(mp.length);
  buf.writeBytes(Uint8List.fromList(mp.codeUnits));
  return buf;
}

void main() {
  group('VaultCryptoV4', () {
    test('lock/unlock round-trips a vault', () async {
      final crypto = VaultCryptoV4();
      final json = Uint8List.fromList('{"entries":[]}'.codeUnits);
      final mp = createMP('testMP');
      final blob = await crypto.lockVault(json, mp);
      final result = await crypto.unlockVault(blob, mp);
      expect(result, equals(json));
    });

    test('header has GEN4 magic and vault_count=2', () async {
      final crypto = VaultCryptoV4();
      final json = Uint8List.fromList('{}'.codeUnits);
      final mp = createMP('mp');
      final blob = await crypto.lockVault(json, mp);
      final bd = blob.buffer.asByteData();
      expect(bd.getInt32(0, Endian.big), V4Constants.magic);
      expect(blob[4], 4);
      // vault_count is at fixed offset 43 (after salt+nonce)
      expect(blob[43], 2);
    });

    test('wrong password throws DecryptionFailedError', () async {
      final crypto = VaultCryptoV4();
      final json = Uint8List.fromList('{}'.codeUnits);
      final mp1 = createMP('right');
      final mp2 = createMP('wrong');
      final blob = await crypto.lockVault(json, mp1);
      await expectLater(
        crypto.unlockVault(blob, mp2),
        throwsA(isA<DecryptionFailedError>()),
      );
    });

    test('header tamper throws DecryptionFailedError', () async {
      final crypto = VaultCryptoV4();
      final json = Uint8List.fromList('{}'.codeUnits);
      final mp = createMP('mp');
      final blob = await crypto.lockVault(json, mp);
      blob[15] = blob[15] ^ 0x01;
      await expectLater(
        crypto.unlockVault(blob, mp),
        throwsA(isA<DecryptionFailedError>()),
      );
    });
  });

  group('v5 header MAC (E12)', () {
    test('outer AEAD is empty-plaintext header MAC (tag only, no ciphertext)', () async {
      final crypto = VaultCryptoV4();
      final json = Uint8List.fromList('{"entries":[]}'.codeUnits);
      final mp = createMP('testMP');
      final blob = await crypto.lockVault(json, mp);
      final header = V4Header.parse(blob);
      final hdrLen = _headerLength(header);
      // Layout: [header][slot2 (256B noise)][tag (16B)]. Tag is last 16.
      expect(blob.length, hdrLen + 256 + 16);
      // Unlock succeeds.
      final result = await crypto.unlockVault(blob, mp);
      expect(result, equals(json));
    });

    test('wrong MP still fails on empty-plaintext header MAC', () async {
      final crypto = VaultCryptoV4();
      final json = Uint8List.fromList('{}'.codeUnits);
      final blob = await crypto.lockVault(json, createMP('right'));
      await expectLater(
        crypto.unlockVault(blob, createMP('wrong')),
        throwsA(isA<DecryptionFailedError>()),
      );
    });
  });

  group('v5 single-file two-slot deniability (E3/E4)', () {
    test('header layout identical with and without decoy embedded', () async {
      final crypto = VaultCryptoV4();
      final json = Uint8List.fromList('{"entries":[]}'.codeUnits);
      final mp = createMP('testMP');
      final fixedSalt = Uint8List.fromList(List.generate(16, (i) => i));
      // Without decoy.
      final blobPlain = await crypto.lockVault(json, mp, fixedSalt: fixedSalt);
      // With a decoy blob embedded in slot 2 (same salt as primary).
      final decoy = await crypto.lockDecoy(
        Uint8List.fromList('{"entries":[]}'.codeUnits),
        createMP('duress'),
        fixedSalt,
      );
      final blobDecoy = await crypto.lockVault(json, mp,
          decoyBlob: decoy, fixedSalt: fixedSalt);
      // Fixed header region identical (single salt, two slots).
      final hdrPlain = V4Header.parse(blobPlain);
      final hdrDecoy = V4Header.parse(blobDecoy);
      expect(hdrPlain.salt, equals(hdrDecoy.salt));
      expect(hdrPlain.vaultCount, 2);
      expect(hdrDecoy.vaultCount, 2);
      // Both unlock with the primary MP.
      expect(await crypto.unlockVault(blobPlain, mp), equals(json));
      expect(await crypto.unlockVault(blobDecoy, mp), equals(json));
    });

    test('duress MP opens decoy embedded in slot 2 of the single file', () async {
      final crypto = VaultCryptoV4();
      final primaryJson = Uint8List.fromList('{"entries":[]}'.codeUnits);
      final decoyJson = Uint8List.fromList(
        '{"entries":[{"id":"d1","title":"Old Email","username":"a@b.c",'
        '"password":"low","url":"mail.example.com","domain":"mail.example.com",'
        '"tier":0}]}'.codeUnits,
      );
      final mp = createMP('primary');
      final duressMp = createMP('duress');
      final fixedSalt = Uint8List.fromList(List.generate(16, (i) => 0xFF - i));
      final decoy = await crypto.lockDecoy(decoyJson, duressMp, fixedSalt);
      final blob = await crypto.lockVault(primaryJson, mp,
          decoyBlob: decoy, fixedSalt: fixedSalt);

      // Primary MP -> primary vault.
      expect(await crypto.unlockVault(blob, mp), equals(primaryJson));
      // Duress MP -> decoy vault from slot 2.
      final session = await crypto.duressUnlockSession(blob, duressMp);
      expect(session.entries.length, 1);
      expect(session.entries.first.id, 'd1');
      session.vrk.dispose();
    });
  });
}

int _headerLength(V4Header header) {
  var len = V4Constants.fixedHeaderSize + 2;
  for (final rec in header.entries) {
    len += V4Constants.uuidSize + 1 + 2 + rec.wrappedDek.length +
        2 + rec.searchTags.length * V4Constants.searchTagSize +
        2 + rec.vectorClock.length + 4 + rec.ciphertext.length;
  }
  return len;
}