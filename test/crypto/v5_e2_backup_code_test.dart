import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/crypto/errors.dart';
import 'package:vault_crypto/src/crypto/native/argon2id.dart';
import 'package:vault_crypto/src/crypto/native/secure_buffer.dart';
import 'package:vault_crypto/src/crypto/v4/header.dart';
import 'package:vault_crypto/src/crypto/v4/second_factor.dart';
import 'package:vault_crypto/src/crypto/v4/vault_crypto_v4.dart';

// Intent: v5 E2 — backup codes coherent with KDF-bound 2FA. SFM is stored
// encrypted under MK_base in a file OUTSIDE the vault. A valid backup code
// authorizes release of SFM into the KDF; the vault opens via the REAL
// derivation path (no bypass branch). Wrong/consumed/rate-limited code fails
// BEFORE any vault decrypt.
SecureBuffer createMP(String mp) {
  final buf = SecureBuffer.alloc(mp.length);
  buf.writeBytes(Uint8List.fromList(mp.codeUnits));
  return buf;
}

void main() {
  group('v5 E2 backup-code SFM release', () {
    test('MP + valid backup code opens vault via real KDF path', () async {
      final crypto = VaultCryptoV4();
      final json = Uint8List.fromList(
        '{"entries":[{"id":"e1","title":"Bank","username":"u",'
        '"password":"p","url":"bank.example.com","domain":"bank.example.com",'
        '"tier":1}]}'.codeUnits,
      );
      final mp = createMP('mp');
      final sfm = Uint8List.fromList('123456'.codeUnits); // TOTP seed bytes
      final codes = ['8246-9130', '1111-2222', '3333-4444'];

      // Lock the vault with the SFM folded into the KDF (real 2FA path).
      final blob = await crypto.lockVault(json, mp, totpBytes: sfm);
      // Seal the SFM file under MK_base (outside the vault).
      final mkBase = await _deriveMkBase(mp, blob);
      final sfmFile = SecondFactor.seal(mkBase, sfm, codes);

      // Unlock via MP + valid backup code -> SFM released into the KDF.
      final result = await crypto.unlockWithBackupCode(blob, mp, sfmFile, codes.first);
      expect(result.session.entries.length, 1);
      expect(result.session.entries.first.id, 'e1');
      // The code was consumed (single-use): updated file has one fewer hash.
      expect(result.updatedSfmFile.length, lessThan(sfmFile.length));
      result.session.vrk.dispose();
    });

    test('wrong backup code fails BEFORE any vault decrypt', () async {
      final crypto = VaultCryptoV4();
      final json = Uint8List.fromList('{"entries":[]}'.codeUnits);
      final mp = createMP('mp');
      final sfm = Uint8List.fromList('123456'.codeUnits);
      final codes = ['8246-9130'];
      final blob = await crypto.lockVault(json, mp, totpBytes: sfm);
      final mkBase = await _deriveMkBase(mp, blob);
      final sfmFile = SecondFactor.seal(mkBase, sfm, codes);

      await expectLater(
        crypto.unlockWithBackupCode(blob, mp, sfmFile, '0000-0000'),
        throwsA(isA<BackupCodeError>()),
      );
    });

    test('consumed backup code fails on second use', () async {
      final crypto = VaultCryptoV4();
      final json = Uint8List.fromList('{"entries":[]}'.codeUnits);
      final mp = createMP('mp');
      final sfm = Uint8List.fromList('123456'.codeUnits);
      final codes = ['8246-9130'];
      final blob = await crypto.lockVault(json, mp, totpBytes: sfm);
      final mkBase = await _deriveMkBase(mp, blob);
      final sfmFile = SecondFactor.seal(mkBase, sfm, codes);

      // First use consumes the code.
      final r1 = await crypto.unlockWithBackupCode(blob, mp, sfmFile, codes.first);
      r1.session.vrk.dispose();
      // Second use of the same code fails (already consumed).
      await expectLater(
        crypto.unlockWithBackupCode(blob, mp, r1.updatedSfmFile, codes.first),
        throwsA(isA<BackupCodeError>()),
      );
    });

    test('rate-limited after 3 wrong attempts', () async {
      final crypto = VaultCryptoV4();
      final json = Uint8List.fromList('{"entries":[]}'.codeUnits);
      final mp = createMP('mp');
      final sfm = Uint8List.fromList('123456'.codeUnits);
      final codes = ['8246-9130'];
      final blob = await crypto.lockVault(json, mp, totpBytes: sfm);
      final mkBase = await _deriveMkBase(mp, blob);
      var sfmFile = SecondFactor.seal(mkBase, sfm, codes);

      // 3 wrong attempts -> rate-limited.
      for (var i = 0; i < 3; i++) {
        try {
          await crypto.unlockWithBackupCode(blob, mp, sfmFile, '0000-0000');
          fail('expected BackupCodeError');
        } on BackupCodeError catch (e) {
          if (e.updatedFile != null) sfmFile = e.updatedFile!;
        }
      }
      // 4th attempt: rate-limited (attempts >= 3) -> BackupCodeError, no decrypt.
      await expectLater(
        crypto.unlockWithBackupCode(blob, mp, sfmFile, codes.first),
        throwsA(isA<BackupCodeError>()),
      );
    });
  });
}

Future<Uint8List> _deriveMkBase(SecureBuffer mp, Uint8List blob) async {
  final header = V4Header.parse(blob);
  return Argon2id.derive(
    mp.readBytes(),
    header.salt,
    memory: header.kdfMemory,
    iterations: header.kdfIterations,
    parallelism: header.kdfParallelism,
  );
}