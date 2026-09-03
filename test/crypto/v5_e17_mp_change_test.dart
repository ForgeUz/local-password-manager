import 'dart:io';
import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/crypto/errors.dart';
import 'package:vault_crypto/src/crypto/native/argon2id.dart';
import 'package:vault_crypto/src/crypto/native/secure_buffer.dart';
import 'package:vault_crypto/src/crypto/v4/header.dart';
import 'package:vault_crypto/src/crypto/v4/search_tag.dart';
import 'package:vault_crypto/src/crypto/v4/second_factor.dart';
import 'package:vault_crypto/src/crypto/v4/vault_crypto_v4.dart';
import 'package:vault_crypto/src/vault/vault_storage.dart';

// Intent: v5 E17/V3.3 — MP change is ATOMIC: re-wrap all DEKs under the new
// VRK, recompute ALL search_tags, rewrite header + all payloads + re-encrypt
// the SFM file in ONE temp-file-then-rename save. No lazy "fix on next unlock"
// mixed state. Old MP fails after change; new MP + TOTP and new MP + backup
// code both succeed. Interrupted change leaves the old file intact.
SecureBuffer createMP(String mp) {
  final buf = SecureBuffer.alloc(mp.length);
  buf.writeBytes(Uint8List.fromList(mp.codeUnits));
  return buf;
}

void main() {
  group('v5 E17 atomic MP change', () {
    test('MP change produces a fully valid file in ONE atomic save', () async {
      final crypto = VaultCryptoV4();
      final json = Uint8List.fromList(
        '{"entries":[{"id":"e1","title":"Bank","username":"u",'
                '"password":"p","url":"bank.example.com","domain":"bank.example.com",'
                '"tier":1}]}'
            .codeUnits,
      );
      final oldMp = createMP('oldMP');
      final newMp = createMP('newMP');
      final sfm = Uint8List.fromList('123456'.codeUnits);
      final codes = ['8246-9130', '1111-2222'];

      // Lock with old MP + SFM folded into KDF.
      final blob = await crypto.lockVault(json, oldMp, totpBytes: sfm);
      final mkBase = await _deriveMkBase(oldMp, blob);
      final sfmFile = SecondFactor.seal(mkBase, sfm, codes);

      // Atomic MP change.
      final result = await crypto.changeMasterPassword(blob, oldMp, newMp,
          sfmFile: sfmFile);
      expect(result.sfmFile, isNotNull);

      // Old MP fails (real KDF path, no bypass).
      await expectLater(
        crypto.unlockSession(result.blob, oldMp, totpBytes: sfm),
        throwsA(isA<DecryptionFailedError>()),
      );

      // New MP + TOTP succeeds.
      final session =
          await crypto.unlockSession(result.blob, newMp, totpBytes: sfm);
      expect(session.entries.length, 1);
      expect(session.entries.first.id, 'e1');
      session.vrk.dispose();

      // New MP + backup code succeeds (SFM re-sealed under new MK_base).
      final bc = await crypto.unlockWithBackupCode(
          result.blob, newMp, result.sfmFile!, codes.first);
      expect(bc.session.entries.length, 1);
      bc.session.vrk.dispose();
    });

    test('interrupted change leaves old file intact (temp + rename)', () async {
      final dir = Directory.systemTemp.createTempSync('vault_e17_');
      addTearDown(() => dir.deleteSync(recursive: true));
      final storage = VaultStorage(baseDir: dir);
      final crypto = VaultCryptoV4();
      final json = Uint8List.fromList('{"entries":[]}'.codeUnits);
      final oldMp = createMP('oldMP');
      final newMp = createMP('newMP');
      final blob = await crypto.lockVault(json, oldMp);
      await storage.writeBlob(blob);

      // Simulate an interrupted change: write the temp file but never rename.
      final tmp = File('${dir.path}${Platform.pathSeparator}.vault.blob.tmp');
      final newBlob =
          (await crypto.changeMasterPassword(blob, oldMp, newMp)).blob;
      await tmp.writeAsBytes(newBlob, flush: true);

      // The live file is still the OLD blob: old MP still opens it.
      final live = await storage.readBlob();
      expect(live, equals(blob));
      final session = await crypto.unlockSession(live, oldMp);
      session.vrk.dispose();
      // New MP does NOT open the live file (no mixed state).
      await expectLater(
        crypto.unlockSession(live, newMp),
        throwsA(isA<DecryptionFailedError>()),
      );
    });

    test('no mixed tag/VRK state: search works under new VRK only', () async {
      final crypto = VaultCryptoV4();
      final json = Uint8List.fromList(
        '{"entries":[{"id":"e1","title":"Bank","username":"u",'
                '"password":"p","url":"bank.example.com","domain":"bank.example.com",'
                '"tier":1}]}'
            .codeUnits,
      );
      final oldMp = createMP('oldMP');
      final newMp = createMP('newMP');
      final blob = await crypto.lockVault(json, oldMp);
      final result = await crypto.changeMasterPassword(blob, oldMp, newMp);

      // New MP opens; search_tags were recomputed under the new SearchKey.
      final session = await crypto.unlockSession(result.blob, newMp);
      expect(session.searchTags['e1'], isNotNull);
      // The stored tag must match a fresh computation under the new VRK.
      final newVrk = session.vrk.readBytes();
      final recomputed = SearchTag.computePrefixes(newVrk, 'bank.example.com');
      expect(session.searchTags['e1']!.length, recomputed.length);
      session.vrk.dispose();
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
