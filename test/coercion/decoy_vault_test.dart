import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/coercion/decoy_vault.dart';
import 'package:vault_crypto/src/crypto/errors.dart';
import 'package:vault_crypto/src/crypto/native/secure_buffer.dart';
import 'package:vault_crypto/src/crypto/v4/vault_crypto_v4.dart';

// Intent: Verify decoy-vault setup produces an 8-digit cancellation code and a
// decoy locked under a *separate* VRK (VRK_duress) embedded in slot 2 of the
// single vault file (v5 E3/E4). Primary unlock path cannot open it.
void main() {
  SecureBuffer mp(String s) =>
      SecureBuffer.fromList(Uint8List.fromList(s.codeUnits));

  test('setup duress generates 8-digit cancellation code + separate VRK',
      () async {
    final crypto = VaultCryptoV4();
    final duressMp = mp('duress-secret');
    final primaryMp = mp('primary-secret');
    final fixedSalt = Uint8List.fromList(List.generate(16, (i) => i));

    // Build the decoy blob (locked under VRK_duress, same salt as primary).
    final decoyJson = Uint8List.fromList(
      '{"entries":[{"id":"d1","title":"Old Email","username":"a@b.c",'
              '"password":"lowvalue","url":"mail.example.com",'
              '"domain":"mail.example.com","tier":0}]}'
          .codeUnits,
    );
    final decoy = await crypto.lockDecoy(decoyJson, duressMp, fixedSalt);

    // Embed decoy into slot 2 of the single primary vault file.
    final primaryJson = Uint8List.fromList('{"entries":[]}'.codeUnits);
    final blob = await crypto.lockVault(primaryJson, primaryMp,
        decoyBlob: decoy, fixedSalt: fixedSalt);

    // 8-digit cancellation code (static helper).
    expect(DecoyVault.generateCancellationCode(), matches(RegExp(r'^\d{8}$')));

    // Duress MP opens the decoy from slot 2 of the single file.
    final session = await crypto.duressUnlockSession(blob, duressMp);
    expect(session.entries.length, 1);
    expect(session.entries.first.id, 'd1');
    session.vrk.dispose();

    // Primary unlock path (VRK via "GENESIS-VRK-v4") must NOT open the decoy.
    await expectLater(
      crypto.unlockSession(blob, duressMp),
      throwsA(isA<DecryptionFailedError>()),
    );
  });
}
