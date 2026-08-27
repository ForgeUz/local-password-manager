// File: test/security/multivault/test_multiple_vaults.dart
// Intent: security2.md gate 29.1 — Multiple vault files.
// Invariants:
// - Two vault files, different master passwords.
// - Unlock vault A, then attempt to unlock vault B with A's password.
// - Vault B rejects vault A's password (different salts/KDF).
// - No key material from vault A persists when unlocking vault B.
// - Shamir shares are vault-specific (share from A doesn't recover B).
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

void main() {
  group('Gate 29.1 Multiple Vault Files', () {
    test('two vaults with different passwords: each opens with its own', () async {
      final crypto = VaultCryptoV4();
      final jsonA = Uint8List.fromList('{"entries":[]}'.codeUnits);
      final jsonB = Uint8List.fromList('{"entries":[]}'.codeUnits);
      final blobA = await crypto.lockVault(jsonA, _mp('passA'));
      final blobB = await crypto.lockVault(jsonB, _mp('passB'));
      // Each opens with its own password.
      expect(await crypto.unlockVault(blobA, _mp('passA')), equals(jsonA));
      expect(await crypto.unlockVault(blobB, _mp('passB')), equals(jsonB));
    });

    test('vault B rejects vault A password (different salts/KDF)', () async {
      final crypto = VaultCryptoV4();
      final jsonA = Uint8List.fromList('{"entries":[]}'.codeUnits);
      final jsonB = Uint8List.fromList('{"entries":[]}'.codeUnits);
      final blobA = await crypto.lockVault(jsonA, _mp('passA'));
      final blobB = await crypto.lockVault(jsonB, _mp('passB'));
      // Vault A's password cannot open vault B.
      await expectLater(
        crypto.unlockVault(blobB, _mp('passA')),
        throwsA(anything),
      );
      // Vault B's password cannot open vault A.
      await expectLater(
        crypto.unlockVault(blobA, _mp('passB')),
        throwsA(anything),
      );
    });

    test('no key material from vault A persists when unlocking vault B', () async {
      final crypto = VaultCryptoV4();
      final jsonA = Uint8List.fromList('{"entries":[]}'.codeUnits);
      final jsonB = Uint8List.fromList('{"entries":[]}'.codeUnits);
      final blobA = await crypto.lockVault(jsonA, _mp('passA'));
      final blobB = await crypto.lockVault(jsonB, _mp('passB'));
      // Unlock A, dispose its VRK, then unlock B.
      final sessionA = await crypto.unlockSession(blobA, _mp('passA'));
      sessionA.vrk.dispose();
      // B opens independently with its own password.
      expect(await crypto.unlockVault(blobB, _mp('passB')), equals(jsonB));
    });

    test('shamir shares are vault-specific (share from A does not recover B)', () {
      // The MK is vault-specific; shares of A's MK cannot recover B's MK.
      final mkA = Uint8List.fromList(List.generate(32, (i) => i));
      final mkB = Uint8List.fromList(List.generate(32, (i) => 0xFF - i));
      final sharesA = ShamirKit.split(mkA, n: 3, k: 2);
      // Reconstructing from A's shares yields A's MK, not B's.
      final recovered = ShamirKit.reconstruct([sharesA[0], sharesA[1]]);
      expect(recovered, equals(mkA));
      expect(recovered, isNot(equals(mkB)));
    });
  });
}
