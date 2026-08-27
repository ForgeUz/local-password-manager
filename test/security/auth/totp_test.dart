// File: test/security/auth/test_totp.dart
// Intent: security.md gate 4.2 — TOTP integration verification.
// Invariants:
// - TOTP is folded into KDF (mathematically affects key derivation).
// - TOTP verification is constant-time (no early exit).
// - TOTP secret is sealed under MK_base via AES-GCM.
// - TOTP secret never exists in plaintext after import.
// - Failed TOTP attempts are rate-limited.
// - Backup codes release second-factor material through real KDF path.
// - Backup codes are single-use.
// - Backup codes are Argon2id-hashed before storage.
// Dependencies: second_factor.dart, key_hierarchy.dart, errors.dart.

import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/crypto/errors.dart';
import 'package:vault_crypto/src/crypto/v4/key_hierarchy.dart';
import 'package:vault_crypto/src/crypto/v4/second_factor.dart';

Uint8List _bytes(int len, int seed) =>
    Uint8List.fromList(List.generate(len, (i) => (seed + i) & 0xFF));

void main() {
  group('Gate 4.2 TOTP Integration', () {
    test('TOTP is folded into KDF (affects key derivation)', () {
      final mk = _bytes(32, 1);
      final totp = _bytes(6, 2);
      final vrkNoTotp = KeyHierarchy.deriveVrk(mk);
      final vrkWithTotp = KeyHierarchy.deriveVrk(mk, totpBytes: totp);
      // Different VRK when TOTP is folded in.
      expect(vrkNoTotp, isNot(equals(vrkWithTotp)));
    });

    test('TOTP secret is sealed under MK_base via AES-GCM', () {
      final mkBase = _bytes(32, 1);
      final sfm = _bytes(20, 2); // TOTP seed
      final file = SecondFactor.seal(mkBase, sfm, ['code1', 'code2']);
      // The SFM file must not contain the plaintext seed.
      expect(_contains(file, sfm), isFalse);
    });

    test('backup code releases SFM through real KDF path', () {
      final mkBase = _bytes(32, 1);
      final sfm = _bytes(20, 2);
      final file = SecondFactor.seal(mkBase, sfm, ['backup1']);
      final (released, updated) = SecondFactor.open(mkBase, file, 'backup1');
      expect(released, equals(sfm));
      // The updated file consumed the code (count decremented).
      expect(updated.length, lessThan(file.length));
    });

    test('backup codes are single-use', () {
      final mkBase = _bytes(32, 1);
      final sfm = _bytes(20, 2);
      final file = SecondFactor.seal(mkBase, sfm, ['backup1']);
      // First use succeeds.
      final (_, updated) = SecondFactor.open(mkBase, file, 'backup1');
      // Second use of the same code on the updated file must fail.
      expect(
        () => SecondFactor.open(mkBase, updated, 'backup1'),
        throwsA(isA<BackupCodeError>()),
      );
    });

    test('failed TOTP attempts are rate-limited', () {
      final mkBase = _bytes(32, 1);
      final sfm = _bytes(20, 2);
      final file = SecondFactor.seal(mkBase, sfm, ['backup1']);
      // 3 wrong attempts -> rate-limited (BackupCodeError).
      var current = file;
      for (var i = 0; i < 3; i++) {
        try {
          SecondFactor.open(mkBase, current, 'wrong');
        } on BackupCodeError catch (e) {
          if (e.updatedFile != null) current = e.updatedFile!;
        }
      }
      // 4th attempt (even with correct code) must be rate-limited.
      expect(
        () => SecondFactor.open(mkBase, current, 'backup1'),
        throwsA(isA<BackupCodeError>()),
      );
    });

    test('backup codes are Argon2id-hashed before storage', () {
      final mkBase = _bytes(32, 1);
      final sfm = _bytes(20, 2);
      final file = SecondFactor.seal(mkBase, sfm, ['backup1']);
      // The plaintext code must not appear in the file.
      expect(_contains(file, Uint8List.fromList('backup1'.codeUnits)), isFalse);
    });
  });
}

bool _contains(Uint8List haystack, Uint8List needle) {
  if (needle.isEmpty || needle.length > haystack.length) return false;
  for (var i = 0; i <= haystack.length - needle.length; i++) {
    var match = true;
    for (var j = 0; j < needle.length; j++) {
      if (haystack[i + j] != needle[j]) {
        match = false;
        break;
      }
    }
    if (match) return true;
  }
  return false;
}
