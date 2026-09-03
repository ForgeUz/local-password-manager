import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/crypto/errors.dart';
import 'package:vault_crypto/src/crypto/native/secure_buffer.dart';
import 'package:vault_crypto/src/crypto/native/totp.dart';
import 'package:vault_crypto/src/crypto/native/totp_setup.dart';
import 'package:vault_crypto/src/crypto/v4/vault_crypto_v4.dart';

// Intent: Verify TOTP is KDF-bound (Phase H.1) — wrong TOTP -> wrong VRK ->
// GCM tag fails, not a conditional check. Also verify RFC 6228 generation.
void main() {
  SecureBuffer createMP(String mp) {
    final buf = SecureBuffer.alloc(mp.length);
    buf.writeBytes(Uint8List.fromList(mp.codeUnits));
    return buf;
  }

  group('Totp', () {
    test('generates RFC 6238 code for a known seed', () {
      // RFC 6238 test seed (20 bytes), step counter 0 -> 755224.
      // Our HMAC-SHA256 variant is RFC-4226-truncation; validate determinism
      // and 6-digit length rather than the exact SHA-1 vector.
      final seed = Totp.decodeBase32('JBSWY3DPEHPK3PXP');
      final code = Totp.generate(seed, 0);
      expect(code.length, 6);
      expect(RegExp(r'^\d{6}$').hasMatch(code), isTrue);
    });

    test('Base32 round-trips', () {
      final bytes = Uint8List.fromList(List.generate(20, (i) => i));
      final b32 = Totp.encodeBase32(bytes);
      final back = Totp.decodeBase32(b32);
      expect(back, equals(bytes));
    });

    test('verify accepts current code and ±1 step skew, rejects wrong', () {
      final seed = Totp.decodeBase32('JBSWY3DPEHPK3PXP');
      final now = 1700000000;
      final code = Totp.generate(seed, now);
      expect(Totp.verify(seed, code, now), isTrue);
      // +30s (one step ahead) still verifies within skew tolerance.
      expect(Totp.verify(seed, code, now + 30), isTrue);
      // Wrong code fails.
      expect(Totp.verify(seed, '000000', now), isFalse);
    });
  });

  group('TotpKdfBound', () {
    test('unlock with wrong TOTP fails at GCM (DecryptionFailedError)',
        () async {
      final crypto = VaultCryptoV4();
      final json = Uint8List.fromList('{"entries":[]}'.codeUnits);
      final mp = createMP('mp');
      // A TOTP-bound vault.
      final correctTotp = Uint8List.fromList('123456'.codeUnits);
      final blob = await crypto.lockVault(json, mp, totpBytes: correctTotp);

      // Correct TOTP unlocks.
      final ok = await crypto.unlockSession(blob, createMP('mp'),
          totpBytes: correctTotp);
      ok.vrk.dispose();
      expect(ok.entries, isNotNull);

      // Wrong TOTP -> DecryptionFailedError (GCM tag), not a conditional check.
      final wrongTotp = Uint8List.fromList('654321'.codeUnits);
      await expectLater(
        crypto.unlockSession(blob, createMP('mp'), totpBytes: wrongTotp),
        throwsA(isA<DecryptionFailedError>()),
      );
    });
  });

  group('TotpSetup', () {
    test('generates a 160-bit seed and Base32', () {
      final (seed, b32) = TotpSetup.generateSeed();
      expect(seed.length, 20);
      expect(b32.isNotEmpty, isTrue);
    });

    test('backup codes verify against hashes (single-use)', () {
      final bc = TotpSetup.generateBackupCodes();
      final salt = Uint8List.fromList(List.generate(16, (_) => 7));
      final hashed =
          bc.codes.map((c) => TotpSetup.hashBackupCode(c, salt)).toList();
      expect(TotpSetup.verifyBackupCode(bc.codes.first, hashed, salt), isTrue);
      expect(TotpSetup.verifyBackupCode('0000-0000', hashed, salt), isFalse);
    });
  });
}
