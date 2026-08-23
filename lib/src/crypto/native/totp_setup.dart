import 'dart:math';
import 'dart:typed_data';
import '../native/argon2id.dart';
import '../native/constant_time.dart';
import 'totp.dart';

// Intent: TOTP 2FA setup + backup codes (v3 §12.7 / Phase H.1/H).
// Generates a 160-bit seed (RFC 4226), encodes as Base32 for QR display, and
// generates 10 single-use backup codes stored only as Argon2id hashes.
// Invariants: seed is 160 bits; backup codes single-use via hashed verification.
// Dependencies: dart:math, dart:typed_data, Argon2id, ConstantTime, Totp.

class TotpSetup {
  static const int seedBytes = 20; // 160-bit
  static const int backupCodeCount = 10;

  // Generate a fresh 160-bit TOTP seed, returning raw bytes + Base32 string.
  static (Uint8List seed, String base32) generateSeed() {
    final r = Random.secure();
    final seed = Uint8List.fromList(List.generate(seedBytes, (_) => r.nextInt(256)));
    return (seed, Totp.encodeBase32(seed));
  }

  // Build the otpauth:// URI for QR code display.
  static String otpauthUri(String base32, {String issuer = 'Vault', String account = ''}) {
    return 'otpauth://totp/$issuer:${account.isEmpty ? 'user' : account}?secret=$base32&issuer=$issuer&algorithm=SHA256&digits=6&period=30';
  }

  // Generate backup codes (10). Return plaintext codes for one-time display;
  // store the hashes (Argon2id) in a separate file.
  static BackupCodes generateBackupCodes() {
    final r = Random.secure();
    final codes = List.generate(backupCodeCount, (_) {
      // 8 random digits, e.g. "8246-9130".
      final a = 1000 + r.nextInt(9000);
      final b = 1000 + r.nextInt(9000);
      return '$a-$b';
    });
    return BackupCodes(codes: codes, hashed: <String, String>{}); // filled by hash
  }

  // Hash a backup code (for storage in the separated file).
  static String hashBackupCode(String code, Uint8List salt) {
    final h = Argon2id.derive(
      Uint8List.fromList(code.codeUnits),
      salt,
      memory: 65536,
      iterations: 3,
      parallelism: 1,
    );
    return h.fold<String>('', (a, b) => a + b.toRadixString(16).padLeft(2, '0'));
  }

  // Verify a submitted backup code against the stored hashes (single-use).
  static bool verifyBackupCode(String code, List<String> hashed, Uint8List salt) {
    final candidate = hashBackupCode(code, salt);
    final candBytes = _fromHex(candidate);
    for (final h in hashed) {
      if (ConstantTime.equals(candBytes, _fromHex(h))) return true;
    }
    return false;
  }

  static Uint8List _fromHex(String hex) {
    final out = Uint8List(hex.length ~/ 2);
    for (var i = 0; i < out.length; i++) {
      out[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
    }
    return out;
  }
}

class BackupCodes {
  final List<String> codes; // plaintext, shown exactly once
  final Map<String, String> hashed; // code -> hash
  BackupCodes({required this.codes, required this.hashed});
}