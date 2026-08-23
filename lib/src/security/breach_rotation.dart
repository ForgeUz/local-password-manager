import 'dart:math';

// Intent: One-tap breach rotation (v3 §18.3 / Phase K.3). When breach monitoring
// flags a domain, generate a new strong password, mark the old one 'compromised'
// (NOT deleted), leave the TOTP seed untouched, and require fresh re-auth for
// Critical-tier entries. Pure logic.
// Dependencies: dart:math.

class RotationResult {
  final String newPassword;
  final String oldPassword; // preserved, marked compromised
  final bool totpSeedUntouched;
  const RotationResult({
    required this.newPassword,
    required this.oldPassword,
    required this.totpSeedUntouched,
  });
}

class BreachRotation {
  static const String _charset =
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#\$%^&*()-_=+';

  // Generate a strong password via rejection sampling (no modulo bias).
  static String generateStrongPassword({int length = 20}) {
    final r = Random.secure();
    final buf = StringBuffer();
    while (buf.length < length) {
      final b = r.nextInt(256);
      if (b < _charset.length) buf.write(_charset[b]);
    }
    return buf.toString();
  }

  // Rotate an entry's password. Returns the new password + the old (preserved,
  // marked compromised). TOTP seed is never touched. If the entry is Critical,
  // the caller must have already performed fresh re-auth (isAuthed).
  static RotationResult rotate({
    required String oldPassword,
    required bool isCritical,
    required bool isAuthed,
    int length = 20,
  }) {
    if (isCritical && !isAuthed) {
      throw StateError('Critical-tier rotation requires fresh re-auth');
    }
    final newPassword = generateStrongPassword(length: length);
    return RotationResult(
      newPassword: newPassword,
      oldPassword: oldPassword, // preserved, marked compromised by caller
      totpSeedUntouched: true,
    );
  }
}