// Intent: Pure CSPRNG challenge generation for WebAuthn/FIDO2.
// Invariants:
// - Challenge MUST be >= 32 bytes (WebAuthn spec).
// - Encoding MUST be base64url (no padding) per WebAuthn spec.
// - No I/O, no global state.
import 'dart:math';
import 'dart:convert';
import 'dart:typed_data';

class PasskeyChallenge {
  const PasskeyChallenge._();

  /// Generate a cryptographically secure, base64url-encoded challenge.
  /// Strips '=' padding to strictly comply with WebAuthn Level 2 spec.
  static String generate({int byteLength = 32}) {
    final random = Random.secure();
    final bytes = Uint8List.fromList(
      List.generate(byteLength, (_) => random.nextInt(256)),
    );
    return base64UrlEncode(bytes).replaceAll('=', '');
  }
}
