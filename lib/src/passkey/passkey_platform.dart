// Intent: Imperative shell for Android 14+ CredentialManager (FIDO2/WebAuthn).
// Invariants:
// - Private keys NEVER leave hardware Keystore.
// - Core only receives opaque credentialId (base64url string).
// State Transition: Request -> OS Biometric Prompt -> Signature/CredentialId.
// Dependencies: flutter/services (MethodChannel).

import 'package:flutter/services.dart';

const _channel = MethodChannel('vault_crypto/passkey');

class PasskeyPlatform {
  const PasskeyPlatform._();

  /// Create a new FIDO2 passkey for a Relying Party.
  /// Returns the opaque credentialId (base64url) to store in the vault.
  static Future<String?> create({
    required String rpId,
    required String rpName,
    required String userId,
    required String userName,
    required String challenge,
  }) async {
    try {
      return await _channel.invokeMethod<String>('createPasskey', {
        'rpId': rpId,
        'rpName': rpName,
        'userId': userId,
        'userName': userName,
        'challenge': challenge,
      });
    } on PlatformException {
      return null;
    }
  }

  /// Authenticate using an existing FIDO2 passkey.
  /// Returns the signature and credentialId used.
  static Future<Map<String, String>?> get({
    required String rpId,
    required String challenge,
    required List<String> allowedCredentials,
  }) async {
    try {
      final result =
          await _channel.invokeMethod<Map<dynamic, dynamic>>('getPasskey', {
        'rpId': rpId,
        'challenge': challenge,
        'allowedCredentials': allowedCredentials,
      });
      return result?.cast<String, String>();
    } on PlatformException {
      return null;
    }
  }
}
