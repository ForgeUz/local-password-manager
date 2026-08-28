import 'package:flutter/services.dart';

// Intent: Android Keystore VRK storage (Phase D.1). The wrapped VRK is stored
// encrypted under a biometric-gated Keystore key (invalidatedByBiometricEnrollment).
// On unlock, retrieveVrk() prompts biometric and returns the VRK, skipping
// Argon2id. MP remains the always-available fallback.
const _channel = MethodChannel('vault_crypto/biometric');

class KeystoreVrk {
  // Store the wrapped VRK (encrypted under the Keystore key).
  Future<bool> store(Uint8List vrk) async {
    try {
      final ok = await _channel.invokeMethod<bool>('storeVrk', {'blob': vrk});
      return ok ?? false;
    } on PlatformException {
      return false;
    }
  }

  // Biometric-gated retrieval. Returns the VRK bytes, or null if absent /
  // canceled / key invalidated (new fingerprint enrolled).
  Future<Uint8List?> retrieve() async {
    try {
      final bytes = await _channel.invokeMethod<Uint8List>('retrieveVrk');
      return bytes;
    } on PlatformException {
      return null;
    }
  }
}
