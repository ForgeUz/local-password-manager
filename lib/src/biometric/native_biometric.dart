import 'package:flutter/services.dart';
import 'biometric_platform.dart';

// Intent: Connects pure Dart to Android BiometricPrompt + Keystore.
const _channel = MethodChannel('vault_crypto/biometric');

class NativeBiometric implements BiometricPlatform {
  @override
  Future<bool> authenticate() async {
    try {
      final result = await _channel.invokeMethod<bool>('authenticate');
      return result ?? false;
    } on PlatformException {
      return false;
    }
  }
}