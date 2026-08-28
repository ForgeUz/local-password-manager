// Intent: Deep module boundary for native biometric/keystore prompts.
abstract class BiometricPlatform {
  Future<bool> authenticate();
}
