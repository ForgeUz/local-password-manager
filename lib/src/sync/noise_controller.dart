import 'noise_platform.dart';

// Intent: Bridges pure PairingSession to native Noise crypto.
class NoiseController {
  final NoisePlatform _platform;

  NoiseController({required NoisePlatform platform}) : _platform = platform;

  Future<bool> pair(String pin, String peerId) async {
    try {
      return await _platform.initiatePairing(pin, peerId);
    } catch (_) {
      return false;
    }
  }

  Future<String> getStaticPublicKey() async {
    return await _platform.getStaticPublicKey();
  }
}
