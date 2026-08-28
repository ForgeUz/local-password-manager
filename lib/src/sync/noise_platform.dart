// Intent: Deep module boundary for Noise Protocol (PSK pattern).
abstract class NoisePlatform {
  Future<bool> initiatePairing(String pin, String peerId);
  Future<String> getStaticPublicKey();
}
