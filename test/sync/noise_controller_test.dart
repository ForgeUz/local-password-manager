import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/sync/noise_platform.dart';
import 'package:vault_crypto/src/sync/noise_controller.dart';

class MockNoisePlatform implements NoisePlatform {
  String? lastPin;
  String? lastPeerId;
  bool shouldSucceed = true;

  @override
  Future<bool> initiatePairing(String pin, String peerId) async {
    lastPin = pin;
    lastPeerId = peerId;
    return shouldSucceed;
  }

  @override
  Future<String> getStaticPublicKey() async {
    return 'mock_static_key_123';
  }
}

void main() {
  test('NoiseController calls initiatePairing with PIN and PeerId', () async {
    final mock = MockNoisePlatform();
    final controller = NoiseController(platform: mock);

    final success = await controller.pair('123456', 'peer_abc');
    
    expect(success, isTrue);
    expect(mock.lastPin, '123456');
    expect(mock.lastPeerId, 'peer_abc');
  });

  test('NoiseController fails gracefully on platform error', () async {
    final mock = MockNoisePlatform()..shouldSucceed = false;
    final controller = NoiseController(platform: mock);

    final success = await controller.pair('000000', 'peer_xyz');
    
    expect(success, isFalse);
  });
}