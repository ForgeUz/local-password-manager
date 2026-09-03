import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/sync/noise_session.dart';

// Intent: Verify Noise PSK session (Phase G.1).
// Invariants: correct PIN + within 60s -> paired + key pinned (TOFU); wrong PIN
// fails; 3 failed attempts -> cooldown.

// Mock transport: succeeds only if the submitted PIN matches the expected one.
class MockTransport implements Transport {
  final String expectedPin;
  MockTransport(String pin) : expectedPin = pin;
  @override
  Future<bool> handshake(String pin) async => pin == expectedPin;
}

void main() {
  test('correct PIN -> paired and peer key pinned', () async {
    final now = DateTime.now();
    final s = NoiseSession(MockTransport('123456'), now: () => now);
    final st = await s.pair('123456');
    expect(st.status, PairStatus.paired);
    expect(st.pinnedPeerKey, isNotNull);
  });

  test('wrong PIN -> not paired', () async {
    final now = DateTime.now();
    final s = NoiseSession(MockTransport('123456'), now: () => now);
    final st = await s.pair('000000');
    expect(st.status, isNot(PairStatus.paired));
  });

  test('3 failed attempts -> cooldown', () async {
    final now = DateTime.now();
    final s = NoiseSession(MockTransport('123456'), now: () => now);
    await s.pair('bad');
    await s.pair('bad');
    final st = await s.pair('bad');
    expect(st.status, PairStatus.cooldown);
    final during = await s.pair('bad');
    expect(during.status, PairStatus.cooldown);
  });

  test('fresh idle session can pair (new window)', () async {
    final s = NoiseSession(MockTransport('987654'), now: () => DateTime.now());
    final st = await s.pair('987654');
    expect(st.status, PairStatus.paired);
  });
}
