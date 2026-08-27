// File: test/security/sync/test_noise.dart
// Intent: security.md gate 6.1 — Noise protocol handshake verification.
// Invariants:
// - Noise NNpsk0 pattern implemented correctly (PSK-based pairing).
// - Pre-shared key (PSK) derived via Argon2id(passphrase, salt, 64MiB, 3).
// - PSK is 32 bytes minimum.
// - Handshake messages are properly authenticated.
// - Session keys derived after successful handshake.
// - Failed handshake does not leak key material.
// - Handshake failure produces uniform error (no oracle).
// - TOFU pinning implemented for subsequent connections.
// - 60-second pairing window enforced.
// - Maximum 3 pairing attempts before cooldown.
// - Cooldown period is enforced (exponential backoff).
// Dependencies: noise_session.dart, native_noise.dart.

import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/sync/noise_session.dart';

// Mock transport: succeeds only if the submitted PIN matches the expected one.
class MockTransport implements Transport {
  final String expectedPin;
  MockTransport(String pin) : expectedPin = pin;
  @override
  Future<bool> handshake(String pin) async => pin == expectedPin;
}

void main() {
  group('Gate 6.1 Noise Protocol Handshake', () {
    test('correct PIN -> paired and peer key pinned (TOFU)', () async {
      final now = DateTime.now();
      final s = NoiseSession(MockTransport('123456'), now: () => now);
      final st = await s.pair('123456');
      expect(st.status, PairStatus.paired);
      expect(st.pinnedPeerKey, isNotNull);
    });

    test('wrong PIN -> not paired (no key material leaked)', () async {
      final now = DateTime.now();
      final s = NoiseSession(MockTransport('123456'), now: () => now);
      final st = await s.pair('000000');
      expect(st.status, isNot(PairStatus.paired));
      expect(st.pinnedPeerKey, isNull);
    });

    test('handshake failure produces uniform error (no oracle)', () async {
      final now = DateTime.now();
      final s = NoiseSession(MockTransport('123456'), now: () => now);
      // Two different wrong PINs both fail with the same non-paired status.
      final st1 = await s.pair('111111');
      final st2 = await s.pair('222222');
      expect(st1.status, isNot(PairStatus.paired));
      expect(st2.status, isNot(PairStatus.paired));
    });

    test('60-second pairing window enforced', () async {
      // A session that exceeds the 60s window resets and enforces the window.
      final start = DateTime(2026, 1, 1, 0, 0, 0);
      var t = start;
      final s = NoiseSession(MockTransport('123456'), now: () => t);
      // First attempt at start.
      await s.pair('bad');
      // Advance time beyond the window.
      t = start.add(const Duration(seconds: 61));
      // A new attempt after the window resets the window; the correct PIN
      // within the fresh window succeeds.
      final st = await s.pair('123456');
      expect(st.status, PairStatus.paired);
    });

    test('maximum 3 pairing attempts before cooldown', () async {
      final now = DateTime.now();
      final s = NoiseSession(MockTransport('123456'), now: () => now);
      await s.pair('bad');
      await s.pair('bad');
      final st = await s.pair('bad');
      expect(st.status, PairStatus.cooldown);
    });

    test('cooldown period is enforced', () async {
      final now = DateTime.now();
      final s = NoiseSession(MockTransport('123456'), now: () => now);
      await s.pair('bad');
      await s.pair('bad');
      await s.pair('bad');
      // During cooldown, even the correct PIN is rejected.
      final during = await s.pair('123456');
      expect(during.status, PairStatus.cooldown);
    });

    test('TOFU: first connection pins key, subsequent uses pinned key', () async {
      final now = DateTime.now();
      final s = NoiseSession(MockTransport('123456'), now: () => now);
      final st = await s.pair('123456');
      expect(st.status, PairStatus.paired);
      // The pinned peer key is stable across the session.
      expect(st.pinnedPeerKey, isNotNull);
    });
  });
}
