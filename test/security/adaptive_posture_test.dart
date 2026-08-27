// File: test/security/adaptive_posture_test.dart
// Intent: Kill-tests for AdaptivePosture rule engine (M134-M137).
// Invariants:
// - Canary triggered -> lockdown (overrides ALL other conditions).
// - recentFailures >= 2 -> high (regardless of network).
// - Unknown network + strictRoamingEnabled=false -> low (not high).
// - High posture -> autoLockTimeout = 30 seconds.

import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/security/adaptive_posture.dart';

void main() {
  group('M134: Canary lockdown priority', () {
    test('canaryTriggered=true -> lockdown (overrides low failures + known network)', () {
      final policy = AdaptivePosture.evaluate(
        canaryTriggered: true,
        networkRecognized: true,
        recentFailures: 0,
      );
      expect(policy.level, equals(PostureLevel.lockdown));
      expect(policy.autoLockTimeout, equals(Duration.zero));
      expect(policy.biometricFastPath, isFalse);
    });
  });

  group('M135: Failure threshold enforcement', () {
    test('recentFailures=2 -> high (regardless of network)', () {
      final policy = AdaptivePosture.evaluate(
        canaryTriggered: false,
        networkRecognized: true,
        recentFailures: 2,
      );
      expect(policy.level, equals(PostureLevel.high));
      expect(policy.autoLockTimeout, equals(const Duration(seconds: 30)));
      expect(policy.biometricFastPath, isFalse);
    });

    test('recentFailures=1 -> low (below threshold)', () {
      final policy = AdaptivePosture.evaluate(
        canaryTriggered: false,
        networkRecognized: true,
        recentFailures: 1,
      );
      expect(policy.level, equals(PostureLevel.low));
      expect(policy.autoLockTimeout, equals(const Duration(minutes: 5)));
    });
  });

  group('M136: Strict roaming opt-in enforcement', () {
    test('unknown network + strictRoamingEnabled=false -> low', () {
      final policy = AdaptivePosture.evaluate(
        canaryTriggered: false,
        networkRecognized: false,
        recentFailures: 0,
        strictRoamingEnabled: false,
      );
      expect(policy.level, equals(PostureLevel.low));
    });

    test('unknown network + strictRoamingEnabled=true -> high', () {
      final policy = AdaptivePosture.evaluate(
        canaryTriggered: false,
        networkRecognized: false,
        recentFailures: 0,
        strictRoamingEnabled: true,
      );
      expect(policy.level, equals(PostureLevel.high));
    });
  });
}
