import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/security/adaptive_posture.dart';

// Intent: v5 E16 — rule-based adaptive security posture with strict-roaming
// opt-in. Rules: canary -> lockdown; 2+ failures -> high ALWAYS; unknown
// network -> high ONLY inside opt-in strict roaming (off by default); known
// network + no failures -> low.
void main() {
  group('v5 E16 AdaptivePosture', () {
    test('canary triggered -> lockdown', () {
      final p = AdaptivePosture.evaluate(
        canaryTriggered: true,
        networkRecognized: true,
        recentFailures: 0,
      );
      expect(p.level, PostureLevel.lockdown);
    });

    test('unknown network WITHOUT strict roaming stays LOW', () {
      final p = AdaptivePosture.evaluate(
        canaryTriggered: false,
        networkRecognized: false,
        recentFailures: 0,
        strictRoamingEnabled: false,
      );
      expect(p.level, PostureLevel.low);
    });

    test('unknown network WITH strict roaming armed -> HIGH', () {
      final p = AdaptivePosture.evaluate(
        canaryTriggered: false,
        networkRecognized: false,
        recentFailures: 0,
        strictRoamingEnabled: true,
      );
      expect(p.level, PostureLevel.high);
    });

    test('known network + no failures -> low', () {
      final p = AdaptivePosture.evaluate(
        canaryTriggered: false,
        networkRecognized: true,
        recentFailures: 0,
      );
      expect(p.level, PostureLevel.low);
    });

    test('two or more failures ALWAYS escalate to HIGH (regardless of network)', () {
      final known = AdaptivePosture.evaluate(
        canaryTriggered: false,
        networkRecognized: true,
        recentFailures: 2,
      );
      final unknownNoRoam = AdaptivePosture.evaluate(
        canaryTriggered: false,
        networkRecognized: false,
        recentFailures: 2,
        strictRoamingEnabled: false,
      );
      expect(known.level, PostureLevel.high);
      expect(unknownNoRoam.level, PostureLevel.high);
    });

    test('lockdown policy: zero auto-lock, no biometric, fresh MP autofill', () {
      final p = AdaptivePosture.evaluate(
        canaryTriggered: true,
        networkRecognized: true,
        recentFailures: 0,
      );
      expect(p.autoLockTimeout, Duration.zero);
      expect(p.biometricFastPath, isFalse);
      expect(p.autofillRequiresFreshMp, isTrue);
    });
  });
}