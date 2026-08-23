// Intent: Rule-based adaptive security posture (v4 §6.3, v5 E16). Three
// deterministic rules, no ML. Posture drives auto-lock timeout, biometric
// availability, and autofill confirmation requirements.
//   Rule 1: canary triggered -> lockdown
//   Rule 2: 2+ recent failures -> high (ALWAYS, regardless of network)
//           unknown network -> high ONLY inside opt-in "strict roaming mode"
//           (off by default). A roaming laptop must not live in permanent high
//           posture -> users disable security.
//   Rule 3: known network + no failures -> low
// Pure function: no I/O, no side effects (rules_light §9).
// Invariants: canary always wins; failures always escalate; unknown network
// escalates only when strict roaming is armed.

enum PostureLevel { low, high, lockdown }

class PosturePolicy {
  final PostureLevel level;
  final Duration autoLockTimeout;
  final bool biometricFastPath;
  final bool autofillRequiresFreshMp;
  final bool criticalRequiresFido2;

  const PosturePolicy({
    required this.level,
    required this.autoLockTimeout,
    required this.biometricFastPath,
    required this.autofillRequiresFreshMp,
    required this.criticalRequiresFido2,
  });
}

class AdaptivePosture {
  static const int _failureThreshold = 2;

  // v5 E16: unknown-network escalation exists ONLY inside opt-in strict roaming
  // mode (off by default). Laptops roam; permanent high posture trains users
  // to disable security.
  static PosturePolicy evaluate({
    required bool canaryTriggered,
    required bool networkRecognized,
    required int recentFailures,
    bool strictRoamingEnabled = false,
  }) {
    if (canaryTriggered) {
      return PosturePolicy(
        level: PostureLevel.lockdown,
        autoLockTimeout: Duration.zero,
        biometricFastPath: false,
        autofillRequiresFreshMp: true,
        criticalRequiresFido2: true,
      );
    }

    // Failures ALWAYS escalate (independent of network).
    if (recentFailures >= _failureThreshold) {
      return PosturePolicy(
        level: PostureLevel.high,
        autoLockTimeout: const Duration(seconds: 30),
        biometricFastPath: false,
        autofillRequiresFreshMp: false,
        criticalRequiresFido2: false,
      );
    }

    // Unknown network escalates ONLY when strict roaming is armed.
    if (!networkRecognized && strictRoamingEnabled) {
      return PosturePolicy(
        level: PostureLevel.high,
        autoLockTimeout: const Duration(seconds: 30),
        biometricFastPath: false,
        autofillRequiresFreshMp: false,
        criticalRequiresFido2: false,
      );
    }

    // Known network (or unknown + no roaming) + no failures -> low.
    return PosturePolicy(
      level: PostureLevel.low,
      autoLockTimeout: const Duration(minutes: 5),
      biometricFastPath: true,
      autofillRequiresFreshMp: false,
      criticalRequiresFido2: false,
    );
  }
}