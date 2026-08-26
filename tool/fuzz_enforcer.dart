// File: tool/fuzz_enforcer.dart
// Intent: Fuzz TierAutofillEnforcer for algorithmic DoS and ReDoS.
import 'dart:math';
import 'package:vault_crypto/src/autofill/tier_autofill_enforcer.dart';
import 'package:vault_crypto/src/security/security_tier.dart';

void main() {
  final random = Random.secure();
  const iterations = 50000;
  var crashes = 0;

  print('Fuzzing TierAutofillEnforcer ($iterations iterations)...');
  for (var i = 0; i < iterations; i++) {
    // Generate massive strings to test O(N*M) guard
    final lenA = random.nextInt(300); // Some exceed 253
    final lenB = random.nextInt(300);
    final domainA = List.generate(lenA, (_) => String.fromCharCode(random.nextInt(128))).join();
    final domainB = List.generate(lenB, (_) => String.fromCharCode(random.nextInt(128))).join();

    final req = AutofillRequest(
      entryDomain: domainA,
      requestedDomain: domainB,
      tier: SecurityTier.values[random.nextInt(3)],
    );

    final stopwatch = Stopwatch()..start();
    try {
      TierAutofillEnforcer.decide(req);
    } catch (e) {
      print('CRASH: $e');
      crashes++;
    }
    stopwatch.stop();

    if (stopwatch.elapsedMilliseconds > 100) {
      print('TIMEOUT: DoS detected on lenA=$lenA, lenB=$lenB');
      crashes++;
    }
  }

  if (crashes > 0) {
    print('FAILED: $crashes issues found.');
  } else {
    print('PASSED: 0 crashes, 0 timeouts.');
  }
}
