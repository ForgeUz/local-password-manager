import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/security/behavioral_biometrics.dart';

// Intent: v5 E15 — behavioral biometrics in LOG-SPACE (log-normal via Welford),
// per-pair scoring gate (>=8 samples per pair), global 3.5-sigma fallback below
// the gate, three consecutive anomalies -> lock. No fabricated FP figures — the
// FP/FN behavior is measured empirically in testing.
void main() {
  group('v5 E15 behavioral biometrics', () {
    test('log-space model works: normal typing does not lock', () {
      final model = BehavioralModel();
      // Normal typing: tight cluster around ~100us (log-space near-constant).
      for (var i = 0; i < 50; i++) {
        final r = model.observe('a', 'b', 100 + (i % 3));
        expect(r.lockTriggered, isFalse);
      }
      // A few more normal samples — never locks.
      for (var i = 0; i < 20; i++) {
        final r = model.observe('a', 'b', 100 + (i % 3));
        expect(r.lockTriggered, isFalse);
      }
    });

    test('three consecutive anomalies trigger lock (per-pair gate reached)', () {
      final model = BehavioralModel();
      // Train one pair past the per-pair gate (>=8 samples).
      for (var i = 0; i < 12; i++) {
        model.observe('a', 'b', 100 + (i % 3));
      }
      // Three wildly anomalous flight times on the SAME pair -> lock.
      var locked = false;
      for (var i = 0; i < 3; i++) {
        final r = model.observe('a', 'b', 50000);
        if (r.lockTriggered) locked = true;
      }
      expect(locked, isTrue);
    });

    test('per-pair gate falls back to global model when samples < 8', () {
      // Feed samples spread across MANY pairs, none reaching 8 per pair.
      final model = BehavioralModel();
      final keys = ['a', 'b', 'c', 'd', 'e', 'f'];
      for (var i = 0; i < 30; i++) {
        final pk = keys[i % 6];
        final ck = keys[(i + 1) % 6];
        model.observe(pk, ck, 100 + (i % 3));
      }
      // Global model is now trained (30 samples). A wild anomaly on a pair
      // with <8 samples is still flagged via the GLOBAL 3.5-sigma fallback.
      var locked = false;
      for (var i = 0; i < 3; i++) {
        final r = model.observe('a', 'b', 90000);
        if (r.lockTriggered) locked = true;
      }
      expect(locked, isTrue);
    });
  });
}