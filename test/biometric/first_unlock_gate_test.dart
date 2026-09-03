import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/biometric/first_unlock_gate.dart';

// Intent: v5 E20 — optional "require MP on first unlock of the day" so the
// duress path (which requires typing) stays reachable despite the biometric
// fast path. Biometric cannot signal duress — documented honestly.
void main() {
  group('v5 E20 first-unlock-of-day gate', () {
    test(
        'armed: first unlock of the day forces MP, later unlocks allow biometric',
        () {
      final gate = FirstUnlockGate(requireMpOnFirstUnlock: true);
      // First unlock today -> MP required (biometric denied).
      expect(gate.requiresMp('20260823'), isTrue);
      // User types the MP (duress path stays reachable). Record the unlock.
      gate.recordUnlock('20260823');
      // Subsequent unlocks today -> biometric allowed.
      expect(gate.requiresMp('20260823'), isFalse);
      // Next day -> MP required again.
      expect(gate.requiresMp('20260824'), isTrue);
    });

    test('not armed: biometric always allowed', () {
      final gate = FirstUnlockGate(requireMpOnFirstUnlock: false);
      expect(gate.requiresMp('20260823'), isFalse);
      gate.recordUnlock('20260823');
      expect(gate.requiresMp('20260823'), isFalse);
    });
  });
}
