import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/sync/push_approval.dart';

// Intent: v5 H.8 — companion-device push approval. 2-digit challenge, 3
// options, number-matching, rate-limited (excess silently dropped).
void main() {
  group('v5 H.8 push approval', () {
    test('generates a 2-digit challenge with 3 options, one matching', () {
      final c = PushApproval.generate();
      expect(c.challenge, inInclusiveRange(0, 99));
      expect(c.options.length, 3);
      expect(c.options.contains(c.challenge), isTrue);
    });

    test('correct option verifies; wrong option fails', () {
      final c = PushApproval.generate();
      expect(PushApproval.verify(c, c.challenge, attempts: 0), isTrue);
      // A wrong option (not the challenge) fails.
      final wrong = c.options.firstWhere((o) => o != c.challenge);
      expect(PushApproval.verify(c, wrong, attempts: 0), isFalse);
    });

    test('rate-limited after max attempts (silently dropped)', () {
      final c = PushApproval.generate();
      // Even the correct option is dropped once attempts >= max.
      expect(PushApproval.verify(c, c.challenge, attempts: 5), isFalse);
    });
  });
}
