import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/security/risk_tiers.dart';

// Intent: Verify risk-tier policies (v3 §14 / Phase I.1).
// Invariants: Critical always requires re-auth; Sensitive has a grace period;
// Standard never requires; heuristic suggests Sensitive for bank/pay/crypto.
void main() {
  group('RiskTiers', () {
    test('Critical always requires re-auth (even with recent reveal)', () {
      expect(
        RiskTiers.requiresReauth(RiskTiers.critical, lastReveal: DateTime.now()),
        isTrue,
      );
    });

    test('Standard never requires re-auth', () {
      expect(RiskTiers.requiresReauth(RiskTiers.standard), isFalse);
    });

    test('Sensitive requires re-auth on first access, then has grace', () {
      // First access: no lastReveal -> requires re-auth.
      expect(RiskTiers.requiresReauth(RiskTiers.sensitive), isTrue);
      // Within grace: no re-auth.
      expect(
        RiskTiers.requiresReauth(RiskTiers.sensitive, lastReveal: DateTime.now()),
        isFalse,
      );
      // After grace: requires re-auth.
      expect(
        RiskTiers.requiresReauth(
          RiskTiers.sensitive,
          lastReveal: DateTime.now().subtract(const Duration(minutes: 3)),
        ),
        isTrue,
      );
    });

    test('heuristic suggests Sensitive for bank/pay/crypto domains', () {
      expect(RiskTiers.suggestTier('online-banking.example'), RiskTiers.sensitive);
      expect(RiskTiers.suggestTier('paypal.com'), RiskTiers.sensitive);
      expect(RiskTiers.suggestTier('cryptoexchange.io'), RiskTiers.sensitive);
      expect(RiskTiers.suggestTier('news.example.com'), RiskTiers.standard);
    });
  });
}