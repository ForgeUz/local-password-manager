// File: test/security/tier_autofill_enforcer_test.dart
// Intent: Kill-tests for TierAutofillEnforcer (M101-M108).
// Invariants:
// - Critical NEVER autofills.
// - Lookalike -> HardStopLookalike.
// - Domain mismatch -> BlockDomainMismatch.
// - Sensitive -> FillAfterReauth with 5s delay.
// Dependencies: tier_autofill_enforcer.dart, security_tier.dart.

import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/autofill/tier_autofill_enforcer.dart';
import 'package:vault_crypto/src/security/security_tier.dart';

void main() {
  group('M101: critical tier NEVER autofills', () {
    test('critical + exact domain match -> BlockManualOnly', () {
      final req = AutofillRequest(
        entryDomain: 'bank.com',
        requestedDomain: 'bank.com',
        tier: SecurityTier.critical,
      );
      final decision = TierAutofillEnforcer.decide(req);
      expect(decision, isA<BlockManualOnly>());
      expect(decision.mayReleaseCredential, isFalse);
    });

    test('critical + www normalization -> still BlockManualOnly', () {
      final req = AutofillRequest(
        entryDomain: 'bank.com',
        requestedDomain: 'www.bank.com',
        tier: SecurityTier.critical,
      );
      final decision = TierAutofillEnforcer.decide(req);
      expect(decision, isA<BlockManualOnly>());
    });
  });

  group('M102: lookalike domain hard-stops', () {
    test('homoglyph g00gle.com vs google.com -> HardStopLookalike', () {
      final req = AutofillRequest(
        entryDomain: 'google.com',
        requestedDomain: 'g00gle.com',
        tier: SecurityTier.standard,
      );
      final decision = TierAutofillEnforcer.decide(req);
      expect(decision, isA<HardStopLookalike>());
      expect(decision.mayReleaseCredential, isFalse);
    });

    test('punycode mismatch -> HardStopLookalike', () {
      final req = AutofillRequest(
        entryDomain: 'example.com',
        requestedDomain: 'xn--e1ample.com',
        tier: SecurityTier.standard,
      );
      final decision = TierAutofillEnforcer.decide(req);
      expect(decision, isA<HardStopLookalike>());
    });
  });

  group('M103: domain mismatch blocks', () {
    test('completely different domains -> BlockDomainMismatch', () {
      final req = AutofillRequest(
        entryDomain: 'github.com',
        requestedDomain: 'gitlab.com',
        tier: SecurityTier.standard,
      );
      final decision = TierAutofillEnforcer.decide(req);
      expect(decision, isA<BlockDomainMismatch>());
      expect(decision.mayReleaseCredential, isFalse);
    });

    test('subdomain of different parent -> BlockDomainMismatch', () {
      final req = AutofillRequest(
        entryDomain: 'example.com',
        requestedDomain: 'evil.com',
        tier: SecurityTier.standard,
      );
      final decision = TierAutofillEnforcer.decide(req);
      expect(decision, isA<BlockDomainMismatch>());
    });
  });

  group('M104: sensitive tier adds delay', () {
    test('sensitive + match -> FillAfterReauth with 5s', () {
      final req = AutofillRequest(
        entryDomain: 'shop.com',
        requestedDomain: 'shop.com',
        tier: SecurityTier.sensitive,
      );
      final decision = TierAutofillEnforcer.decide(req);
      expect(decision, isA<FillAfterReauth>());
      expect((decision as FillAfterReauth).delaySeconds, equals(5));
      expect(decision.mayReleaseCredential, isTrue);
    });
  });

  group('M105: www normalization', () {
    test('www.example.com matches example.com', () {
      final req = AutofillRequest(
        entryDomain: 'example.com',
        requestedDomain: 'www.example.com',
        tier: SecurityTier.standard,
      );
      final decision = TierAutofillEnforcer.decide(req);
      // Must NOT be BlockDomainMismatch -> normalization works.
      expect(decision, isA<FillImmediately>());
    });
  });

  group('M106: edit distance 1 typosquat', () {
    test('githun.com vs github.com -> HardStopLookalike', () {
      final req = AutofillRequest(
        entryDomain: 'github.com',
        requestedDomain: 'githun.com',
        tier: SecurityTier.standard,
      );
      final decision = TierAutofillEnforcer.decide(req);
      expect(decision, isA<HardStopLookalike>());
    });
  });

  group('M107: homoglyph 0/o pair', () {
    test('g0ogle.com vs google.com -> HardStopLookalike', () {
      final req = AutofillRequest(
        entryDomain: 'google.com',
        requestedDomain: 'g0ogle.com',
        tier: SecurityTier.standard,
      );
      final decision = TierAutofillEnforcer.decide(req);
      expect(decision, isA<HardStopLookalike>());
    });
  });

  group('M108: subdomain impersonation', () {
    test('evil.example.com.net (mid-domain) -> HardStopLookalike', () {
      final req = AutofillRequest(
        entryDomain: 'example.com',
        requestedDomain: 'evil.example.com.net',
        tier: SecurityTier.standard,
      );
      final decision = TierAutofillEnforcer.decide(req);
      // Must specifically be HardStopLookalike to kill the mid-domain mutant.
      expect(decision, isA<HardStopLookalike>());
    });
  });

  group('Standard tier happy path', () {
    test('standard + exact match -> FillImmediately', () {
      final req = AutofillRequest(
        entryDomain: 'netflix.com',
        requestedDomain: 'netflix.com',
        tier: SecurityTier.standard,
      );
      final decision = TierAutofillEnforcer.decide(req);
      expect(decision, isA<FillImmediately>());
      expect(decision.mayReleaseCredential, isTrue);
    });
  });
}
