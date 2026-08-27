// File: test/security/android/test_autofill.dart
// Intent: security.md gate 7.1 — Autofill service security verification.
// Invariants:
// - Lookalike detection: homoglyph check (0/o, 1/l/i, 5/s).
// - Lookalike detection: edit distance <= 1.
// - Lookalike detection: subdomain impersonation (microsoft.com.evil.io).
// - Critical tier entries NEVER autofill (hard stop).
// - Sensitive tier entries require re-authentication.
// - Standard tier entries autofill immediately.
// - Domain mismatch ALWAYS blocks autofill (phishing protection).
// Dependencies: tier_autofill_enforcer.dart, security_tier.dart,
//   lookalike_domain.dart.

import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/autofill/tier_autofill_enforcer.dart';
import 'package:vault_crypto/src/security/lookalike_domain.dart';
import 'package:vault_crypto/src/security/security_tier.dart';

void main() {
  group('Gate 7.1 Autofill Security', () {
    test('critical tier entries NEVER autofill (hard stop)', () {
      final req = AutofillRequest(
        entryDomain: 'bank.com',
        requestedDomain: 'bank.com',
        tier: SecurityTier.critical,
      );
      final decision = TierAutofillEnforcer.decide(req);
      expect(decision, isA<BlockManualOnly>());
      expect(decision.mayReleaseCredential, isFalse);
    });

    test('sensitive tier entries require re-authentication', () {
      final req = AutofillRequest(
        entryDomain: 'email.com',
        requestedDomain: 'email.com',
        tier: SecurityTier.sensitive,
      );
      final decision = TierAutofillEnforcer.decide(req);
      expect(decision, isA<FillAfterReauth>());
    });

    test('standard tier entries autofill immediately', () {
      final req = AutofillRequest(
        entryDomain: 'news.com',
        requestedDomain: 'news.com',
        tier: SecurityTier.standard,
      );
      final decision = TierAutofillEnforcer.decide(req);
      expect(decision, isA<FillImmediately>());
      expect(decision.mayReleaseCredential, isTrue);
    });

    test('domain mismatch ALWAYS blocks autofill (phishing protection)', () {
      final req = AutofillRequest(
        entryDomain: 'bank.com',
        requestedDomain: 'evil.com',
        tier: SecurityTier.standard,
      );
      final decision = TierAutofillEnforcer.decide(req);
      expect(decision, isA<BlockDomainMismatch>());
      expect(decision.mayReleaseCredential, isFalse);
    });

    test('lookalike detection: homoglyph (0/o) -> hard stop', () {
      final r = LookalikeDomain.detect(
        targetDomain: 'g00gle.com',
        savedDomains: ['google.com'],
      );
      expect(r, isNotNull);
    });

    test('lookalike detection: edit distance <= 1 -> hard stop', () {
      final r = LookalikeDomain.detect(
        targetDomain: 'paypa1.com',
        savedDomains: ['paypal.com'],
      );
      expect(r, isNotNull);
      expect(r!.distance, lessThanOrEqualTo(1));
    });

    test('lookalike detection: subdomain impersonation', () {
      // microsoft.com.evil.io is a different registrable domain, but the
      // enforcer must not autofill on a mismatched domain.
      final req = AutofillRequest(
        entryDomain: 'microsoft.com',
        requestedDomain: 'microsoft.com.evil.io',
        tier: SecurityTier.standard,
      );
      final decision = TierAutofillEnforcer.decide(req);
      expect(decision.mayReleaseCredential, isFalse);
    });

    test('exact match -> no lookalike warning', () {
      final r = LookalikeDomain.detect(
        targetDomain: 'google.com',
        savedDomains: ['google.com'],
      );
      expect(r, isNull);
    });
  });
}
