// Intent: Unit + mutation tests for TierPolicy and TierValidator.
// Every operator/branch change must fail a test (mutation kill target).
//
// Invariants tested:
// - Critical tier: autofill ALWAYS blocked, export ALWAYS blocked
// - Sensitive tier: autofill delay exactly 5 seconds
// - Standard tier: no delay, no reauth for reveal
// - Reveal requirement escalates: none -> biometric -> masterPassword
// - Downgrade requires confirmation, upgrade does not
// - Tier ordinal ordering (standard=0 < sensitive=1 < critical=2)
//
// Dependencies: SecurityTier, TierPolicy, TierValidator, AuthRequirement

import 'package:test/test.dart';

import 'package:vault_crypto/src/security/security_tier.dart';

void main() {
  group('TierPolicy.allowsAutoFill', () {
    test('standard allows autofill', () {
      expect(TierPolicy.allowsAutoFill(SecurityTier.standard), isTrue);
    });

    test('sensitive allows autofill (with delay)', () {
      expect(TierPolicy.allowsAutoFill(SecurityTier.sensitive), isTrue);
    });

    // CRITICAL MUTATION KILLER: if someone changes critical to allow
    // autofill, this MUST fail. Banking must never autofill.
    test('critical BLOCKS autofill (never auto)', () {
      expect(TierPolicy.allowsAutoFill(SecurityTier.critical), isFalse);
    });
  });

  group('TierPolicy.autofillDelay', () {
    test('standard has zero delay', () {
      expect(TierPolicy.autofillDelay(SecurityTier.standard),
          equals(Duration.zero));
    });

    // MUTATION KILLER: delay must be exactly 5 seconds.
    // Changing 5 to any other value fails this test.
    test('sensitive has exactly 5 second delay', () {
      expect(TierPolicy.autofillDelay(SecurityTier.sensitive),
          equals(const Duration(seconds: 5)));
    });
  });

  group('TierPolicy.revealRequirement', () {
    test('standard reveal requires no auth', () {
      expect(TierPolicy.revealRequirement(SecurityTier.standard),
          equals(AuthRequirement.none));
    });

    test('sensitive reveal requires biometric', () {
      expect(TierPolicy.revealRequirement(SecurityTier.sensitive),
          equals(AuthRequirement.biometric));
    });

    // CRITICAL MUTATION KILLER: critical reveal must require master password.
    // Downgrading this to biometric-only is a security regression.
    test('critical reveal requires master password', () {
      expect(TierPolicy.revealRequirement(SecurityTier.critical),
          equals(AuthRequirement.masterPassword));
    });
  });

  group('TierPolicy.editRequirement', () {
    test('standard edit requires biometric', () {
      expect(TierPolicy.editRequirement(SecurityTier.standard),
          equals(AuthRequirement.biometric));
    });

    test('sensitive edit requires biometric', () {
      expect(TierPolicy.editRequirement(SecurityTier.sensitive),
          equals(AuthRequirement.biometric));
    });

    test('critical edit requires master password', () {
      expect(TierPolicy.editRequirement(SecurityTier.critical),
          equals(AuthRequirement.masterPassword));
    });
  });

  group('TierPolicy.allowsExport', () {
    test('standard can export', () {
      expect(TierPolicy.allowsExport(SecurityTier.standard), isTrue);
    });

    test('sensitive can export', () {
      expect(TierPolicy.allowsExport(SecurityTier.sensitive), isTrue);
    });

    // CRITICAL MUTATION KILLER: critical export must be blocked.
    // Prevents bulk exfiltration of banking credentials.
    test('critical CANNOT export', () {
      expect(TierPolicy.allowsExport(SecurityTier.critical), isFalse);
    });
  });

  group('TierPolicy.allowsAutoCopyTotp', () {
    test('standard allows auto-copy TOTP', () {
      expect(TierPolicy.allowsAutoCopyTotp(SecurityTier.standard), isTrue);
    });

    test('sensitive allows auto-copy TOTP', () {
      expect(TierPolicy.allowsAutoCopyTotp(SecurityTier.sensitive), isTrue);
    });

    // CRITICAL MUTATION KILLER: critical must not auto-copy TOTP.
    test('critical BLOCKS auto-copy TOTP', () {
      expect(TierPolicy.allowsAutoCopyTotp(SecurityTier.critical), isFalse);
    });
  });

  group('TierValidator.validateChange', () {
    test('upgrade standard -> critical allowed immediately', () {
      final result = TierValidator.validateChange(
        current: SecurityTier.standard,
        proposed: SecurityTier.critical,
      );
      expect(result, isA<TierValid>());
      if (result is TierValid) {
        expect(result.tier, equals(SecurityTier.critical));
      }
    });

    test('upgrade sensitive -> critical allowed immediately', () {
      final result = TierValidator.validateChange(
        current: SecurityTier.sensitive,
        proposed: SecurityTier.critical,
      );
      expect(result, isA<TierValid>());
    });

    test('same tier change is valid (no-op)', () {
      final result = TierValidator.validateChange(
        current: SecurityTier.sensitive,
        proposed: SecurityTier.sensitive,
      );
      expect(result, isA<TierValid>());
    });

    // CRITICAL MUTATION KILLER: downgrade must require confirmation.
    // If someone removes the confirmation, this fails.
    test('downgrade critical -> standard requires confirmation', () {
      final result = TierValidator.validateChange(
        current: SecurityTier.critical,
        proposed: SecurityTier.standard,
      );
      expect(result, isA<TierDowngradeConfirm>());
      if (result is TierDowngradeConfirm) {
        expect(result.from, equals(SecurityTier.critical));
        expect(result.to, equals(SecurityTier.standard));
        expect(result.warning, isNotEmpty);
      }
    });

    test('downgrade critical -> sensitive requires confirmation', () {
      final result = TierValidator.validateChange(
        current: SecurityTier.critical,
        proposed: SecurityTier.sensitive,
      );
      expect(result, isA<TierDowngradeConfirm>());
    });

    test('downgrade sensitive -> standard requires confirmation', () {
      final result = TierValidator.validateChange(
        current: SecurityTier.sensitive,
        proposed: SecurityTier.standard,
      );
      expect(result, isA<TierDowngradeConfirm>());
    });
  });

  group('Tier Ordinal Ordering (Property-Based)', () {
    test('standard < sensitive < critical (index ordering)', () {
      // MUTATION KILLER: if enum order changes, index comparisons break.
      expect(
          SecurityTier.standard.index, lessThan(SecurityTier.sensitive.index));
      expect(
          SecurityTier.sensitive.index, lessThan(SecurityTier.critical.index));
    });

    test('all tiers are covered (exhaustive)', () {
      // Ensure no tier is missing from policy coverage.
      for (final tier in SecurityTier.values) {
        // Each call must not throw (all branches handled).
        TierPolicy.allowsAutoFill(tier);
        TierPolicy.autofillDelay(tier);
        TierPolicy.revealRequirement(tier);
        TierPolicy.editRequirement(tier);
        TierPolicy.allowsExport(tier);
        TierPolicy.allowsAutoCopyTotp(tier);
      }
      // If a new tier is added without updating policy, this loop
      // will hit a missing switch case -> compile/runtime error.
      expect(SecurityTier.values.length, equals(3));
    });
  });
}
