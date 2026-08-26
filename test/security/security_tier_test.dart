// File: test/security/security_tier_test.dart
// Intent: Kill-tests for SecurityTier + TierPolicy + TierValidator (M109-M114).
// Invariants:
// - Critical blocks export, requires master password for reveal.
// - Downgrade requires confirmation.
// - Sensitive enforces 5s delay.
// - Standard allows autofill.
// Dependencies: security_tier.dart.

import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/security/security_tier.dart';

void main() {
  group('M109: critical blocks export', () {
    test('allowsExport(critical) -> false', () {
      expect(TierPolicy.allowsExport(SecurityTier.critical), isFalse);
    });

    test('allowsExport(standard) -> true', () {
      expect(TierPolicy.allowsExport(SecurityTier.standard), isTrue);
    });

    test('allowsExport(sensitive) -> true', () {
      expect(TierPolicy.allowsExport(SecurityTier.sensitive), isTrue);
    });
  });

  group('M110: downgrade requires confirmation', () {
    test('critical -> standard -> TierDowngradeConfirm', () {
      final result = TierValidator.validateChange(
        current: SecurityTier.critical,
        proposed: SecurityTier.standard,
      );
      expect(result, isA<TierDowngradeConfirm>());
      expect((result as TierDowngradeConfirm).warning, isNotEmpty);
    });

    test('sensitive -> standard -> TierDowngradeConfirm', () {
      final result = TierValidator.validateChange(
        current: SecurityTier.sensitive,
        proposed: SecurityTier.standard,
      );
      expect(result, isA<TierDowngradeConfirm>());
    });

    test('standard -> critical (upgrade) -> TierValid', () {
      final result = TierValidator.validateChange(
        current: SecurityTier.standard,
        proposed: SecurityTier.critical,
      );
      expect(result, isA<TierValid>());
    });
  });

  group('M111: critical reveal requires master password', () {
    test('revealRequirement(critical) -> masterPassword', () {
      expect(
        TierPolicy.revealRequirement(SecurityTier.critical),
        AuthRequirement.masterPassword,
      );
    });

    test('revealRequirement(sensitive) -> biometric', () {
      expect(
        TierPolicy.revealRequirement(SecurityTier.sensitive),
        AuthRequirement.biometric,
      );
    });

    test('revealRequirement(standard) -> none', () {
      expect(
        TierPolicy.revealRequirement(SecurityTier.standard),
        AuthRequirement.none,
      );
    });
  });

  group('M112: sensitive enforces 5s delay', () {
    test('autofillDelay(sensitive) -> 5 seconds', () {
      final delay = TierPolicy.autofillDelay(SecurityTier.sensitive);
      expect(delay, equals(const Duration(seconds: 5)));
    });

    test('autofillDelay(standard) -> zero', () {
      final delay = TierPolicy.autofillDelay(SecurityTier.standard);
      expect(delay, equals(Duration.zero));
    });
  });

  group('M113: standard allows autofill', () {
    test('allowsAutoFill(standard) -> true', () {
      expect(TierPolicy.allowsAutoFill(SecurityTier.standard), isTrue);
    });

    test('allowsAutoFill(critical) -> false', () {
      expect(TierPolicy.allowsAutoFill(SecurityTier.critical), isFalse);
    });

    test('allowsAutoFill(sensitive) -> true (with delay)', () {
      expect(TierPolicy.allowsAutoFill(SecurityTier.sensitive), isTrue);
    });
  });

  group('M114: critical blocks auto-copy TOTP', () {
    test('allowsAutoCopyTotp(critical) -> false', () {
      expect(TierPolicy.allowsAutoCopyTotp(SecurityTier.critical), isFalse);
    });

    test('allowsAutoCopyTotp(standard) -> true', () {
      expect(TierPolicy.allowsAutoCopyTotp(SecurityTier.standard), isTrue);
    });
  });

  group('editRequirement consistency', () {
    test('critical edit -> masterPassword', () {
      expect(
        TierPolicy.editRequirement(SecurityTier.critical),
        AuthRequirement.masterPassword,
      );
    });

    test('standard edit -> biometric', () {
      expect(
        TierPolicy.editRequirement(SecurityTier.standard),
        AuthRequirement.biometric,
      );
    });
  });
}
