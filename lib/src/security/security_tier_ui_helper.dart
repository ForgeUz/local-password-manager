// Intent: UI helper for security tier display and interaction.
// Provides color coding, icons, labels, and confirmation dialogs.
// Pure logic — no Flutter imports (platform-agnostic).
//
// Invariants:
// - Color/icon/label mappings are exhaustive (every tier covered)
// - Downgrade confirmations always show explicit warning text
// - Critical tier operations always show "master password required" notice
//
// Dependencies: SecurityTier enum

import 'security_tier.dart';

/// UI metadata for security tiers.
/// Used by Flutter widgets to render tier indicators.
class TierUiInfo {
  /// Display label (localized key).
  final String labelKey;

  /// Color hex value (Material 3 color token).
  final String colorHex;

  /// Icon name (Material Icons).
  final String iconName;

  /// Short description for tooltip.
  final String descriptionKey;

  const TierUiInfo({
    required this.labelKey,
    required this.colorHex,
    required this.iconName,
    required this.descriptionKey,
  });
}

/// Maps SecurityTier to UI metadata.
class TierUiHelper {
  const TierUiHelper._();

  /// Get UI info for a tier.
  static TierUiInfo getUiInfo(SecurityTier tier) {
    switch (tier) {
      case SecurityTier.standard:
        return const TierUiInfo(
          labelKey: 'tier.standard.label',
          colorHex: '#4CAF50', // Green
          iconName: 'shield',
          descriptionKey: 'tier.standard.description',
        );
      case SecurityTier.sensitive:
        return const TierUiInfo(
          labelKey: 'tier.sensitive.label',
          colorHex: '#FF9800', // Orange
          iconName: 'shield_with_lock',
          descriptionKey: 'tier.sensitive.description',
        );
      case SecurityTier.critical:
        return const TierUiInfo(
          labelKey: 'tier.critical.label',
          colorHex: '#F44336', // Red
          iconName: 'shield_alert',
          descriptionKey: 'tier.critical.description',
        );
    }
  }

  /// Get confirmation message for tier downgrade.
  /// Returns null if no confirmation needed (upgrade).
  static String? getDowngradeMessage(SecurityTier from, SecurityTier to) {
    if (to.index >= from.index) return null; // Upgrade, no confirmation

    switch (from) {
      case SecurityTier.critical:
        return 'You are downgrading from CRITICAL to ${to.name.toUpperCase()}. '
            'This entry will no longer require master password for access. '
            'Banking and financial entries should remain critical. '
            'Are you sure?';
      case SecurityTier.sensitive:
        return 'You are downgrading from SENSITIVE to STANDARD. '
            'The 5-second delay and re-auth prompt will be removed. '
            'Are you sure?';
      case SecurityTier.standard:
        return null; // Cannot downgrade below standard
    }
  }

  /// Get description of what actions require for this tier.
  /// Displayed in tier selection UI.
  static List<String> getActionDescriptions(SecurityTier tier) {
    switch (tier) {
      case SecurityTier.standard:
        return [
          'Autofill: Immediate',
          'Reveal password: Single tap',
          'Edit: Biometric',
          'Export: Allowed',
        ];
      case SecurityTier.sensitive:
        return [
          'Autofill: 5-second delay + re-auth',
          'Reveal password: Biometric re-auth',
          'Edit: Biometric re-auth',
          'Export: Allowed',
        ];
      case SecurityTier.critical:
        return [
          'Autofill: MANUAL ONLY',
          'Reveal password: Master password + biometric',
          'Edit: Master password',
          'Export: BLOCKED',
        ];
    }
  }

  /// Suggested tier based on domain (advisory only, user decides).
  /// User's answer: "user chooses manually" — this is just a suggestion.
  static SecurityTier? suggestTierForDomain(String domain) {
    final lower = domain.toLowerCase();

    // Banking / financial
    final bankingPatterns = [
      'bank', 'chase', 'wellsfargo', 'citi', 'hsbc', 'barclays',
      'paypal', 'venmo', 'coinbase', 'binance', 'kraken',
      'stripe', 'square', 'revolut', 'wise',
    ];
    if (bankingPatterns.any((p) => lower.contains(p))) {
      return SecurityTier.critical;
    }

    // Email (primary accounts)
    final emailPatterns = ['gmail', 'outlook', 'protonmail', 'yahoo', 'mail'];
    if (emailPatterns.any((p) => lower.contains(p))) {
      return SecurityTier.sensitive;
    }

    // Government
    final govPatterns = ['.gov', '.gov.', 'irs', 'ssa', 'passport'];
    if (govPatterns.any((p) => lower.contains(p))) {
      return SecurityTier.critical;
    }

    // Crypto exchanges
    final cryptoPatterns = ['coinbase', 'binance', 'kraken', 'gemini', 'bitstamp'];
    if (cryptoPatterns.any((p) => lower.contains(p))) {
      return SecurityTier.critical;
    }

    // Default: no suggestion (user decides)
    return null;
  }
}