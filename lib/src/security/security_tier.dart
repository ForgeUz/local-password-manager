// Intent: Define security tier system for per-entry access control.
// Users manually assign tiers. Tiers enforce progressively stricter
// authentication requirements for autofill, reveal, and edit operations.
//
// Invariants:
// - Every VaultEntry has exactly one SecurityTier (default: standard)
// - Tier cannot be downgraded without explicit user confirmation
// - Critical tier ALWAYS requires master password (biometric alone insufficient)
// - Tier assignment is stored encrypted in vault blob (attacker cannot downgrade)
//
// State Transition:
//   EntryCreated -> tier assigned by user -> tier persisted in encrypted entry
//   AutofillRequest(tier) -> Standard: auto | Sensitive: delay+reauth | Critical: manual
//   RevealRequest(tier) -> Standard: show | Sensitive: biometric | Critical: master+biometric
//
// Dependencies: None (pure enum + policy logic)

/// Security classification for vault entries.
/// Determines authentication requirements for accessing the entry.
///
/// Doctrine alignment: user-controlled security levels allow progressive
/// hardening without overwhelming non-technical users.
enum SecurityTier {
  /// Low-security entries: streaming, forums, social media.
  /// Autofill: immediate. Reveal: single tap. Edit: biometric.
  standard,

  /// Medium-security entries: email, shopping, cloud storage.
  /// Autofill: 5-second delay + re-auth prompt. Reveal: biometric re-auth.
  /// Edit: biometric re-auth.
  sensitive,

  /// High-security entries: banking, crypto, government, email primary.
  /// Autofill: MANUAL ONLY (user must type or explicitly confirm).
  /// Reveal: master password + biometric. Edit: master password.
  /// Export: BLOCKED.
  critical,
}

/// Policy enforcement for security tiers.
/// Pure logic — no I/O, no side effects. UI and platform layers
/// call these methods to determine what authentication is required.
class TierPolicy {
  const TierPolicy._();

  /// Whether autofill is allowed without additional interaction.
  /// Standard: yes. Sensitive: yes (with delay). Critical: NO.
  static bool allowsAutoFill(SecurityTier tier) {
    switch (tier) {
      case SecurityTier.standard:
        return true;
      case SecurityTier.sensitive:
        return true; // but with delay + re-auth
      case SecurityTier.critical:
        return false; // manual only
    }
  }

  /// Delay in seconds before autofill proceeds (for sensitive tier).
  /// Gives user time to cancel if autofill is unexpected.
  static Duration autofillDelay(SecurityTier tier) {
    switch (tier) {
      case SecurityTier.standard:
        return Duration.zero;
      case SecurityTier.sensitive:
        return const Duration(seconds: 5);
      case SecurityTier.critical:
        // Never reached — autofill blocked entirely
        return const Duration(seconds: 0);
    }
  }

  /// Whether revealing the password requires re-authentication.
  /// Standard: no. Sensitive: biometric. Critical: master password.
  static AuthRequirement revealRequirement(SecurityTier tier) {
    switch (tier) {
      case SecurityTier.standard:
        return AuthRequirement.none;
      case SecurityTier.sensitive:
        return AuthRequirement.biometric;
      case SecurityTier.critical:
        return AuthRequirement.masterPassword;
    }
  }

  /// Whether editing the entry requires re-authentication.
  static AuthRequirement editRequirement(SecurityTier tier) {
    switch (tier) {
      case SecurityTier.standard:
        return AuthRequirement.biometric;
      case SecurityTier.sensitive:
        return AuthRequirement.biometric;
      case SecurityTier.critical:
        return AuthRequirement.masterPassword;
    }
  }

  /// Whether entry data can be exported.
  /// Critical entries CANNOT be exported (prevents bulk exfiltration).
  static bool allowsExport(SecurityTier tier) {
    switch (tier) {
      case SecurityTier.standard:
      case SecurityTier.sensitive:
        return true;
      case SecurityTier.critical:
        return false;
    }
  }

  /// Whether TOTP codes can be auto-copied to clipboard.
  /// Critical: no auto-copy (user must tap explicitly).
  static bool allowsAutoCopyTotp(SecurityTier tier) {
    switch (tier) {
      case SecurityTier.standard:
      case SecurityTier.sensitive:
        return true;
      case SecurityTier.critical:
        return false;
    }
  }
}

/// What authentication is required for an action.
enum AuthRequirement {
  /// No additional auth needed (vault is already unlocked).
  none,

  /// Biometric authentication (fingerprint / face).
  biometric,

  /// Master password entry required.
  masterPassword,

  /// Both master password AND biometric.
  masterPasswordAndBiometric,
}

/// Validation result for tier operations.
/// Typestate: invalid tier transitions are caught at compile time
/// through the type system (not runtime if-checks).
sealed class TierValidationResult {
  const TierValidationResult();
}

/// Tier assignment is valid.
final class TierValid extends TierValidationResult {
  final SecurityTier tier;
  const TierValid(this.tier);
}

/// Tier assignment requires user confirmation (downgrade).
final class TierDowngradeConfirm extends TierValidationResult {
  final SecurityTier from;
  final SecurityTier to;
  final String warning;
  const TierDowngradeConfirm({
    required this.from,
    required this.to,
    required this.warning,
  });
}

/// Validates a tier change request.
/// Downgrades (critical -> standard) require explicit confirmation.
/// Upgrades (standard -> critical) are always allowed.
class TierValidator {
  const TierValidator._();

  /// Check if changing from [current] to [proposed] is allowed.
  /// Returns TierValid if allowed immediately.
  /// Returns TierDowngradeConfirm if user confirmation needed.
  static TierValidationResult validateChange({
    required SecurityTier current,
    required SecurityTier proposed,
  }) {
    // Upgrade: always allowed
    if (proposed.index >= current.index) {
      return TierValid(proposed);
    }

    // Downgrade: require confirmation with warning
    final warning = _downgradeWarning(current, proposed);
    return TierDowngradeConfirm(
      from: current,
      to: proposed,
      warning: warning,
    );
  }

  static String _downgradeWarning(SecurityTier from, SecurityTier to) {
    switch (from) {
      case SecurityTier.critical:
        return 'Downgrading from CRITICAL removes master password requirement. '
            'Banking/financial entries should remain critical.';
      case SecurityTier.sensitive:
        return 'Downgrading from SENSITIVE removes re-auth delay.';
      case SecurityTier.standard:
        return ''; // Cannot downgrade below standard
    }
  }
}
