// Intent: Per-entry risk tiers (v3 §14 / v4 §3 preserved). Standard / Sensitive
// / Critical with distinct reveal policies. Pure logic, no I/O.
//   Standard:  normal access
//   Sensitive: short reveal grace period (re-auth after it expires)
//   Critical:  fresh MP re-auth required every time
// Also: default-tier heuristic (bank/pay/crypto/registrar domains -> Sensitive+).
// Invariants: Critical always requires fresh re-auth; tier is an int in {0,1,2}.
// Dependencies: none (pure).

class RiskTiers {
  static const int standard = 0;
  static const int sensitive = 1;
  static const int critical = 2;

  // Sensitive grace period (short reap as defined in v3 §14).
  static const Duration sensitiveGrace = Duration(minutes: 2);

  // Returns true if the tier requires a fresh re-authentication before reveal,
  // given the tier and whether a reveal has happened within the grace window.
  static bool requiresReauth(int tier, {DateTime? lastReveal, DateTime? now}) {
    switch (tier) {
      case standard:
        return false; // normal access, no re-auth
      case sensitive:
        // Re-auth only if grace expired or never revealed.
        if (lastReveal == null) return true;
        return (now ?? DateTime.now()).difference(lastReveal) > sensitiveGrace;
      case critical:
        return true; // fresh MP every time
      default:
        return true; // unknown tier -> treat as critical (fail-closed)
    }
  }

  // Default-tier heuristic: suggest Sensitive+ for banking/payment/crypto/
  // registrar-style domains. Always a suggestion; user overridable.
  static int suggestTier(String domain) {
    final d = domain.toLowerCase();
    final sensitiveDomains = [
      'bank', 'pay', 'wallet', 'capital', 'credit', 'invest',
      'crypto', 'exchange', 'coin', 'registrar', 'dns', 'finance',
    ];
    for (final kw in sensitiveDomains) {
      if (d.contains(kw)) return sensitive;
    }
    return standard;
  }
}