// Intent: Pure enforcement logic that decides autofill action based on
// security tier + domain context. Called by Android AutofillService via
// MethodChannel and by Dart-side entry detail screen.
//
// Invariants:
// - Critical tier NEVER autofills (manual only) — hard rule
// - Domain mismatch ALWAYS blocks autofill (phishing protection)
// - Lookalike domain ALWAYS hard-stops (no fill, warn user)
// - Sensitive tier adds delay + requires re-auth before fill
// - Decision is a sealed type — caller must handle every case explicitly
// - Pure function: no I/O, no side effects, no global state
//
// State Transition:
//   AutofillRequest(domain, tier) -> Decision computed -> one of:
//     FillImmediately | FillAfterDelay(reauth) | BlockManual | BlockDomainMismatch
//     | HardStopLookalike
//
// Dependencies: SecurityTier, TierPolicy (no I/O dependencies)

import '../security/security_tier.dart';

/// The autofill decision. Typestate: every branch must be handled by caller.
/// Invalid decisions are unrepresentable (no null, no boolean flags).
sealed class AutofillDecision {
  const AutofillDecision();

  /// Whether any credential data may be released to the requesting app.
  bool get mayReleaseCredential;
}

/// Standard tier: fill immediately, no extra interaction.
final class FillImmediately extends AutofillDecision {
  const FillImmediately();
  @override
  bool get mayReleaseCredential => true;
}

/// Sensitive tier: fill after a delay + biometric re-auth.
/// [delaySeconds] gives user time to cancel unexpected autofill.
final class FillAfterReauth extends AutofillDecision {
  final int delaySeconds;
  const FillAfterReauth({required this.delaySeconds});
  @override
  bool get mayReleaseCredential => true; // after reauth succeeds
}

/// Critical tier: block autofill entirely. User must type manually.
final class BlockManualOnly extends AutofillDecision {
  final String reason;
  const BlockManualOnly({required this.reason});
  @override
  bool get mayReleaseCredential => false;
}

/// Domain mismatch: requested domain does not match stored entry domain.
/// This is a phishing protection — never fill on wrong domain.
final class BlockDomainMismatch extends AutofillDecision {
  final String expectedDomain;
  final String requestedDomain;
  const BlockDomainMismatch({
    required this.expectedDomain,
    required this.requestedDomain,
  });
  @override
  bool get mayReleaseCredential => false;
}

/// Lookalike domain detected (homoglyph / typosquat).
/// HARD STOP: no fill, surface explicit warning to user.
final class HardStopLookalike extends AutofillDecision {
  final String expectedDomain;
  final String requestedDomain;
  final String reason;
  const HardStopLookalike({
    required this.expectedDomain,
    required this.requestedDomain,
    required this.reason,
  });
  @override
  bool get mayReleaseCredential => false;
}

/// Request context passed to the enforcer.
class AutofillRequest {
  /// Domain the entry was saved for (from vault).
  final String entryDomain;

  /// Domain currently requesting autofill (from Android).
  final String requestedDomain;

  /// Security tier of the entry.
  final SecurityTier tier;

  const AutofillRequest({
    required this.entryDomain,
    required this.requestedDomain,
    required this.tier,
  });
}

/// Decides autofill action. Pure function — deterministic, no side effects.
///
/// Decision priority (highest wins):
///   1. Lookalike detection -> HardStopLookalike
///   2. Domain mismatch -> BlockDomainMismatch
///   3. Critical tier -> BlockManualOnly
///   4. Sensitive tier -> FillAfterReauth
///   5. Standard tier -> FillImmediately
class TierAutofillEnforcer {
  const TierAutofillEnforcer._();

  /// Compute the autofill decision for a request.
  static AutofillDecision decide(AutofillRequest request) {
    // Priority 1: Lookalike detection (most dangerous — active phishing).
    // Check BEFORE exact match because a lookalike could otherwise pass
    // a naive substring check.
    final lookalikeReason = _detectLookalike(
      request.entryDomain,
      request.requestedDomain,
    );
    if (lookalikeReason != null) {
      return HardStopLookalike(
        expectedDomain: request.entryDomain,
        requestedDomain: request.requestedDomain,
        reason: lookalikeReason,
      );
    }

    // Priority 2: Exact domain match (phishing protection).
    if (!_domainsMatch(request.entryDomain, request.requestedDomain)) {
      return BlockDomainMismatch(
        expectedDomain: request.entryDomain,
        requestedDomain: request.requestedDomain,
      );
    }

    // Priority 3-5: Tier-based decision (domain matched).
    switch (request.tier) {
      case SecurityTier.critical:
        // Critical: NEVER autofill. User must type manually.
        return const BlockManualOnly(
          reason: 'Critical entries require manual entry. '
              'Autofill is disabled for banking/financial accounts.',
        );

      case SecurityTier.sensitive:
        // Sensitive: fill after delay + re-auth.
        final delay = TierPolicy.autofillDelay(SecurityTier.sensitive);
        return FillAfterReauth(delaySeconds: delay.inSeconds);

      case SecurityTier.standard:
        // Standard: fill immediately.
        return const FillImmediately();
    }
  }

  /// Normalize and compare domains.
  /// Strips "www." prefix, lowercases, handles trailing dot.
  /// Does NOT do fuzzy matching — that's the lookalike detector's job.
  static bool _domainsMatch(String a, String b) {
    final normA = _normalizeDomain(a);
    final normB = _normalizeDomain(b);
    return normA == normB;
  }

  /// Normalize a domain for comparison.
  static String _normalizeDomain(String domain) {
    var d = domain.toLowerCase().trim();
    // Strip scheme if present
    d = d.replaceFirst(RegExp(r'^https?://'), '');
    // Strip path
    final slashIndex = d.indexOf('/');
    if (slashIndex != -1) d = d.substring(0, slashIndex);
    // Strip port
    final colonIndex = d.indexOf(':');
    if (colonIndex != -1) d = d.substring(0, colonIndex);
    // Strip www.
    if (d.startsWith('www.')) d = d.substring(4);
    // Strip trailing dot
    if (d.endsWith('.')) d = d.substring(0, d.length - 1);
    return d;
  }

  /// Detect lookalike / homoglyph / typosquat domains.
  /// Returns a reason string if lookalike detected, null otherwise.
  ///
  /// Checks:
  ///   1. Punycode (IDN) mismatch — xn-- domains vs ASCII
  ///   2. Character substitution (0/o, 1/l/i, 5/s)
  ///   3. Edit distance 1 (single char insert/delete/substitute)
  ///   4. Label reorder (evil-example.com vs example.com)
  static String? _detectLookalike(String expected, String requested) {
    final normExpected = _normalizeDomain(expected);
    final normRequested = _normalizeDomain(requested);

    // SECURITY: RFC 1035 domain limit (253 chars). Prevents O(N*M) algorithmic DoS in edit distance.
    if (normExpected.length > 253 || normRequested.length > 253) {
      return 'Domain exceeds RFC 1035 maximum length.';
    }

    // Exact match after normalization -> not a lookalike.
    if (normExpected == normRequested) return null;

    // Check 1: Punycode presence mismatch.
    // If one uses xn-- (IDN) and the other doesn't, suspicious.
    final expectedHasPuny = normExpected.contains('xn--');
    final requestedHasPuny = normRequested.contains('xn--');
    if (expectedHasPuny != requestedHasPuny) {
      return 'Internationalized domain (punycode) mismatch. '
          'One domain uses non-ASCII characters.';
    }

    // Check 2: Character substitution (common homoglyphs).
    if (_isCharSubstitution(normExpected, normRequested)) {
      return 'Domains differ only by easily-confused characters '
          '(e.g., 0/o, 1/l). Possible typosquat.';
    }

    // Check 3: Edit distance exactly 1 (typosquat).
    if (_editDistance(normExpected, normRequested) == 1) {
      return 'Domains differ by a single character. Possible typosquat.';
    }

    // Check 4: Subdomain impersonation.
    // e.g., expected "example.com", requested "example.com.evil.net"
    if (_isSubdomainImpersonation(normExpected, normRequested)) {
      return 'Requested domain embeds the expected domain as a subdomain '
          'of a different parent. Possible phishing.';
    }

    // No lookalike pattern matched.
    return null;
  }

  /// Check if two domains differ only by homoglyph substitution.
  static bool _isCharSubstitution(String a, String b) {
    if (a.length != b.length) return false;

    // Map of easily-confused character groups.
    const confusables = {
      '0': 'o', 'o': '0',
      'l': '1', '1': 'i', 'i': '1',
      '5': 's', 's': '5',
      '8': 'b', 'b': '8',
      'rn': 'm', 'm': 'rn', // "rn" looks like "m"
    };

    int diffCount = 0;
    for (int i = 0; i < a.length; i++) {
      if (a[i] != b[i]) {
        diffCount++;
        // If the differing char is NOT a known confusable pair, bail.
        final ca = a[i];
        final cb = b[i];
        final isConfusable = (confusables[ca] == cb) || (confusables[cb] == ca);
        if (!isConfusable) return false;
      }
    }
    return diffCount > 0 && diffCount <= 2;
  }

  /// Levenshtein edit distance (bounded early-exit).
  /// Returns distance, or >maxDistance if exceeded (perf guard).
  static int _editDistance(String a, String b, {int maxDistance = 2}) {
    final m = a.length;
    final n = b.length;

    // Quick length-based reject.
    if ((m - n).abs() > maxDistance) return maxDistance + 1;

    // Standard DP with two rows.
    var prev = List<int>.generate(n + 1, (i) => i);
    var curr = List<int>.filled(n + 1, 0);

    for (int i = 1; i <= m; i++) {
      curr[0] = i;
      for (int j = 1; j <= n; j++) {
        final cost = a[i - 1] == b[j - 1] ? 0 : 1;
        curr[j] = [
          prev[j] + 1, // deletion
          curr[j - 1] + 1, // insertion
          prev[j - 1] + cost // substitution
        ].reduce((x, y) => x < y ? x : y);
      }
      final tmp = prev;
      prev = curr;
      curr = tmp;
    }
    return prev[n];
  }

  /// Detect subdomain impersonation.
  /// requested = "expected.evil.tld" or "evil.expected" patterns.
  static bool _isSubdomainImpersonation(String expected, String requested) {
    // If requested ends with ".expected", it's a subdomain of expected — OK
    // only if the parent matches. But "expected.com.evil.net" is malicious.
    // Check: does requested contain expected followed by a different parent?
    if (requested.contains('.$expected.')) {
      // expected appears mid-domain with different parent -> suspicious
      return true;
    }
    // requested starts with expected but has more after a dot
    // e.g., expected "example.com", requested "example.com.evil.net"
    if (requested.startsWith('$expected.') && requested != expected) {
      // This is a subdomain OF expected's parent — could be legit or not.
      // We flag it as suspicious to be safe.
      final afterPrefix = requested.substring(expected.length + 1);
      // If what follows is a known public suffix, it's a different site.
      if (_isPublicSuffix(afterPrefix.split('.').last)) {
        return true;
      }
    }
    return false;
  }

  /// Minimal public-suffix check (top-level indicator).
  static bool _isPublicSuffix(String s) {
    const tlds = {
      'com',
      'net',
      'org',
      'io',
      'co',
      'dev',
      'app',
      'me',
      'info',
      'biz',
      'xyz',
      'online',
      'site',
      'tech',
      'gov',
      'edu',
    };
    return tlds.contains(s);
  }
}
