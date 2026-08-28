// Intent: Look-alike domain detection (v3 §15.2 / Phase I.5). Before autofill,
// check if the target domain is within an edit-distance or homoglyph threshold
// of a DIFFERENT saved entry's domain. If yes -> hard-stop warning. Exact match
// -> no warning. Pure logic.
// Dependencies: none (pure).

class LookalikeDomain {
  // Levenshtein edit distance between two strings.
  static int editDistance(String a, String b) {
    final m = a.length;
    final n = b.length;
    final dp = List.generate(m + 1, (_) => List.filled(n + 1, 0));
    for (var i = 0; i <= m; i++) {
      dp[i][0] = i;
    }
    for (var j = 0; j <= n; j++) {
      dp[0][j] = j;
    }
    for (var i = 1; i <= m; i++) {
      for (var j = 1; j <= n; j++) {
        final cost = a[i - 1] == b[j - 1] ? 0 : 1;
        dp[i][j] = [
          dp[i - 1][j] + 1,
          dp[i][j - 1] + 1,
          dp[i - 1][j - 1] + cost,
        ].reduce((x, y) => x < y ? x : y);
      }
    }
    return dp[m][n];
  }

  // Homoglyph substitution map (common look-alike characters).
  // Canonical homoglyph mapping: both members of a look-alike pair map to the
  // SAME canonical char so normalization converges (0 and o -> 'o', etc.).
  static const Map<String, String> _homoglyphs = {
    '0': 'o',
    'o': 'o',
    '1': 'l',
    'l': 'l',
    'i': 'l',
    '5': 's',
    's': 's',
    'v': 'w',
    'w': 'w',
  };

  // Normalize a domain by collapsing homoglyphs to a canonical form.
  static String _normalizeHomoglyphs(String s) {
    final sb = StringBuffer();
    for (final c in s.toLowerCase().split('')) {
      sb.write(_homoglyphs[c] ?? c);
    }
    return sb.toString();
  }

  // Check if target is a look-alike of any OTHER saved domain. Returns the
  // matched saved domain + distance if within threshold, else null.
  // Exact match (same domain) is excluded -> no warning.
  static ({String savedDomain, int distance})? detect({
    required String targetDomain,
    required List<String> savedDomains,
    int maxEditDistance = 1,
  }) {
    final t = targetDomain.toLowerCase();
    for (final saved in savedDomains) {
      final s = saved.toLowerCase();
      if (s == t) continue; // exact match -> no warning
      final d = editDistance(t, s);
      if (d <= maxEditDistance) return (savedDomain: saved, distance: d);
      // Homoglyph-normalized comparison.
      if (_normalizeHomoglyphs(t) == _normalizeHomoglyphs(s)) {
        return (savedDomain: saved, distance: d);
      }
    }
    return null;
  }
}
