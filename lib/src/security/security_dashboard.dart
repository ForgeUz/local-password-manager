// Intent: Local Security Dashboard (v3 §18.4 / Phase K.1). Detect duplicate
// passwords, weak/short passwords (entropy), and old passwords (by updatedAt).
// Fully local, zero network. Pure logic over entry (title, password, updatedAt).
// Invariants: warnings are category-tagged; works on any entry list.
// Dependencies: none (pure).

import 'dart:math';

class DashboardWarning {
  final String severity; // 'high' | 'medium'
  final String type; // 'duplicate' | 'weak' | 'old'
  final String entryId;
  final String detail;
  const DashboardWarning({
    required this.severity,
    required this.type,
    required this.entryId,
    required this.detail,
  });
}

class SecurityDashboard {
  // Entropy estimate: sum over unique characters of -log2(count/len).
  static double entropy(String password) {
    if (password.isEmpty) return 0;
    final counts = <int, int>{};
    for (final c in password.codeUnits) {
      counts[c] = (counts[c] ?? 0) + 1;
    }
    var e = 0.0;
    for (final n in counts.values) {
      final p = n / password.length;
      e -= p * (log(p) / ln2);
    }
    return e;
  }

  // Run all checks. Returns warnings for each entry (canaries excluded by caller).
  static List<DashboardWarning> analyze({
    required List<({String id, String title, String password, int updatedAt, String domain})> entries,
    int now = 0,
    int staleDays = 180,
  }) {
    final warnings = <DashboardWarning>[];
    final byPassword = <String, List<String>>{};
    for (final e in entries) {
      byPassword.putIfAbsent(e.password, () => []).add(e.id);
    }

    for (final e in entries) {
      // Duplicate: password reused across >1 entry.
      final pwList = byPassword[e.password] ?? const [];
      if (pwList.length > 1 && pwList.first == e.id) {
        warnings.add(DashboardWarning(
          severity: 'high',
          type: 'duplicate',
          entryId: e.id,
          detail: 'Password reused in ${pwList.length} entries',
        ));
      }
      // Weak/short: entropy < threshold or length short.
      final ent = entropy(e.password);
      if (e.password.length < 8 || ent < 3.0) {
        warnings.add(DashboardWarning(
          severity: ent < 3.0 ? 'high' : 'medium',
          type: 'weak',
          entryId: e.id,
          detail: 'Weak password (entropy ${ent.toStringAsFixed(1)})',
        ));
      }
      // Old: not updated in > staleDays.
      if (now > 0 && e.updatedAt > 0 && now - e.updatedAt > staleDays * 24 * 3600 * 1000) {
        final days = ((now - e.updatedAt) / (24 * 3600 * 1000)).floor();
        warnings.add(DashboardWarning(
          severity: 'medium',
          type: 'old',
          entryId: e.id,
          detail: 'Password not changed in $days days',
        ));
      }
    }
    return warnings;
  }
}