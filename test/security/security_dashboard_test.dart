import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/security/security_dashboard.dart';

// Intent: Verify the local security dashboard (Phase K.1).
// Invariants: detects duplicates, weak/short, old passwords; fully local.
void main() {
  group('SecurityDashboard', () {
    test('entropy is high for random-looking password, low for short', () {
      expect(SecurityDashboard.entropy('a'), lessThan(1.0));
      expect(SecurityDashboard.entropy(r'!A9#kL2$mQ7@'), greaterThan(3.0));
    });

    test('detects duplicate + weak + old warnings', () {
      final now = DateTime.now().millisecondsSinceEpoch;
      final entries = [
        (id: 'a', title: 'A', password: 'samepass', updatedAt: now - 400 * 24 * 3600 * 1000, domain: 'a.com'),
        (id: 'b', title: 'B', password: 'samepass', updatedAt: now, domain: 'b.com'),
        (id: 'c', title: 'C', password: 'short', updatedAt: now, domain: 'c.com'),
      ];
      final warnings = SecurityDashboard.analyze(entries: entries, now: now);
      final types = warnings.map((w) => w.type).toSet();
      expect(types, contains('duplicate'));
      expect(types, contains('weak'));
      expect(types, contains('old'));
    });

    test('no warnings for strong unique fresh passwords', () {
      final now = DateTime.now().millisecondsSinceEpoch;
      final entries = [
        (id: 'a', title: 'A', password: r'!K#m9Q2$zL7', updatedAt: now, domain: 'a.com'),
        (id: 'b', title: 'B', password: r'&R4@pW1#fN8', updatedAt: now, domain: 'b.com'),
      ];
      final warnings = SecurityDashboard.analyze(entries: entries, now: now);
      expect(warnings, isEmpty);
    });
  });
}