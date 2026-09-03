import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/sync/vector_clock.dart';

// Intent: Verify per-entry vector clocks (Phase G.4).
// Invariants: domination -> local/remote wins; concurrent -> conflict;
// serialization round-trips.
void main() {
  group('PerEntryVectorClock', () {
    test('A dominates B -> local wins (no conflict)', () {
      // Both edited on device-a after bootstrap; A has an extra edit.
      final base = VectorClock({'dev-a': 3, 'dev-b': 2});
      final a = base.increment('dev-a'); // {a:4, b:2}
      final b = base; // {a:3, b:2}
      expect(a.dominates(b), isTrue);
      expect(a.decideAgainst(b), SyncFlag.localWins);
    });

    test('concurrent edits -> conflict', () {
      final base = VectorClock({'dev-a': 1, 'dev-b': 1});
      final a = base.increment('dev-a'); // {a:2, b:1}
      final b = base.increment('dev-b'); // {a:1, b:2}
      expect(a.dominates(b), isFalse);
      expect(b.dominates(a), isFalse);
      expect(a.decideAgainst(b), SyncFlag.conflict);
    });

    test('clock-skew rollback cannot overwrite newer', () {
      final newer = VectorClock({'dev-a': 5}).increment('dev-a'); // {a:6}
      final older = VectorClock({'dev-a': 3}); // stale
      expect(newer.decideAgainst(older), SyncFlag.localWins);
      expect(older.decideAgainst(newer), SyncFlag.remoteWins);
    });

    test('serialize/parse round-trips', () {
      final vc = VectorClock({'dev-a': 1, 'dev-b': 9}).increment('dev-b');
      final parsed = VectorClock.fromBytes(vc.toBytes());
      expect(parsed.map['dev-b'], 10);
      expect(parsed.map['dev-a'], 1);
    });
  });
}
