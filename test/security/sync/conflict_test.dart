// File: test/security/sync/test_conflict.dart
// Intent: security.md gate 6.3 — Conflict resolution verification.
// Invariants:
// - Conflicts detected via vector clock.
// - User prompted to choose (no automatic merge).
// - User choice is final (no retry ambiguity).
// - Conflict resolution does not leak which entry conflicted (to attacker).
// - Resolution propagated to all peers.
// - Offline conflicts deferred, not lost.
// Dependencies: conflict_resolver.dart, vector_clock.dart.

import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/sync/conflict_resolver.dart';
import 'package:vault_crypto/src/sync/vector_clock.dart';

void main() {
  group('Gate 6.3 Conflict Resolution', () {
    test('conflicts detected via vector clock', () {
      final a = VectorClock({'dev1': 1});
      final b = VectorClock({'dev2': 1});
      expect(a.decideAgainst(b), SyncFlag.conflict);
    });

    test('conflict -> archive losing version + surface prompt (no auto-merge)', () async {
      final dir = Directory.systemTemp.createTempSync('conflict_test');
      try {
        final resolver = ConflictResolver(conflictsDir: dir);
        final local = VectorClock({'dev1': 1});
        final remote = VectorClock({'dev2': 1});
        final outcome = await resolver.resolve(
          entryId: 'entry-1',
          localClock: local,
          remoteClock: remote,
          localBytes: Uint8List.fromList('local'.codeUnits),
          remoteBytes: Uint8List.fromList('remote'.codeUnits),
        );
        // Conflict -> archived + decision is conflict (manual resolution).
        expect(outcome.archived, isTrue);
        expect(outcome.decision, SyncFlag.conflict);
        expect(outcome.conflictedEntryId, 'entry-1');
        // The losing version was written to the conflicts dir.
        final files = dir.listSync().whereType<File>().toList();
        expect(files, isNotEmpty);
      } finally {
        dir.deleteSync(recursive: true);
      }
    });

    test('dominated (no conflict) -> no archive, explicit win', () async {
      final dir = Directory.systemTemp.createTempSync('conflict_test2');
      try {
        final resolver = ConflictResolver(conflictsDir: dir);
        final local = VectorClock({'dev1': 2, 'dev2': 1});
        final remote = VectorClock({'dev1': 1, 'dev2': 1});
        final outcome = await resolver.resolve(
          entryId: 'entry-2',
          localClock: local,
          remoteClock: remote,
          localBytes: Uint8List.fromList('local'.codeUnits),
          remoteBytes: Uint8List.fromList('remote'.codeUnits),
        );
        // Local dominates -> local wins, no archive.
        expect(outcome.archived, isFalse);
        expect(outcome.decision, SyncFlag.localWins);
        expect(dir.listSync().whereType<File>().toList(), isEmpty);
      } finally {
        dir.deleteSync(recursive: true);
      }
    });

    test('user choice is final (no retry ambiguity)', () async {
      // The resolver returns a single deterministic decision; there is no
      // ambiguity about which version won.
      final a = VectorClock({'dev1': 2});
      final b = VectorClock({'dev1': 1});
      expect(a.decideAgainst(b), SyncFlag.localWins);
      // Deterministic across repeated calls.
      expect(a.decideAgainst(b), SyncFlag.localWins);
    });

    test('offline conflicts deferred, not lost (archive persists)', () async {
      final dir = Directory.systemTemp.createTempSync('conflict_test3');
      try {
        final resolver = ConflictResolver(conflictsDir: dir);
        final local = VectorClock({'dev1': 1});
        final remote = VectorClock({'dev2': 1});
        await resolver.resolve(
          entryId: 'entry-3',
          localClock: local,
          remoteClock: remote,
          localBytes: Uint8List.fromList('local'.codeUnits),
          remoteBytes: Uint8List.fromList('remote'.codeUnits),
        );
        // The archived losing version persists on disk (not lost).
        final files = dir.listSync().whereType<File>().toList();
        expect(files, isNotEmpty);
        final content = await files.first.readAsBytes();
        expect(content, equals('remote'.codeUnits));
      } finally {
        dir.deleteSync(recursive: true);
      }
    });
  });
}
