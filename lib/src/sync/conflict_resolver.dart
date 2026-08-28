import 'dart:io';
import 'dart:typed_data';
import 'vector_clock.dart';

// Intent: Per-entry conflict resolution (Phase G.5). On a concurrent-edit
// conflict, archive the losing version to a conflicts/ folder and surface a
// manual-merge prompt. Never auto-merges.
// Invariants: conflict -> archive + prompt; dominated -> no archive, explicit
// win. Losing version is the remote/stale copy when the local dominates.
// Dependencies: dart:io, dart:typed_data, VectorClock.

class ConflictOutcome {
  final bool archived; // a losing version was written to conflicts/
  final String? conflictedEntryId;
  final SyncFlag decision;
  const ConflictOutcome({
    required this.archived,
    required this.decision,
    this.conflictedEntryId,
  });
}

class ConflictResolver {
  final Directory _conflictsDir;

  ConflictResolver({required Directory conflictsDir})
      : _conflictsDir = conflictsDir {
    if (!_conflictsDir.existsSync()) _conflictsDir.createSync(recursive: true);
  }

  // Decide a per-entry sync conflict and archive the losing version if needed.
  Future<ConflictOutcome> resolve({
    required String entryId,
    required VectorClock localClock,
    required VectorClock remoteClock,
    required Uint8List localBytes,
    required Uint8List remoteBytes,
  }) async {
    final decision = localClock.decideAgainst(remoteClock);
    switch (decision) {
      case SyncFlag.localWins:
        return ConflictOutcome(archived: false, decision: SyncFlag.localWins);
      case SyncFlag.remoteWins:
        return ConflictOutcome(archived: false, decision: SyncFlag.remoteWins);
      case SyncFlag.same:
        return ConflictOutcome(archived: false, decision: SyncFlag.same);
      case SyncFlag.conflict:
        // Archive the remote (losing-for-now) version for manual merge.
        final stamp = DateTime.now().millisecondsSinceEpoch;
        final file = File(
            '${_conflictsDir.path}${Platform.pathSeparator}conflict_${entryId}_$stamp.blob');
        await file.writeAsBytes(remoteBytes, flush: true);
        return ConflictOutcome(
          archived: true,
          decision: SyncFlag.conflict,
          conflictedEntryId: entryId,
        );
    }
  }
}
