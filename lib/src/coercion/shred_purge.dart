import 'dart:io';
import 'dart:typed_data';

// Intent: v5 E7 — purge + reseed snapshots/ and conflicts/ on shred.
// When a DEK is shredded, the snapshots/ directory and conflicts/ archive must
// be PURGED of any recoverable material for that entry, then reseeded from the
// post-shred state. Crypto-shredding must not be locally undoable.
// Invariants: after shred, snapshots/ + conflicts/ contain no recoverable
// material for the shredded entry; restore list shows only post-shred states.
// Dependencies: dart:io, dart:typed_data.

class ShredPurge {
  // Purge all snapshots and conflict archives that reference the shredded
  // entry, then reseed snapshots/ with the post-shred blob. Returns the list
  // of surviving snapshot files (post-shred only).
  static Future<List<String>> purgeEntry({
    required String entryId,
    required Directory snapshotsDir,
    required Directory conflictsDir,
    required Uint8List postShredBlob,
  }) async {
    // Purge conflicts/ files that reference the entry (filename carries id).
    if (conflictsDir.existsSync()) {
      for (final f in conflictsDir.listSync().whereType<File>()) {
        if (f.path.contains(entryId)) {
          await f.delete();
        }
      }
    }

    // Purge ALL snapshots (they may hold the pre-shred wrapped DEK), then
    // reseed with the post-shred blob as the only snapshot.
    if (snapshotsDir.existsSync()) {
      for (final f in snapshotsDir.listSync().whereType<File>()) {
        await f.delete();
      }
    }
    if (!snapshotsDir.existsSync()) snapshotsDir.createSync(recursive: true);
    final seed =
        File('${snapshotsDir.path}${Platform.pathSeparator}vault.v1.blob');
    await seed.writeAsBytes(postShredBlob, flush: true);

    // Restore list = only post-shred states.
    return snapshotsDir
        .listSync()
        .whereType<File>()
        .map((f) => f.path)
        .toList();
  }
}
