import 'dart:io';
import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/sync/conflict_resolver.dart';
import 'package:vault_crypto/src/sync/vector_clock.dart';

// Intent: Verify per-entry conflict resolution (Phase G.5).
// Invariants: concurrent -> archive losing version + conflict decision; local
// dominates -> no archive, local wins; no auto-merge.
void main() {
  late Directory tmp;
  late ConflictResolver resolver;

  setUp(() {
    tmp = Directory.systemTemp.createTempSync('conflict_');
    resolver =
        ConflictResolver(conflictsDir: Directory('${tmp.path}/conflicts'));
  });

  tearDown(() {
    if (tmp.existsSync()) tmp.deleteSync(recursive: true);
  });

  test('concurrent conflict archives the remote version', () async {
    final base = VectorClock({'a': 1, 'b': 1});
    final localClock = base.increment('a');
    final remoteClock = base.increment('b');
    final local = Uint8List.fromList([1]);
    final remote = Uint8List.fromList([2]);

    final out = await resolver.resolve(
      entryId: 'e1',
      localClock: localClock,
      remoteClock: remoteClock,
      localBytes: local,
      remoteBytes: remote,
    );
    expect(out.archived, isTrue);
    expect(out.decision, SyncFlag.conflict);
    // conflicts/ dir now has the archived remote version.
    final files = Directory('${tmp.path}/conflicts')
        .listSync()
        .whereType<File>()
        .toList();
    expect(files.length, 1);
    expect(Uint8List.fromList(files.first.readAsBytesSync()), remote);
  });

  test('local dominates -> no archive, no merge', () async {
    final localClock = VectorClock({'a': 3, 'b': 2});
    final remoteClock = VectorClock({'a': 2, 'b': 2});
    final out = await resolver.resolve(
      entryId: 'e2',
      localClock: localClock,
      remoteClock: remoteClock,
      localBytes: Uint8List.fromList([1]),
      remoteBytes: Uint8List.fromList([9]),
    );
    expect(out.archived, isFalse);
    expect(out.decision, SyncFlag.localWins);
    // No archive file written (dir exists from constructor but is empty).
    final files = Directory('${tmp.path}/conflicts')
        .listSync()
        .whereType<File>()
        .toList();
    expect(files, isEmpty);
  });
}
