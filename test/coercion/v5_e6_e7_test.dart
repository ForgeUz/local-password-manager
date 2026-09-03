import 'dart:io';
import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/coercion/shred_deferral.dart';
import 'package:vault_crypto/src/coercion/shred_purge.dart';
import 'package:vault_crypto/src/sync/shred_messages.dart';
import 'package:vault_crypto/src/sync/vector_clock.dart';

// Intent: v5 E6 (shred/cancel propagation race) and E7 (snapshot/conflict purge
// on shred). E6: a device executes shred only after delay + after confirming no
// unprocessed cancellation; offline -> DEFER until handshake or local code.
// E7: after shred, snapshots/ + conflicts/ contain no recoverable material for
// the shredded entry; restore list shows only post-shred states.
void main() {
  group('v5 E6 shred/cancel propagation', () {
    test('offline peer that missed a cancellation NEVER shreds (defers)', () {
      // Originator A schedules shred, then sends SHRED_CANCELLED.
      final seen = <String, VectorClock>{};
      final scheduled = ShredMessage(
        type: ShredMessageType.scheduled,
        originatorId: 'A',
        entryId: 'e1',
        clock: VectorClock({'A': 1}),
      );
      final cancelled = ShredMessage(
        type: ShredMessageType.cancelled,
        originatorId: 'A',
        entryId: 'e1',
        clock: VectorClock({'A': 2}),
      );
      expect(ShredMessages.apply(scheduled, seen), isTrue);
      expect(ShredMessages.apply(cancelled, seen), isTrue);

      // Offline peer B: no handshake, no local code, cancellation pending.
      final decision = ShredDeferral.decide(
        hasUnprocessedCancellation:
            ShredMessages.hasUnprocessedCancellation(seen, 'e1'),
        handshakeOk: false,
        localCodeEntered: false,
      );
      expect(decision, ShredDecision.defer);

      // After a successful Noise handshake with A, B confirms no cancellation
      // is pending -> executes.
      final afterHandshake = ShredDeferral.decide(
        hasUnprocessedCancellation: false,
        handshakeOk: true,
        localCodeEntered: false,
      );
      expect(afterHandshake, ShredDecision.execute);
    });

    test('local cancellation-code entry also cancels (no handshake needed)',
        () {
      final decision = ShredDeferral.decide(
        hasUnprocessedCancellation: false,
        handshakeOk: false,
        localCodeEntered: true,
      );
      expect(decision, ShredDecision.execute);
    });

    test('SHRED_CANCELLED is idempotent (re-delivery is a no-op)', () {
      final seen = <String, VectorClock>{};
      final cancelled = ShredMessage(
        type: ShredMessageType.cancelled,
        originatorId: 'A',
        entryId: 'e1',
        clock: VectorClock({'A': 2}),
      );
      expect(ShredMessages.apply(cancelled, seen), isTrue);
      // Re-delivery of the same (or older) message is a no-op.
      expect(ShredMessages.apply(cancelled, seen), isFalse);
    });
  });

  group('v5 E7 snapshot/conflict purge on shred', () {
    test(
        'snapshots/ and conflicts/ purged of shredded entry; restore = post-shred',
        () async {
      final dir = Directory.systemTemp.createTempSync('vault_e7_');
      addTearDown(() => dir.deleteSync(recursive: true));
      final snapshots =
          Directory('${dir.path}${Platform.pathSeparator}snapshots');
      final conflicts =
          Directory('${dir.path}${Platform.pathSeparator}conflicts');
      snapshots.createSync(recursive: true);
      conflicts.createSync(recursive: true);

      // Pre-shred state: a snapshot + a conflict archive referencing entry e1.
      final preShred = Uint8List.fromList('pre-shred-e1'.codeUnits);
      final conflict = Uint8List.fromList('conflict-e1'.codeUnits);
      await File('${snapshots.path}${Platform.pathSeparator}vault.v1.blob')
          .writeAsBytes(preShred, flush: true);
      await File(
              '${conflicts.path}${Platform.pathSeparator}conflict_e1_123.blob')
          .writeAsBytes(conflict, flush: true);

      // Post-shred blob (e1 removed).
      final postShred = Uint8List.fromList('post-shred'.codeUnits);

      final restore = await ShredPurge.purgeEntry(
        entryId: 'e1',
        snapshotsDir: snapshots,
        conflictsDir: conflicts,
        postShredBlob: postShred,
      );

      // conflicts/ has no e1 material.
      final conflictFiles = conflicts.listSync().whereType<File>().toList();
      expect(conflictFiles.any((f) => f.path.contains('e1')), isFalse);
      // snapshots/ has only the post-shred seed.
      expect(restore.length, 1);
      final seeded = await File(restore.first).readAsBytes();
      expect(seeded, equals(postShred));
    });
  });
}
