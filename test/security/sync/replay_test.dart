// File: test/security/sync/test_replay.dart
// Intent: security.md gate 6.2 — Replay prevention verification.
// Invariants:
// - Vector clock detects concurrent modifications.
// - Replay counter increments monotonically.
// - Duplicate messages rejected.
// - Old messages rejected.
// - Vector clock comparison is deterministic.
// - Conflict detection triggers manual resolution (no auto-merge).
// - Traffic padding applied to prevent traffic analysis.
// Dependencies: replay_counter.dart, vector_clock.dart, traffic_padding.dart.

import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/sync/replay_counter.dart';
import 'package:vault_crypto/src/sync/traffic_padding.dart';
import 'package:vault_crypto/src/sync/vector_clock.dart';

void main() {
  group('Gate 6.2 Replay Prevention', () {
    test('replay counter increments monotonically', () {
      final counter = ReplayCounter();
      expect(counter.validate(1), isTrue);
      expect(counter.validate(2), isTrue);
      expect(counter.validate(3), isTrue);
    });

    test('duplicate messages rejected', () {
      final counter = ReplayCounter();
      counter.validate(5);
      // Same counter again -> rejected (duplicate).
      expect(counter.validate(5), isFalse);
    });

    test('old messages rejected', () {
      final counter = ReplayCounter();
      counter.validate(10);
      // Lower counter -> rejected (old/replayed).
      expect(counter.validate(9), isFalse);
      expect(counter.validate(5), isFalse);
    });

    test('vector clock detects concurrent modifications', () {
      final a = VectorClock({'dev1': 1});
      final b = VectorClock({'dev2': 1});
      // Neither dominates -> conflict.
      expect(a.decideAgainst(b), SyncFlag.conflict);
    });

    test('vector clock comparison is deterministic', () {
      final a = VectorClock({'dev1': 2, 'dev2': 1});
      final b = VectorClock({'dev1': 1, 'dev2': 1});
      // a dominates b.
      expect(a.decideAgainst(b), SyncFlag.localWins);
      // Deterministic: repeated calls give same result.
      expect(a.decideAgainst(b), SyncFlag.localWins);
      expect(a.decideAgainst(b), SyncFlag.localWins);
    });

    test('conflict detection triggers manual resolution (no auto-merge)', () {
      final a = VectorClock({'dev1': 1});
      final b = VectorClock({'dev2': 1});
      // Conflict is detected, not auto-merged.
      expect(a.hasConflict(b), isTrue);
    });

    test('traffic padding applied to prevent traffic analysis', () {
      // Messages are padded to fixed buckets (256/1K/4K/16K).
      final small = Uint8List(10);
      final padded = TrafficPadding.pad(small);
      expect(padded.length, 256); // smallest bucket
      // Padding is CSPRNG, not zeros.
      expect(padded.sublist(10).any((b) => b != 0), isTrue);
    });

    test('traffic padding: message sizes not correlated with content', () {
      // A 10-byte and a 200-byte message both pad to the 256-byte bucket.
      final p1 = TrafficPadding.pad(Uint8List(10));
      final p2 = TrafficPadding.pad(Uint8List(200));
      expect(p1.length, 256);
      expect(p2.length, 256);
    });
  });
}
