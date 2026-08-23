import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/sync/traffic_padding.dart';

// Intent: Verify sync traffic padding (Phase G.6).
// Invariants: padded to fixed bucket; bucket size hides true length; dummies
// are random 2-5; >16KB messages split into 16KB chunks.
void main() {
  group('TrafficPadding', () {
    test('pads a small message to its bucket, hiding exact size', () {
      final msg = Uint8List.fromList(List.generate(10, (i) => i));
      final padded = TrafficPadding.pad(msg);
      // 10 bytes -> 256B bucket.
      expect(padded.length, 256);
      // Content preserved at start.
      expect(padded[0], 0);
      expect(padded[9], 9);
      // Padding is non-zero CSPRNG (at least somewhere after content).
      expect(padded.sublist(10).any((b) => b != 0), isTrue);
    });

    test('generates 2-5 dummy messages', () {
      final dummies = TrafficPadding.generateDummies();
      expect(dummies.length, inInclusiveRange(2, 5));
      // Dummies are random data (non-zero content likely).
      expect(dummies.every((d) => d.isNotEmpty), isTrue);
    });

    test('splits messages larger than 16KB into 16KB chunks', () {
      final big = Uint8List(40 * 1024); // 40KB
      final chunks = TrafficPadding.splitAndPad(big);
      expect(chunks.length, 3); // 40/16 = 2.5 -> 3 chunks
      expect(chunks.every((c) => c.length == 16 * 1024), isTrue);
    });
  });
}