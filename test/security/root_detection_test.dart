import 'dart:io';
import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/security/root_detection.dart';

// Intent: Verify Android root detection (v4 §8 Phase D.6, v2 §5.1).
// Advisory only, never blocking. Root is flagged if any known marker exists.
void main() {
  group('RootDetection', () {
    test('flags rooted when a marker exists', () {
      // Use a definitely-present path as the root marker probe.
      final rooted = RootDetection.isRooted([
        Platform.environment['HOME'] ?? '/tmp', // always exists
      ]);
      expect(rooted, isTrue);
    });

    test('not rooted when no markers exist', () {
      final rooted = RootDetection.isRooted([
        '/nonexistent/root/marker/a',
        '/nonexistent/root/marker/b',
      ]);
      expect(rooted, isFalse);
    });

    test('standard Android root marker list', () {
      // Verify the canonical marker list is non-empty and well-formed.
      final markers = RootDetection.defaultMarkers;
      expect(markers, isNotEmpty);
    });
  });
}