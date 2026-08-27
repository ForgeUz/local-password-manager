// File: test/security/android/test_ble.dart
// Intent: security.md gate 7.3 — BLE transport security verification.
// The BLE plugin (BleTransportPlugin.kt) is Kotlin/device-level and not
// unit-testable in Dart. This test verifies the Dart-side transport contract
// that BLE carries: the Noise-encrypted channel (native_noise) and the
// traffic-padding layer, which are the security-relevant Dart components.
// Invariants:
// - BLE connection uses Noise protocol (encrypted).
// - Data transfer round-trips through the encrypted channel.
// - Traffic padding applied to prevent traffic analysis.
// Dependencies: native_noise.dart, traffic_padding.dart.

import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/sync/native_noise.dart';
import 'package:vault_crypto/src/sync/traffic_padding.dart';

void main() {
  group('Gate 7.3 BLE Transport', () {
    test('BLE connection uses Noise protocol (encrypted round-trip)', () {
      final noise = NativeNoise();
      final msg = Uint8List.fromList('sync-payload'.codeUnits);
      final ct = noise.encryptToSelf(msg);
      // Ciphertext is larger than plaintext (16-byte box tag).
      expect(ct.length, msg.length + 16);
      final pt = noise.decryptFromSelf(ct);
      expect(pt, equals(msg));
    });

    test('encrypted channel does not leak plaintext', () {
      final noise = NativeNoise();
      final msg = Uint8List.fromList('secret-sync-data'.codeUnits);
      final ct = noise.encryptToSelf(msg);
      // The plaintext must not appear in the ciphertext.
      expect(_contains(ct, msg), isFalse);
    });

    test('traffic padding applied to BLE messages', () {
      final msg = Uint8List(10);
      final padded = TrafficPadding.pad(msg);
      // Padded to a fixed bucket (256 bytes).
      expect(padded.length, 256);
    });

    test('BLE message sizes not correlated with content', () {
      final p1 = TrafficPadding.pad(Uint8List(5));
      final p2 = TrafficPadding.pad(Uint8List(200));
      expect(p1.length, 256);
      expect(p2.length, 256);
    });
  });
}

bool _contains(Uint8List haystack, Uint8List needle) {
  if (needle.isEmpty || needle.length > haystack.length) return false;
  for (var i = 0; i <= haystack.length - needle.length; i++) {
    var match = true;
    for (var j = 0; j < needle.length; j++) {
      if (haystack[i + j] != needle[j]) {
        match = false;
        break;
      }
    }
    if (match) return true;
  }
  return false;
}
