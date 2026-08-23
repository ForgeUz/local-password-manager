import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/crypto/v4/fido2_factor.dart';

// Intent: v5 H.6 — FIDO2 hardware key as an unlock factor. A P-256 signature
// (64 bytes) is folded into the HKDF input; wrong/absent signature -> different
// VRK -> GCM fails (math, not a check). Keylogger-immune (never typed).
void main() {
  group('v5 H.6 FIDO2 factor', () {
    test('P-256 signature folds into VRK; wrong sig -> different VRK', () {
      final mk = Uint8List.fromList(List.generate(32, (i) => i));
      final sigA = Uint8List.fromList(List.generate(64, (i) => i));
      final sigB = Uint8List.fromList(List.generate(64, (i) => 0xFF - i));

      final vrkA = Fido2Factor.deriveVrkWithFido2(mk, sigA);
      final vrkB = Fido2Factor.deriveVrkWithFido2(mk, sigB);
      expect(vrkA.length, 32);
      // Different signature -> different VRK (wrong key -> GCM fails).
      expect(_eq(vrkA, vrkB), isFalse);
    });

    test('rejects a non-64-byte signature (fail-closed)', () {
      final mk = Uint8List.fromList(List.generate(32, (i) => i));
      final bad = Uint8List.fromList(List.generate(32, (i) => i));
      expect(
        () => Fido2Factor.deriveVrkWithFido2(mk, bad),
        throwsA(isA<StateError>()),
      );
    });
  });
}

bool _eq(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}