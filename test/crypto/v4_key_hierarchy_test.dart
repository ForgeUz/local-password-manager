import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/crypto/native/constant_time.dart';
import 'package:vault_crypto/src/crypto/v4/key_hierarchy.dart';

// Intent: Verify the per-entry key hierarchy (v3 §19 / v4 §8 A.4-A.7).
// Invariants: VRK derives deterministically; DEK wraps under VRK and unwraps
// back; a wrong VRK fails to unwrap.
void main() {
  group('KeyHierarchy', () {
    test('derives deterministic VRK from MK', () {
      final mk = Uint8List.fromList(List.generate(32, (i) => i));
      final v1 = KeyHierarchy.deriveVrk(mk);
      final v2 = KeyHierarchy.deriveVrk(mk);
      expect(v1.length, 32);
      expect(ConstantTime.equals(v1, v2), isTrue);
    });

    test('wraps and unwraps a DEK under VRK', () {
      final mk = Uint8List.fromList(List.generate(32, (i) => i));
      final vrk = KeyHierarchy.deriveVrk(mk);
      final dek = Uint8List.fromList(List.generate(32, (i) => 0x80 + i));
      final wrapped = KeyHierarchy.wrapDek(vrk, dek);
      final unwrapped = KeyHierarchy.unwrapDek(vrk, wrapped);
      expect(ConstantTime.equals(unwrapped, dek), isTrue);
    });

    test('wrong VRK fails to unwrap', () {
      final mk = Uint8List.fromList(List.generate(32, (i) => i));
      final vrk = KeyHierarchy.deriveVrk(mk);
      final wrongVrk = Uint8List.fromList(List.generate(32, (i) => 0xFF - i));
      final dek = Uint8List.fromList(List.generate(32, (i) => 0x80 + i));
      final wrapped = KeyHierarchy.wrapDek(vrk, dek);
      var threw = false;
      try {
        KeyHierarchy.unwrapDek(wrongVrk, wrapped);
      } catch (_) {
        threw = true;
      }
      expect(threw, isTrue);
    });
  });
}
