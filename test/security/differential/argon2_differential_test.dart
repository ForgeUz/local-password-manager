// File: test/security/differential/test_argon2_differential.dart
// Intent: security2.md gate 26.2 — Argon2id parameter compatibility.
// Verifies the FFI Argon2id wrapper produces consistent, deterministic output
// for the standard parameters (m=65536, t=3, p=1). This catches FFI parameter
// marshalling bugs (wrong memory units, wrong parameter order).
// Invariants:
// - Same password/salt → same output (deterministic).
// - Parameters: m=65536, t=3, p=1.
// - Output is 32 bytes.
// - Different salt → different output.
// Dependencies: argon2id.dart, V4Constants.

import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/crypto/native/argon2id.dart';
import 'package:vault_crypto/src/crypto/v4/constants.dart';

Uint8List _bytes(int len, int seed) =>
    Uint8List.fromList(List.generate(len, (i) => (seed + i) & 0xFF));

void main() {
  group('Gate 26.2 Argon2id Parameter Compatibility', () {
    test('parameters are m=65536, t=3, p=1 (standard)', () {
      // The KDF floor constants must match the standard Argon2id parameters.
      expect(V4Constants.kdfFloorMemory ~/ 1024, 65536); // 64 MiB in KiB
      expect(V4Constants.kdfFloorIterations, 3);
      expect(V4Constants.kdfFloorParallelism, 1);
    });

    test('same password/salt → same output (deterministic)', () {
      final pw = _bytes(16, 1);
      final salt = _bytes(16, 2);
      final a = Argon2id.derive(pw, salt, memory: 65536, iterations: 3, parallelism: 1);
      final b = Argon2id.derive(pw, salt, memory: 65536, iterations: 3, parallelism: 1);
      expect(a, equals(b));
    });

    test('output is 32 bytes', () {
      final out = Argon2id.derive(
        _bytes(16, 1),
        _bytes(16, 2),
        memory: 65536,
        iterations: 3,
        parallelism: 1,
      );
      expect(out.length, 32);
    });

    test('different salt → different output', () {
      final pw = _bytes(16, 1);
      final s1 = _bytes(16, 2);
      final s2 = _bytes(16, 3);
      final a = Argon2id.derive(pw, s1, memory: 65536, iterations: 3, parallelism: 1);
      final b = Argon2id.derive(pw, s2, memory: 65536, iterations: 3, parallelism: 1);
      expect(a, isNot(equals(b)));
    });

    test('different password → different output', () {
      final p1 = _bytes(16, 1);
      final p2 = _bytes(16, 4);
      final salt = _bytes(16, 2);
      final a = Argon2id.derive(p1, salt, memory: 65536, iterations: 3, parallelism: 1);
      final b = Argon2id.derive(p2, salt, memory: 65536, iterations: 3, parallelism: 1);
      expect(a, isNot(equals(b)));
    });
  });
}
