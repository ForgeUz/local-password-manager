import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/crypto/native/constant_time.dart';
import 'package:vault_crypto/src/crypto/v4/time_lock.dart';

// Intent: Verify the time-lock hash chain (v4 §5.2 / §6.6).
// Invariants: chain is deterministic; N iterations produce the same key;
// the chain is sequential (each step depends on the previous).
void main() {
  group('TimeLock', () {
    test('computes a deterministic chain of N iterations', () {
      final seed = Uint8List.fromList(List.generate(32, (i) => i));
      final k1 = TimeLock.computeChain(seed, 100);
      final k2 = TimeLock.computeChain(seed, 100);
      expect(k1.length, 32);
      expect(ConstantTime.equals(k1, k2), isTrue);
    });

    test('chain is sequential (N+1 differs from N)', () {
      final seed = Uint8List.fromList(List.generate(32, (i) => i));
      final k100 = TimeLock.computeChain(seed, 100);
      final k101 = TimeLock.computeChain(seed, 101);
      expect(ConstantTime.equals(k100, k101), isFalse);
    });
  });
}