import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/crypto/v4/cooldown.dart';
import 'package:vault_crypto/src/crypto/v4/liveness.dart';
import 'package:vault_crypto/src/crypto/v4/time_lock.dart';

// Intent: v5 E11 (time-lock honesty) + E1 (liveness tokens). E11: friction
// chain capped at short durations, creation <5s; tier-downgrade cooldown is a
// device-enforced policy via signed monotonic timestamps. E1: unlock emits a
// signed epoch token; epoch increments; forged/newer tokens rejected.
void main() {
  group('v5 E11 time-lock honesty', () {
    test('friction chain creation completes in <5s and is capped', () {
      final seed = Uint8List.fromList(List.generate(32, (i) => i));
      final sw = Stopwatch()..start();
      final key = TimeLock.computeChain(seed, 100000);
      sw.stop();
      expect(key.length, 32);
      expect(sw.elapsed.inSeconds, lessThan(5));
      // Cap enforced: beyond maxIterations throws.
      expect(
        () => TimeLock.computeChain(seed, TimeLock.maxIterations + 1),
        throwsA(isA<StateError>()),
      );
    });

    test('tier-downgrade cooldown uses signed monotonic timestamp', () {
      final deviceKey = Uint8List.fromList(List.generate(32, (i) => i));
      final downgradeTs = 1000000;
      final signed = Cooldown.sign(deviceKey, downgradeTs);
      // Cooldown not elapsed -> denied.
      expect(Cooldown.enforce(deviceKey, signed, downgradeTs + 1000, 5000), isFalse);
      // Cooldown elapsed -> allowed.
      expect(Cooldown.enforce(deviceKey, signed, downgradeTs + 6000, 5000), isTrue);
      // Tampered signature -> rejected (rolled-back timestamp).
      final tampered = Uint8List.fromList(signed);
      tampered[0] = tampered[0] ^ 0x01;
      expect(
        () => Cooldown.enforce(deviceKey, tampered, downgradeTs + 6000, 5000),
        throwsA(isA<CooldownTamperError>()),
      );
    });
  });

  group('v5 E1 liveness tokens', () {
    test('unlock emits signed token; epoch increments; forged/newer rejected', () {
      final vrk = Uint8List.fromList(List.generate(32, (i) => i));
      // Unlock 1: epoch 1.
      final t1 = Liveness.emit(vrk, 1, 1000);
      final (e1, ts1) = Liveness.verify(vrk, t1, 1);
      expect(e1, 1);
      expect(ts1, 1000);
      // Unlock 2: epoch increments to 2.
      final t2 = Liveness.emit(vrk, 2, 2000);
      final (e2, _) = Liveness.verify(vrk, t2, 2);
      expect(e2, 2);
      // Forged token (wrong signature) rejected.
      final forged = LivenessToken(
        epoch: 3,
        timestampMillis: 3000,
        signature: Uint8List.fromList(List.generate(32, (_) => 0)),
      );
      expect(
        () => Liveness.verify(vrk, forged, 3),
        throwsA(isA<LivenessForgeryError>()),
      );
      // Newer-epoch token rejected when expected epoch is lower.
      expect(
        () => Liveness.verify(vrk, t2, 1),
        throwsA(isA<LivenessNewerEpochError>()),
      );
    });

    test('token round-trips through export bytes (heir custody)', () {
      final vrk = Uint8List.fromList(List.generate(32, (i) => i));
      final t = Liveness.emit(vrk, 7, 5000);
      final bytes = Liveness.toBytes(t);
      final parsed = Liveness.fromBytes(bytes);
      final (e, ts) = Liveness.verify(vrk, parsed, 7);
      expect(e, 7);
      expect(ts, 5000);
    });
  });
}