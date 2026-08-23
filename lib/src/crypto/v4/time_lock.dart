import 'dart:typed_data';
import '../native/sha256.dart';

// Intent: Time-lock hash chain (v5 E11). Iterative SHA-256 from a seed.
//   TimeLockKey = SHA256^N(seed)
// Sequential: each iteration depends on the previous; cannot be parallelized.
// v5 E11: CAPPED at short durations (minutes to a few hours max). Creation of
// any time-lock completes in <5 seconds. Friction only — never claimed to stop
// a patched build or faster hardware; the spec says exactly that.
// Invariants: deterministic; N+1 differs from N; sequential; N capped.
// Dependencies: Sha256, dart:typed_data.

class TimeLock {
  // v5 E11: hard cap on chain length — minutes to a few hours of CPU friction.
  // 1M SHA-256 iterations is well under 5s on any desktop and provides
  // meaningful friction; the cap prevents multi-day chains.
  static const int maxIterations = 1000000;

  static Uint8List computeChain(Uint8List seed, int iterations) {
    if (iterations > maxIterations) {
      throw StateError('time-lock chain capped at $maxIterations iterations (v5 E11)');
    }
    var current = seed;
    for (var i = 0; i < iterations; i++) {
      current = Sha256.hash(current);
    }
    return current;
  }
}