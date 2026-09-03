// Intent: Pure exponential backoff calculator for failed unlock attempts.
// Prevents brute-force MP guessing.
class BackoffCalculator {
  static const int _maxDelaySeconds = 300; // 5 mins

  static Duration nextDelay(int failCount) {
    if (failCount <= 0) return Duration.zero;
    // 2^(failCount-1) seconds: 1, 2, 4, 8, 16, 32, 64, 128, 256, 300
    // Saturating loop: `1 << (failCount-1)` overflows to 0 for large counts on
    // 64-bit ints, silently disabling the cap. Multiply-and-cap instead.
    var delay = 1;
    for (var i = 1; i < failCount; i++) {
      if (delay >= _maxDelaySeconds) break;
      delay *= 2;
    }
    if (delay > _maxDelaySeconds) delay = _maxDelaySeconds;
    return Duration(seconds: delay);
  }
}
