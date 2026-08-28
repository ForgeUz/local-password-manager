// Intent: Pure exponential backoff calculator for failed unlock attempts.
// Prevents brute-force MP guessing.
class BackoffCalculator {
  static const int _maxDelaySeconds = 300; // 5 mins

  static Duration nextDelay(int failCount) {
    if (failCount <= 0) return Duration.zero;
    // 2^(failCount-1) seconds: 1, 2, 4, 8, 16, 32, 64, 128, 256, 300
    int delay = 1 << (failCount - 1);
    if (delay > _maxDelaySeconds) delay = _maxDelaySeconds;
    return Duration(seconds: delay);
  }
}
