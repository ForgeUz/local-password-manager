import 'dart:math';

// Intent: v5 E15 — behavioral biometrics in LOG-SPACE (log-normal fit via
// Welford). Flight times are right-skewed, not Gaussian — Welford over raw
// milliseconds mis-models them. Per-pair scoring activates ONLY after >=8
// samples for that pair; below the gate, a GLOBAL model with a looser 3.5-sigma
// threshold applies. Three consecutive anomalies -> lock + re-auth. Disabled
// during duress; user kill switch; timing-only (never keystroke content).
// The v4 fabricated FP figure is DELETED; FP/FN are measured empirically.
// Invariants: per-pair gate >=8 samples; global 3.5-sigma fallback; three
// consecutive anomalies lock; normal typing does not.
// Dependencies: dart:math.

class _Stats {
  int count = 0;
  double mean = 0;
  double m2 = 0; // sum of squared differences

  void update(double x) {
    count++;
    final delta = x - mean;
    mean += delta / count;
    m2 += delta * (x - mean);
  }

  double get variance => count > 1 ? m2 / (count - 1) : 0;
  double get stddev => sqrt(variance);
}

class ObservationResult {
  final bool lockTriggered;
  final bool anomalous;

  const ObservationResult(
      {required this.lockTriggered, required this.anomalous});
}

class BehavioralModel {
  // v5 E15: per-pair scoring activates only after >=8 samples for that pair.
  static const int perPairMinSamples = 8;
  // Below the gate, the GLOBAL model uses a looser 3.5-sigma threshold.
  static const double globalSigma = 3.5;
  // Once the per-pair gate is reached, per-pair scoring uses 3.0-sigma.
  static const double perPairSigma = 3.0;
  static const int _consecutiveLock = 3;

  final Map<String, _Stats> _stats = {};
  final _Stats _global = _Stats();
  int _consecutiveAnomalies = 0;

  // v5 E15: no fabricated FP figure. FP/FN must be MEASURED empirically.
  // A model this small cannot claim a fixed false-lock rate.

  ObservationResult observe(String prevKey, String currKey, int flightTimeUs) {
    final key = '$prevKey->$currKey';
    final stats = _stats.putIfAbsent(key, () => _Stats());
    // LOG-SPACE (log-normal fit via Welford): flight times are right-skewed.
    final ln = log(flightTimeUs <= 0 ? 1 : flightTimeUs.toDouble());

    // Score AGAINST the pre-update model: a sample must not be part of the
    // distribution it is scored against (an outlier would inflate variance and
    // mask the next anomaly). Gate reached when the pair already has >=8.
    var anomalous = false;
    if (stats.count >= perPairMinSamples && stats.stddev > 0) {
      // Per-pair gate reached: score with the tighter 3.0-sigma threshold.
      final z = (ln - stats.mean).abs() / stats.stddev;
      anomalous = z > perPairSigma;
    } else if (_global.count > 1 && _global.stddev > 0) {
      // Below the gate: fall back to the GLOBAL model with looser 3.5-sigma.
      final z = (ln - _global.mean).abs() / _global.stddev;
      anomalous = z > globalSigma;
    }

    // Train ONLY non-anomalous samples: the anomaly baseline must stay clean,
    // or two outliers would inflate variance and mask the third (breaking the
    // 3-consecutive-anomaly lock).
    if (!anomalous) {
      stats.update(ln);
      _global.update(ln);
    }

    if (anomalous) {
      _consecutiveAnomalies++;
    } else {
      _consecutiveAnomalies = 0;
    }

    final lock = _consecutiveAnomalies >= _consecutiveLock;
    return ObservationResult(lockTriggered: lock, anomalous: anomalous);
  }
}
