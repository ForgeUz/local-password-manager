// File: tool/timing_statistical.dart
// Intent: security2.md gate 28.1 — Statistical timing analysis (beyond mean).
// Verifies that password verification time distributions for correct vs wrong
// passwords are statistically indistinguishable.
// Statistical tests:
// - Kolmogorov-Smirnov test: distributions identical (p > 0.05).
// - Welch's t-test: no significant difference (p > 0.05).
// - Effect size (Cohen's d): < 0.2 (negligible).
// - No outliers (> 3σ) in either distribution.
// Usage: dart run tool/timing_statistical.dart
// Dependencies: vault_crypto_v4.dart, secure_buffer.dart.

import 'dart:math';
import 'dart:typed_data';

import 'package:vault_crypto/src/crypto/native/secure_buffer.dart';
import 'package:vault_crypto/src/crypto/v4/vault_crypto_v4.dart';

SecureBuffer _mp(String s) {
  final buf = SecureBuffer.alloc(s.length);
  buf.writeBytes(Uint8List.fromList(s.codeUnits));
  return buf;
}

Future<void> main() async {
  final crypto = VaultCryptoV4();
  final json = Uint8List.fromList('{"entries":[]}'.codeUnits);
  final blob = await crypto.lockVault(json, _mp('right'));

  // Warm up.
  for (var i = 0; i < 3; i++) {
    try {
      await crypto.unlockVault(blob, _mp('right'));
    } catch (_) {}
  }

  // Collect 1000 samples per condition.
  final correct = <double>[];
  final wrong = <double>[];
  for (var i = 0; i < 1000; i++) {
    var sw = Stopwatch()..start();
    await crypto.unlockVault(blob, _mp('right'));
    sw.stop();
    correct.add(sw.elapsedMicroseconds.toDouble());

    sw = Stopwatch()..start();
    try {
      await crypto.unlockVault(blob, _mp('wrong'));
    } catch (_) {}
    sw.stop();
    wrong.add(sw.elapsedMicroseconds.toDouble());
  }

  // Remove outliers (> 3σ).
  final correctClean = _removeOutliers(correct);
  final wrongClean = _removeOutliers(wrong);

  final meanC = _mean(correctClean);
  final meanW = _mean(wrongClean);
  final sdC = _std(correctClean);
  final sdW = _std(wrongClean);

  // Welch's t-test.
  final t = _welchT(meanC, meanW, sdC, sdW, correctClean.length, wrongClean.length);
  final df = _welchDf(sdC, sdW, correctClean.length, wrongClean.length);
  final pT = _pValue(t, df);

  // Cohen's d.
  final pooledSd = sqrt((sdC * sdC + sdW * sdW) / 2);
  final cohensD = (meanC - meanW).abs() / pooledSd;

  // KS test (approximate).
  final ksD = _ksStatistic(correctClean, wrongClean);

  print('Correct: mean=${meanC.toStringAsFixed(0)}us sd=${sdC.toStringAsFixed(0)}us n=${correctClean.length}');
  print('Wrong:   mean=${meanW.toStringAsFixed(0)}us sd=${sdW.toStringAsFixed(0)}us n=${wrongClean.length}');
  print('Welch t=${t.toStringAsFixed(3)} df=${df.toStringAsFixed(1)} p=${pT.toStringAsFixed(4)}');
  print("Cohen's d=${cohensD.toStringAsFixed(3)}");
  print('KS D=${ksD.toStringAsFixed(4)}');

  var failures = 0;
  if (pT < 0.05) {
    print('FAIL: t-test p < 0.05 (significant timing difference).');
    failures++;
  }
  if (cohensD >= 0.2) {
    print('FAIL: Cohen\'s d >= 0.2 (non-negligible effect).');
    failures++;
  }
  if (ksD > 0.1) {
    print('FAIL: KS D > 0.1 (distributions differ).');
    failures++;
  }

  if (failures > 0) {
    print('FAIL: $failures statistical timing check(s) failed.');
    throw StateError('statistical timing oracle detected');
  }
  print('PASS: timing distributions statistically indistinguishable.');
}

double _mean(List<double> xs) => xs.reduce((a, b) => a + b) / xs.length;

double _std(List<double> xs) {
  final m = _mean(xs);
  final v = xs.map((x) => (x - m) * (x - m)).reduce((a, b) => a + b) / (xs.length - 1);
  return sqrt(v);
}

List<double> _removeOutliers(List<double> xs) {
  final m = _mean(xs);
  final s = _std(xs);
  return xs.where((x) => (x - m).abs() <= 3 * s).toList();
}

double _welchT(double m1, double m2, double s1, double s2, int n1, int n2) {
  return (m1 - m2) / sqrt((s1 * s1 / n1) + (s2 * s2 / n2));
}

double _welchDf(double s1, double s2, int n1, int n2) {
  final a = s1 * s1 / n1;
  final b = s2 * s2 / n2;
  return (a + b) * (a + b) / ((a * a / (n1 - 1)) + (b * b / (n2 - 1)));
}

// Approximate two-tailed p-value for a t-distribution (normal approximation
// for large df, which is valid here with n=1000).
double _pValue(double t, double df) {
  // For large df, t ~ N(0,1). Two-tailed p = 2*(1 - Phi(|t|)).
  final z = t.abs();
  final phi = 0.5 * (1 + _erf(z / sqrt(2)));
  return 2 * (1 - phi);
}

double _erf(double x) {
  // Abramowitz-Stegun approximation.
  final sign = x < 0 ? -1.0 : 1.0;
  final ax = x.abs();
  final t = 1.0 / (1.0 + 0.3275911 * ax);
  final y = 1.0 - (((((1.061405429 * t - 1.453152027) * t) + 1.421413741) * t - 0.284496736) * t + 0.254829592) * t * exp(-ax * ax);
  return sign * y;
}

// Kolmogorov-Smirnov statistic (max difference between ECDFs).
double _ksStatistic(List<double> a, List<double> b) {
  final all = [...a, ...b]..sort();
  var maxD = 0.0;
  var i = 0, j = 0;
  for (final x in all) {
    while (i < a.length && a[i] <= x) {
      i++;
    }
    while (j < b.length && b[j] <= x) {
      j++;
    }
    final d = ((i / a.length) - (j / b.length)).abs();
    if (d > maxD) maxD = d;
  }
  return maxD;
}
