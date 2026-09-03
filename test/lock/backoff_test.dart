import 'package:test/test.dart';
import 'package:vault_crypto/src/lock/backoff.dart';

void main() {
  test('BackoffCalculator returns correct durations', () {
    expect(BackoffCalculator.nextDelay(0), equals(Duration.zero));
    expect(BackoffCalculator.nextDelay(1), equals(const Duration(seconds: 1)));
    expect(BackoffCalculator.nextDelay(2), equals(const Duration(seconds: 2)));
    expect(BackoffCalculator.nextDelay(3), equals(const Duration(seconds: 4)));
    expect(BackoffCalculator.nextDelay(4), equals(const Duration(seconds: 8)));
    expect(
        BackoffCalculator.nextDelay(9), equals(const Duration(seconds: 256)));
    expect(
        BackoffCalculator.nextDelay(10), equals(const Duration(seconds: 300)));
    expect(
        BackoffCalculator.nextDelay(15), equals(const Duration(seconds: 300)));
  });
}
