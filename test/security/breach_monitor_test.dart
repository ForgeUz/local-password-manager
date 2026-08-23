import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/security/breach_monitor.dart';

// Intent: Verify BreachMonitor k-anonymity prefix lookup against an offline
// corpus. Only the 5-char SHA-256 prefix is ever exposed — never the full hash.
void main() {
  test('detects breached password via 5-char prefix (k-anonymity)', () {
    // Compute the real 5-char prefix of SHA-256('password').
    final prefix = BreachMonitor.prefixOf('password');
    final monitor = BreachMonitor(corpus: {prefix});
    expect(monitor.check('password').breached, isTrue);
    expect(monitor.check('other').breached, isFalse);
    expect(monitor.check('password').prefix.length, 5);
  });

  test('prefix is exactly 5 chars; full hash never exposed', () {
    final monitor = BreachMonitor(corpus: {});
    final result = monitor.check('secret');
    expect(result.prefix.length, 5);
    // The full hash must not be returned.
    expect(result.fullHash, isNull);
  });
}