import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/sync/replay_counter.dart';

void main() {
  test('Accepts increasing counter', () {
    final counter = ReplayCounter();
    expect(counter.validate(1), isTrue);
    expect(counter.validate(2), isTrue);
    expect(counter.validate(3), isTrue);
  });

  test('Rejects non-increasing counter', () {
    final counter = ReplayCounter();
    counter.validate(5);
    expect(counter.validate(4), isFalse); // Decrease
    expect(counter.validate(5), isFalse); // Equal
  });
}