import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/sync/vector_clock.dart';

void main() {
  test('Increment clock updates device entry', () {
    var clock = VectorClock({'A': 0, 'B': 0});
    clock = clock.increment('A');
    expect(clock.map['A'], 1);
  });

  test('Detects conflict on divergent clocks', () {
    final local = VectorClock({'A': 2, 'B': 1});
    final remote = VectorClock({'A': 1, 'B': 2});
    expect(local.hasConflict(remote), isTrue);
  });

  test('No conflict on dominating clocks', () {
    final local = VectorClock({'A': 2, 'B': 1});
    final remote = VectorClock({'A': 1, 'B': 1});
    expect(local.hasConflict(remote), isFalse);
  });
}
