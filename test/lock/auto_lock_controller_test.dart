import 'dart:async';
import 'package:test/test.dart';
import 'package:vault_crypto/src/lock/auto_lock_controller.dart';
import 'package:vault_crypto/src/lock/intent.dart';

void main() {
  test('AutoLockController emits AutoLock after timeout', () async {
    LockIntent? receivedIntent;
    final controller = AutoLockController(
      dispatch: (intent) => receivedIntent = intent,
      timeout: const Duration(milliseconds: 50),
    );

    controller.start();
    await Future.delayed(const Duration(milliseconds: 100));

    expect(receivedIntent, isA<AutoLock>());
    controller.dispose();
  });

  test('RegisterActivity prevents AutoLock before new timeout expires',
      () async {
    LockIntent? receivedIntent;
    final controller = AutoLockController(
      dispatch: (intent) => receivedIntent = intent,
      timeout: const Duration(milliseconds: 50),
    );

    controller.start();

    // Activity at 25ms resets timer to fire at 75ms
    await Future.delayed(const Duration(milliseconds: 25));
    controller.registerActivity();

    // Check at 60ms (original timer would have fired at 50ms)
    await Future.delayed(const Duration(milliseconds: 35));

    expect(receivedIntent, isNull);
    controller.dispose();
  });
}
