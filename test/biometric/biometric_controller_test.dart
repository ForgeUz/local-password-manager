import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/biometric/biometric_platform.dart';
import 'package:vault_crypto/src/biometric/biometric_controller.dart';
import 'package:vault_crypto/src/lock/intent.dart';

class MockBiometricPlatform implements BiometricPlatform {
  bool shouldSucceed;
  Exception? error;
  int callCount = 0;

  MockBiometricPlatform({this.shouldSucceed = true, this.error});

  @override
  Future<bool> authenticate() async {
    callCount++;
    if (error != null) throw error!;
    return shouldSucceed;
  }
}

void main() {
  test('BiometricController dispatches UnlockSuccess on true', () async {
    final mock = MockBiometricPlatform(shouldSucceed: true);
    LockIntent? dispatchedIntent;

    final controller = BiometricController(
      platform: mock,
      dispatch: (intent) => dispatchedIntent = intent,
    );

    await controller.authenticate();

    expect(dispatchedIntent, isA<UnlockSuccess>());
    expect(mock.callCount, 1);
  });

  test('BiometricController dispatches UnlockFail on false', () async {
    final mock = MockBiometricPlatform(shouldSucceed: false);
    LockIntent? dispatchedIntent;

    final controller = BiometricController(
      platform: mock,
      dispatch: (intent) => dispatchedIntent = intent,
    );

    await controller.authenticate();

    expect(dispatchedIntent, isA<UnlockFail>());
  });

  test('BiometricController dispatches UnlockFail on exception', () async {
    final mock = MockBiometricPlatform(error: Exception('Keystore locked'));
    LockIntent? dispatchedIntent;

    final controller = BiometricController(
      platform: mock,
      dispatch: (intent) => dispatchedIntent = intent,
    );

    await controller.authenticate();

    expect(dispatchedIntent, isA<UnlockFail>());
  });
}
