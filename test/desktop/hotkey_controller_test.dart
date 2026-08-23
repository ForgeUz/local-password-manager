import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/desktop/hotkey_platform.dart';
import 'package:vault_crypto/src/desktop/hotkey_controller.dart';
import 'package:vault_crypto/src/lock/intent.dart';

class MockHotkeyPlatform implements HotkeyPlatform {
  void Function()? onKeyPressed;
  
  @override
  Future<void> registerHotkey(void Function() onTrigger) async {
    onKeyPressed = onTrigger;
  }
}

void main() {
  test('HotkeyController dispatches RequestReveal on key press', () async {
    final mock = MockHotkeyPlatform();
    LockIntent? dispatchedIntent;
    
    final controller = HotkeyController(
      platform: mock,
      dispatch: (intent) => dispatchedIntent = intent,
    );

    await controller.register();
    // Simulate OS key press
    mock.onKeyPressed!();
    
    expect(dispatchedIntent, isA<RequestReveal>());
  });
}