import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/clipboard/clipboard_controller.dart';
import 'package:vault_crypto/src/clipboard/clipboard_platform.dart';

// Intent: Mock platform to verify controller logic without native channels.
class MockClipboardPlatform implements ClipboardPlatform {
  String? copiedText;
  bool wasSensitive = false;
  int clearCount = 0;

  @override
  Future<void> copy(String text, {bool sensitive = false}) async {
    copiedText = text;
    wasSensitive = sensitive;
  }

  @override
  Future<void> clear() async {
    clearCount++;
  }
}

void main() {
  test('ClipboardController auto-wipes after 30 seconds', () async {
    final mockPlatform = MockClipboardPlatform();
    // Inject 1 second timeout for testing
    final controller = ClipboardController(
      platform: mockPlatform,
      wipeDuration: const Duration(seconds: 1),
    );

    await controller.copy('my_secret_password');
    expect(mockPlatform.copiedText, 'my_secret_password');
    expect(mockPlatform.clearCount, 0);

    await Future.delayed(const Duration(milliseconds: 500));
    expect(mockPlatform.clearCount, 0); // Not cleared yet

    await Future.delayed(const Duration(milliseconds: 600));
    expect(mockPlatform.clearCount, 1); // Cleared after timeout
  });

  test('Copy overwrites previous and resets timer', () async {
    final mockPlatform = MockClipboardPlatform();
    final controller = ClipboardController(
      platform: mockPlatform,
      wipeDuration: const Duration(seconds: 1),
    );

    await controller.copy('first');
    await Future.delayed(const Duration(milliseconds: 700));
    
    await controller.copy('second');
    expect(mockPlatform.copiedText, 'second');
    expect(mockPlatform.clearCount, 0);

    // Wait 500ms. If timer wasn't reset, clearCount would be 1.
    await Future.delayed(const Duration(milliseconds: 500));
    expect(mockPlatform.clearCount, 0);

    // Wait remaining 600ms to hit 1.1s since second copy
    await Future.delayed(const Duration(milliseconds: 600));
    expect(mockPlatform.clearCount, 1);
  });
}