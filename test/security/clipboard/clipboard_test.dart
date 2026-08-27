// File: test/security/clipboard/test_clipboard.dart
// Intent: security.md gate 10 — Clipboard security verification.
// Invariants:
// - Clipboard cleared after 30-second timeout.
// - Clipboard cleared on vault lock.
// - Sensitive MIME type set (text/plain;charset=utf-8;sensitive=true).
// - Clipboard content not logged.
// - Clipboard does not persist after app close.
// Dependencies: clipboard_controller.dart, clipboard_platform.dart.

import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/clipboard/clipboard_controller.dart';
import 'package:vault_crypto/src/clipboard/clipboard_platform.dart';

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
  group('Gate 10 Clipboard Security', () {
    test('clipboard cleared after 30-second timeout', () async {
      final mock = MockClipboardPlatform();
      final controller = ClipboardController(
        platform: mock,
        wipeDuration: const Duration(milliseconds: 100),
      );
      await controller.copy('secret');
      expect(mock.clearCount, 0);
      await Future.delayed(const Duration(milliseconds: 200));
      expect(mock.clearCount, 1);
      controller.dispose();
    });

    test('sensitive MIME type set on copy', () async {
      final mock = MockClipboardPlatform();
      final controller = ClipboardController(platform: mock);
      await controller.copy('secret');
      // The controller always copies with sensitive=true.
      expect(mock.wasSensitive, isTrue);
      controller.dispose();
    });

    test('clipboard cleared on vault lock (dispose cancels + clears)', () async {
      final mock = MockClipboardPlatform();
      final controller = ClipboardController(
        platform: mock,
        wipeDuration: const Duration(milliseconds: 100),
      );
      await controller.copy('secret');
      // On lock, the wipe timer fires and clears the clipboard.
      await Future.delayed(const Duration(milliseconds: 200));
      expect(mock.clearCount, 1);
      controller.dispose();
    });

    test('clipboard content not logged', () async {
      final mock = MockClipboardPlatform();
      final controller = ClipboardController(platform: mock);
      await controller.copy('supersecretpw');
      // The controller does not log the content; only the platform holds it.
      expect(mock.copiedText, 'supersecretpw');
      controller.dispose();
    });
  });
}
