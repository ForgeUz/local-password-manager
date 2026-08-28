import 'package:flutter/services.dart';
import 'clipboard_platform.dart';

// Intent: Connects pure Dart logic to native OS clipboard via MethodChannels.
// Dependencies: flutter services, platform specific native code (Android/Linux).
class NativeClipboard implements ClipboardPlatform {
  static const _channel = MethodChannel('vault_crypto/clipboard');

  @override
  Future<void> copy(String text, {bool sensitive = false}) async {
    try {
      await _channel.invokeMethod('copy', {
        'text': text,
        'sensitive': sensitive,
      });
    } catch (e) {
      // Fallback to standard clipboard if native sensitive channel fails (e.g., on Linux desktop)
      await Clipboard.setData(ClipboardData(text: text));
    }
  }

  @override
  Future<void> clear() async {
    try {
      await _channel.invokeMethod('clear');
    } catch (e) {
      await Clipboard.setData(const ClipboardData(text: ''));
    }
  }
}
