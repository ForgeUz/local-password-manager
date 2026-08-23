import 'package:flutter/services.dart';
import 'tray_platform.dart';
import 'hotkey_platform.dart';

// Intent: Connects Dart logic to Linux native GTK/X11/Wayland bindings.
class NativeLinuxTray implements TrayPlatform {
  static const _channel = MethodChannel('vault_crypto/linux_tray');

  @override
  Future<void> setup({
    required void Function() onActivate,
    required void Function() onLock,
    required void Function() onQuit,
  }) async {
    _channel.setMethodCallHandler((call) async {
      if (call.method == 'trayActivated') {
        onActivate();
      } else if (call.method == 'trayLock') {
        onLock();
      } else if (call.method == 'trayQuit') {
        onQuit();
      }
      return null;
    });

    try {
      await _channel.invokeMethod('setupTray');
    } on PlatformException {
      // Fail silently if running on non-Linux or missing native plugin
    }
  }

  @override
  Future<void> updateState({required String icon, required String tooltip}) async {
    try {
      await _channel.invokeMethod('updateState', {
        'icon': icon,
        'tooltip': tooltip,
      });
    } on PlatformException {
      // Fail silently if running on non-Linux or missing native plugin
    }
  }
}

class NativeLinuxHotkey implements HotkeyPlatform {
  static const _channel = MethodChannel('vault_crypto/linux_hotkey');

  @override
  Future<void> registerHotkey(void Function() onTrigger) async {
    _channel.setMethodCallHandler((call) async {
      if (call.method == 'hotkeyPressed') {
        onTrigger();
      }
      return null;
    });
    
    try {
      await _channel.invokeMethod('registerHotkey');
    } on PlatformException {
      // Fail silently
    }
  }
}