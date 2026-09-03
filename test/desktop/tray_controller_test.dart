import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/desktop/tray_controller.dart';
import 'package:vault_crypto/src/desktop/tray_platform.dart';
import 'package:vault_crypto/src/lock/state.dart';
import 'package:vault_crypto/src/vault/vault_data.dart';
import 'dart:typed_data';

// Intent: Verify TrayController maps binary lock state to the tray icon and
// wires click/menu callbacks. Tray must never render vault contents.
class MockTrayPlatform implements TrayPlatform {
  String? lastIcon;
  String? lastTooltip;
  void Function()? onActivate;
  void Function()? onLock;
  void Function()? onQuit;

  @override
  Future<void> setup({
    required void Function() onActivate,
    required void Function() onLock,
    required void Function() onQuit,
  }) async {
    this.onActivate = onActivate;
    this.onLock = onLock;
    this.onQuit = onQuit;
  }

  @override
  Future<void> updateState(
      {required String icon, required String tooltip}) async {
    lastIcon = icon;
    lastTooltip = tooltip;
  }
}

void main() {
  test('tray icon updates to Locked when vault state becomes Locked', () async {
    final mock = MockTrayPlatform();
    final controller = TrayController(
      platform: mock,
      onActivate: () {},
      onLock: () {},
      onQuit: () {},
    );
    await controller.init();

    controller.onStateChanged(Locked(blob: Uint8List(0)));
    expect(mock.lastIcon, 'locked_icon');
    expect(mock.lastTooltip, 'Vault Locked');
  });

  test('tray icon updates to Unlocked when vault state becomes Unlocked',
      () async {
    final mock = MockTrayPlatform();
    final controller = TrayController(
      platform: mock,
      onActivate: () {},
      onLock: () {},
      onQuit: () {},
    );
    await controller.init();

    controller.onStateChanged(
        Unlocked(vaultData: VaultData(entries: []), blob: Uint8List(0)));
    expect(mock.lastIcon, 'unlocked_icon');
    expect(mock.lastTooltip, 'Vault Unlocked');
  });

  test('tray menu Lock and Quit dispatch their callbacks', () async {
    final mock = MockTrayPlatform();
    var locked = false;
    var quit = false;
    final controller = TrayController(
      platform: mock,
      onActivate: () {},
      onLock: () => locked = true,
      onQuit: () => quit = true,
    );
    await controller.init();

    mock.onLock!();
    mock.onQuit!();
    expect(locked, isTrue);
    expect(quit, isTrue);
  });
}
