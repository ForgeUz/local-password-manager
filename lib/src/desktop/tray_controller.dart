import 'tray_platform.dart';
import '../lock/state.dart';

// Intent: Maps app state to tray icon visual state. Binary only (Locked/
// Unlocked) — never vault contents. Wires click-to-focus + right-click menu
// (Lock Vault / Quit) to app callbacks.
// State Transition: init() -> onStateChanged(state) -> updateState(icon).
// Dependencies: TrayPlatform, LockState.
class TrayController {
  final TrayPlatform _platform;
  final void Function() _onActivate;
  final void Function() _onLock;
  final void Function() _onQuit;

  TrayController({
    required TrayPlatform platform,
    required void Function() onActivate,
    required void Function() onLock,
    required void Function() onQuit,
  })  : _platform = platform,
        _onActivate = onActivate,
        _onLock = onLock,
        _onQuit = onQuit;

  Future<void> init() async {
    await _platform.setup(
      onActivate: _onActivate,
      onLock: _onLock,
      onQuit: _onQuit,
    );
  }

  void onStateChanged(LockState state) {
    if (state is Locked) {
      _platform.updateState(icon: 'locked_icon', tooltip: 'Vault Locked');
    } else if (state is Unlocked) {
      _platform.updateState(icon: 'unlocked_icon', tooltip: 'Vault Unlocked');
    }
  }
}
