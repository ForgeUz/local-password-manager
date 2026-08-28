import 'hotkey_platform.dart';
import '../lock/intent.dart';

// Intent: Listens for OS hotkey, dispatches intent to state machine.
class HotkeyController {
  final HotkeyPlatform _platform;
  final void Function(LockIntent) _dispatch;

  HotkeyController({
    required HotkeyPlatform platform,
    required void Function(LockIntent) dispatch,
  })  : _platform = platform,
        _dispatch = dispatch;

  Future<void> register() async {
    await _platform.registerHotkey(() {
      _dispatch(RequestReveal());
    });
  }
}
