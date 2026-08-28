// Intent: Deep module boundary for Linux global hotkeys.
abstract class HotkeyPlatform {
  Future<void> registerHotkey(void Function() onTrigger);
}
