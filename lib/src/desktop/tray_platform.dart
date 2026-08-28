// Intent: Deep module boundary for Linux tray icon.
// The tray renders ONLY binary state (Locked/Unlocked) — never vault contents.
// State Transition: setup(callbacks) -> updateState(icon) on lock-state change.
// Dependencies: native GTK/X11/Wayland plugin via MethodChannel.
abstract class TrayPlatform {
  Future<void> setup({
    required void Function() onActivate,
    required void Function() onLock,
    required void Function() onQuit,
  });

  Future<void> updateState({required String icon, required String tooltip});
}
