import 'dart:async';
import 'clipboard_platform.dart';

// Intent: Manages clipboard lifecycle. Enforces 30s auto-wipe.
// State Transition: copy() -> Timer Reset -> Timeout -> clear()
class ClipboardController {
  final ClipboardPlatform _platform;
  final Duration _wipeDuration;
  Timer? _wipeTimer;

  ClipboardController({
    required ClipboardPlatform platform,
    Duration wipeDuration = const Duration(seconds: 30),
  })  : _platform = platform,
        _wipeDuration = wipeDuration;

  Future<void> copy(String text) async {
    await _platform.copy(text, sensitive: true);
    _wipeTimer?.cancel();
    _wipeTimer = Timer(_wipeDuration, () {
      _platform.clear();
    });
  }

  void dispose() {
    _wipeTimer?.cancel();
  }
}
