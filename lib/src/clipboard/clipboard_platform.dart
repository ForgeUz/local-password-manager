// Intent: Deep module boundary for platform clipboards.
// Allows injecting mocks for pure Dart testing.
abstract class ClipboardPlatform {
  Future<void> copy(String text, {bool sensitive = false});
  Future<void> clear();
}
