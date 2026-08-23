import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/crypto/native/sodium_ffi.dart';

// Intent: First tracer-bullet for Phase 0.1 — prove libsodium loads and inits.
// Invariants: sodium_init() == 0 exactly once; version string non-empty.
void main() {
  group('SodiumFfi', () {
    test('loads libsodium and initializes', () {
      final sodium = SodiumFfi.load();
      expect(sodium.init(), 0);
      expect(sodium.versionString(), isNotEmpty);
    });
  });
}