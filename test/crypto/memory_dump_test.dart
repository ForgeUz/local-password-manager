import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/crypto/native/memory_dump.dart';
import 'package:vault_crypto/src/crypto/native/secure_buffer.dart';

// Intent: Verify no residual plaintext remains in a SecureBuffer's native
// region after dispose (memory-dump AC, v2 §4 / v3 §4 / v4 §8 Phase B).
// Invariants: marker present before dispose, absent after.
void main() {
  group('MemoryDumpVerifier', () {
    test('no residual plaintext in native region after dispose', () {
      final marker =
          Uint8List.fromList(List.generate(32, (i) => (0xA0 + i) & 0xFF));
      final buf = SecureBuffer.alloc(marker.length);
      buf.writeBytes(marker);
      // marker present in the native region before dispose (sanity)
      expect(MemoryDumpVerifier.scanFor(buf, marker), isTrue);
      buf.dispose();
      // after dispose, sodium_memzero must have wiped the region
      expect(MemoryDumpVerifier.scanFor(buf, marker), isFalse);
    });
  });
}
