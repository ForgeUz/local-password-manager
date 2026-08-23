import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/crypto/native/secure_buffer.dart';

// Intent: Verify native secure memory (sodium_malloc) zero-wipes on dispose.
// Invariants: after dispose, backing bytes are all zero; double-dispose is safe.
void main() {
  group('SecureBuffer', () {
    test('zero-wipes native memory on dispose', () {
      final buf = SecureBuffer.alloc(16);
      buf.writeBytes(Uint8List.fromList(List.generate(16, (_) => 0xAB)));
      expect(buf.readBytes()[0], 0xAB);
      buf.dispose();
      expect(buf.isDisposed, isTrue);
      expect(buf.peekBytes().every((b) => b == 0), isTrue);
    });

    test('dispose is idempotent', () {
      final buf = SecureBuffer.alloc(4);
      buf.dispose();
      buf.dispose(); // must not throw
      expect(true, isTrue);
    });
  });
}