import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/crypto/native/memory_dump.dart';
import 'package:vault_crypto/src/crypto/native/secure_buffer.dart';
import 'package:vault_crypto/src/lock/secret_wiper.dart';

// Intent: Verify the secret wiper zeroes a SecureBuffer on lock/auto-lock.
// Invariants: after wipe, the native region contains no residual plaintext.
void main() {
  group('SecretWiper', () {
    test('zeroes the secret buffer on wipe', () {
      final secret = SecureBuffer.alloc(64);
      secret.writeBytes(Uint8List.fromList(List.generate(64, (i) => 0x40 + i)));
      expect(
          MemoryDumpVerifier.scanFor(
              secret, Uint8List.fromList(List.generate(8, (i) => 0x40 + i))),
          isTrue);
      SecretWiper.wipe(secret);
      expect(secret.isDisposed, isTrue);
      expect(
          MemoryDumpVerifier.scanFor(
              secret, Uint8List.fromList(List.generate(8, (i) => 0x40 + i))),
          isFalse);
    });

    test('wipe is idempotent', () {
      final secret = SecureBuffer.alloc(16);
      SecretWiper.wipe(secret);
      SecretWiper.wipe(secret); // must not throw
      expect(true, isTrue);
    });
  });
}
