import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/sync/native_noise.dart';

// Intent: Verify the native Noise channel (classical NNpsk core over libsodium
// crypto_box) generates a static keypair and can encrypt/decrypt a message.
// Invariants: static keypair is 32 bytes; encrypt->decrypt round-trips.
void main() {
  group('NativeNoise', () {
    test('generates a 32-byte static public key', () {
      final noise = NativeNoise();
      final pk = noise.getStaticPublicKey();
      expect(pk.length, 32);
    });

    test('round-trips a message with the static keypair', () {
      final noise = NativeNoise();
      final msg = Uint8List.fromList(utf8.encode('hello noise'));
      final ct = noise.encryptToSelf(msg);
      final pt = noise.decryptFromSelf(ct);
      expect(utf8.decode(pt), 'hello noise');
    });
  });
}
