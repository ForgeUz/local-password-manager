import 'dart:convert';
import 'dart:typed_data';
import 'aes_gcm.dart';
import 'argon2id.dart';
import 'constant_time.dart';
import 'hkdf.dart';
import 'hmac_sha256.dart';
import 'sodium_ffi.dart';

// Intent: Startup self-test for the libsodium FFI layer. Fail-closed: if any
// primitive misbehaves, the app must not proceed with crypto.
// Invariants: all known-vector checks pass; throws StateError on any failure.
// State Transition: app start -> run() -> all primitives verified -> proceed.
// Dependencies: all native primitives, libsodium.so.23.

class CryptoSelfTest {
  static void run() {
    final sodium = SodiumFfi.load();
    if (sodium.init() != 0) {
      throw StateError('libsodium init failed');
    }

    // Constant-time compare
    final a = Uint8List.fromList('secret'.codeUnits);
    final b = Uint8List.fromList('secret'.codeUnits);
    final c = Uint8List.fromList('secrex'.codeUnits);
    if (!ConstantTime.equals(a, b) || ConstantTime.equals(a, c)) {
      throw StateError('constant-time compare failed');
    }

    // HMAC-SHA256 known-answer (key=0xaa x32, data=0xdd x50)
    final hmacKey = Uint8List.fromList(List.generate(32, (_) => 0xaa));
    final hmacData = Uint8List.fromList(List.generate(50, (_) => 0xdd));
    final hmacExpected = Uint8List.fromList([
      0xcd, 0xcb, 0x12, 0x20, 0xd1, 0xec, 0xcc, 0xea,
      0x91, 0xe5, 0x3a, 0xba, 0x30, 0x92, 0xf9, 0x62,
      0xe5, 0x49, 0xfe, 0x6c, 0xe9, 0xed, 0x7f, 0xdc,
      0x43, 0x19, 0x1f, 0xbd, 0xe4, 0x5c, 0x30, 0xb0,
    ]);
    if (!ConstantTime.equals(HmacSha256.compute(hmacKey, hmacData), hmacExpected)) {
      throw StateError('HMAC-SHA256 failed');
    }

    // HKDF determinism
    final ikm = Uint8List.fromList(List.generate(32, (_) => 0x01));
    final salt = Uint8List.fromList(List.generate(32, (_) => 0x02));
    final k1 = Hkdf.derive(ikm, salt, 'GENESIS-VRK-v4', 32);
    final k2 = Hkdf.derive(ikm, salt, 'GENESIS-VRK-v4', 32);
    if (k1.length != 32 || !ConstantTime.equals(k1, k2)) {
      throw StateError('HKDF failed');
    }

    // AES-GCM round-trip + tamper-fail
    final gcmKey = Uint8List.fromList(List.generate(32, (_) => 0x11));
    final nonce = Uint8List.fromList(List.generate(12, (_) => 0x22));
    final aad = Uint8List.fromList(utf8.encode('header'));
    final pt = Uint8List.fromList(utf8.encode('secret payload'));
    final ct = AesGcm.encrypt(gcmKey, nonce, aad, pt);
    if (!ConstantTime.equals(AesGcm.decrypt(gcmKey, nonce, aad, ct), pt)) {
      throw StateError('AES-GCM round-trip failed');
    }
    ct[0] = ct[0] ^ 0xff;
    var tamperThrew = false;
    try {
      AesGcm.decrypt(gcmKey, nonce, aad, ct);
    } catch (_) {
      tamperThrew = true;
    }
    if (!tamperThrew) {
      throw StateError('AES-GCM tamper detection failed');
    }

    // Argon2id determinism
    final mp = Uint8List.fromList(utf8.encode('correct horse battery staple'));
    final aSalt = Uint8List.fromList(List.generate(16, (_) => 0x42));
    final a1 = Argon2id.derive(mp, aSalt, memory: 65536, iterations: 3, parallelism: 1);
    final a2 = Argon2id.derive(mp, aSalt, memory: 65536, iterations: 3, parallelism: 1);
    if (a1.length != 32 || !ConstantTime.equals(a1, a2)) {
      throw StateError('Argon2id failed');
    }
  }
}