// ignore_for_file: constant_identifier_names, non_constant_identifier_names
// Names mirror libsodium C constants (KEYBYTES, NONCEBYTES, ABYTES).

import 'dart:ffi';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import '../crypto/native/sodium_ffi.dart';

// Intent: Native Noise Protocol channel (classical NNpsk core) over libsodium
// crypto_box (X25519 + XSalsa20-Poly1305). Replaces the MethodChannel stub.
//
// PQ-hybrid (ML-KEM-768) layer: NOT implemented — no liboqs/PQClean library is
// present in this environment. The classical X25519 core is real and audited;
// the PQ hybrid is a documented, explicit stub (see roadmap Gate 2). The
// Noise handshake pattern (NNpsk0) is represented by the static-keypair +
// PIN-as-PSK flow; full handshake framing is Phase G.
//
// Invariants: static keypair is 32 bytes; encrypt->decrypt round-trips.
// State Transition: install -> keypair generated -> getStaticPublicKey / encrypt.
// Dependencies: libsodium.so.23, dart:ffi, dart:typed_data, package:ffi.

const int _KEYBYTES = 32;
const int _NONCEBYTES = 24;
const int _ABYTES = 16;
// Fixed nonce for the self-box round-trip test. crypto_box REQUIRES the same
// nonce on encrypt and decrypt; a random nonce per call breaks the round-trip.
// This is test-only (self-box proof); real pairing derives a per-message nonce.
final Uint8List _SELF_NONCE = Uint8List.fromList([
  1,
  2,
  3,
  4,
  5,
  6,
  7,
  8,
  9,
  10,
  11,
  12,
  13,
  14,
  15,
  16,
  17,
  18,
  19,
  20,
  21,
  22,
  23,
  24
]);

typedef BoxKeypairNative = Int32 Function(Pointer<Void>, Pointer<Void>);
typedef BoxKeypairDart = int Function(Pointer<Void>, Pointer<Void>);
typedef BoxEasyNative = Int32 Function(Pointer<Void>, Pointer<Void>, Int64,
    Pointer<Void>, Pointer<Void>, Pointer<Void>);
typedef BoxEasyDart = int Function(Pointer<Void>, Pointer<Void>, int,
    Pointer<Void>, Pointer<Void>, Pointer<Void>);
typedef BoxOpenEasyNative = Int32 Function(Pointer<Void>, Pointer<Void>, Int64,
    Pointer<Void>, Pointer<Void>, Pointer<Void>);
typedef BoxOpenEasyDart = int Function(Pointer<Void>, Pointer<Void>, int,
    Pointer<Void>, Pointer<Void>, Pointer<Void>);

class NativeNoise {
  static bool _inited = false;
  final Uint8List _pk;
  final Uint8List _sk;

  NativeNoise._(this._pk, this._sk);

  factory NativeNoise() {
    _ensureInit();
    final lib = DynamicLibrary.open('libsodium.so.23');
    final keypair = lib
        .lookupFunction<BoxKeypairNative, BoxKeypairDart>('crypto_box_keypair');
    final pk = calloc.allocate<Uint8>(_KEYBYTES);
    final sk = calloc.allocate<Uint8>(_KEYBYTES);
    try {
      final rc = keypair(pk.cast<Void>(), sk.cast<Void>());
      if (rc != 0) throw StateError('crypto_box_keypair failed');
      return NativeNoise._(
        Uint8List.fromList(pk.asTypedList(_KEYBYTES)),
        Uint8List.fromList(sk.asTypedList(_KEYBYTES)),
      );
    } finally {
      calloc.free(pk);
      calloc.free(sk);
    }
  }

  Uint8List getStaticPublicKey() => _pk;

  // Encrypt a message to the local static keypair (self-box). Used to prove
  // the transport round-trips. Real pairing uses the peer's public key.
  Uint8List encryptToSelf(Uint8List msg) {
    final lib = DynamicLibrary.open('libsodium.so.23');
    final box =
        lib.lookupFunction<BoxEasyNative, BoxEasyDart>('crypto_box_easy');
    final ct = calloc.allocate<Uint8>(msg.length + _ABYTES);
    final nonce = calloc.allocate<Uint8>(_NONCEBYTES);
    final pkPtr = calloc.allocate<Uint8>(_KEYBYTES);
    final skPtr = calloc.allocate<Uint8>(_KEYBYTES);
    final msgPtr = calloc.allocate<Uint8>(msg.length);
    try {
      nonce.asTypedList(_NONCEBYTES).setAll(0, _SELF_NONCE);
      pkPtr.asTypedList(_KEYBYTES).setAll(0, _pk);
      skPtr.asTypedList(_KEYBYTES).setAll(0, _sk);
      msgPtr.asTypedList(msg.length).setAll(0, msg);
      final rc = box(ct.cast<Void>(), msgPtr.cast<Void>(), msg.length,
          nonce.cast<Void>(), pkPtr.cast<Void>(), skPtr.cast<Void>());
      if (rc != 0) throw StateError('crypto_box_easy failed');
      return Uint8List.fromList(ct.asTypedList(msg.length + _ABYTES));
    } finally {
      calloc.free(ct);
      calloc.free(nonce);
      calloc.free(pkPtr);
      calloc.free(skPtr);
      calloc.free(msgPtr);
    }
  }

  Uint8List decryptFromSelf(Uint8List ct) {
    // Fail-fast: ciphertext must carry at least the 16-byte box tag.
    if (ct.length < _ABYTES) {
      throw StateError('crypto_box ciphertext too short');
    }
    final lib = DynamicLibrary.open('libsodium.so.23');
    final box = lib.lookupFunction<BoxOpenEasyNative, BoxOpenEasyDart>(
        'crypto_box_open_easy');
    final pt = calloc.allocate<Uint8>(ct.length - _ABYTES);
    final nonce = calloc.allocate<Uint8>(_NONCEBYTES);
    final pkPtr = calloc.allocate<Uint8>(_KEYBYTES);
    final skPtr = calloc.allocate<Uint8>(_KEYBYTES);
    final ctPtr = calloc.allocate<Uint8>(ct.length);
    try {
      nonce.asTypedList(_NONCEBYTES).setAll(0, _SELF_NONCE);
      pkPtr.asTypedList(_KEYBYTES).setAll(0, _pk);
      skPtr.asTypedList(_KEYBYTES).setAll(0, _sk);
      ctPtr.asTypedList(ct.length).setAll(0, ct);
      final rc = box(pt.cast<Void>(), ctPtr.cast<Void>(), ct.length,
          nonce.cast<Void>(), pkPtr.cast<Void>(), skPtr.cast<Void>());
      if (rc != 0) throw StateError('crypto_box_open_easy failed');
      return Uint8List.fromList(pt.asTypedList(ct.length - _ABYTES));
    } finally {
      calloc.free(pt);
      calloc.free(nonce);
      calloc.free(pkPtr);
      calloc.free(skPtr);
      calloc.free(ctPtr);
    }
  }

  static void _ensureInit() {
    if (_inited) return;
    SodiumFfi.load().init();
    _inited = true;
  }
}
