import 'dart:ffi';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import 'sodium_ffi.dart';

// Intent: Argon2id via libsodium crypto_pwhash.
// Used for: MK derivation (v2 §2, v3 §19, v4 §5.3).
// Dependencies: libsodium.so.23, dart:ffi, dart:typed_data, package:ffi.

const int _SALTBYTES = 16;
const int _HASHBYTES = 32;
const int _ALG_ARGON2ID13 = 2;

typedef PwhashNative = Int32 Function(
  Pointer<Void>, Int64, Pointer<Void>, Int64, Pointer<Void>, Int64, Int64, Int32, Int32);
typedef PwhashDart = int Function(
  Pointer<Void>, int, Pointer<Void>, int, Pointer<Void>, int, int, int, int);

class Argon2id {
  static bool _inited = false;

  static Uint8List derive(Uint8List password, Uint8List salt,
      {required int memory, required int iterations, required int parallelism}) {
    _ensureInit();
    final lib = DynamicLibrary.open('libsodium.so.23');
    final pwhash = lib.lookupFunction<PwhashNative, PwhashDart>('crypto_pwhash');

    final out = calloc.allocate<Uint8>(_HASHBYTES);
    final pwPtr = calloc.allocate<Uint8>(password.length);
    final saltPtr = calloc.allocate<Uint8>(_SALTBYTES);
    try {
      pwPtr.asTypedList(password.length).setAll(0, password);
      saltPtr.asTypedList(_SALTBYTES).setAll(0, salt);

      // crypto_pwhash(out, outlen, passwd, passwdlen, salt, opslimit, memlimit, alg, p)
      final rc = pwhash(out.cast<Void>(), _HASHBYTES, pwPtr.cast<Void>(), password.length,
          saltPtr.cast<Void>(), iterations, memory, _ALG_ARGON2ID13, parallelism);
      if (rc != 0) throw StateError('Argon2id derivation failed');
      return Uint8List.fromList(out.asTypedList(_HASHBYTES));
    } finally {
      calloc.free(out);
      calloc.free(pwPtr);
      calloc.free(saltPtr);
    }
  }

  static void _ensureInit() {
    if (_inited) return;
    SodiumFfi.load().init();
    _inited = true;
  }
}