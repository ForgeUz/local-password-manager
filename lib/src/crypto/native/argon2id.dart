import 'dart:ffi';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import 'sodium_ffi.dart';
import 'dart:io';

// Intent: Argon2id via libsodium crypto_pwhash.
// Used for: MK derivation (v2 §2, v3 §19, v4 §5.3).
// Dependencies: libsodium.so.23, dart:ffi, dart:typed_data, package:ffi.
//
// SECURITY CRITICAL: All native memory MUST be zeroed before freeing.
// sodium_memzero is called on ALL secret buffers before calloc.free.

const int _SALTBYTES = 16;
const int _HASHBYTES = 32;
const int _ALG_ARGON2ID13 = 2;

// libsodium signatures for sodium_memzero
typedef SodiumMemzeroNative = Void Function(Pointer<Void>, Int64);
typedef SodiumMemzeroDart = void Function(Pointer<Void>, int);

typedef PwhashNative = Int32 Function(Pointer<Void>, Int64, Pointer<Void>,
    Int64, Pointer<Void>, Int64, Int64, Int32, Int32);
typedef PwhashDart = int Function(
    Pointer<Void>, int, Pointer<Void>, int, Pointer<Void>, int, int, int, int);

class Argon2id {
  static bool _inited = false;

  /// Derive a 32-byte master key from password + salt using Argon2id.
  ///
  /// SECURITY: All intermediate secrets are zeroed before freeing.
  /// Returns Uint8List copy (caller responsible for zeroing if sensitive).
  static Uint8List derive(Uint8List password, Uint8List salt,
      {required int memory,
      required int iterations,
      required int parallelism}) {
    _ensureInit();
    final lib = DynamicLibrary.open(
        Platform.isAndroid ? 'libsodium.so' : 'libsodium.so.23');
    final pwhash =
        lib.lookupFunction<PwhashNative, PwhashDart>('crypto_pwhash');
    final memzero = lib.lookupFunction<SodiumMemzeroNative, SodiumMemzeroDart>(
        'sodium_memzero');

    final out = calloc.allocate<Uint8>(_HASHBYTES);
    final pwPtr = calloc.allocate<Uint8>(password.length);
    final saltPtr = calloc.allocate<Uint8>(_SALTBYTES);

    try {
      // Copy password and salt into native memory
      pwPtr.asTypedList(password.length).setAll(0, password);
      saltPtr.asTypedList(_SALTBYTES).setAll(0, salt);

      // Derive key: crypto_pwhash(out, outlen, passwd, passwdlen, salt, opslimit, memlimit, alg, p)
      final rc = pwhash(
          out.cast<Void>(),
          _HASHBYTES,
          pwPtr.cast<Void>(),
          password.length,
          saltPtr.cast<Void>(),
          iterations,
          memory,
          _ALG_ARGON2ID13,
          parallelism);
      if (rc != 0) throw StateError('Argon2id derivation failed');

      // CRITICAL: Copy result BEFORE zeroing native memory
      final result = Uint8List.fromList(out.asTypedList(_HASHBYTES));

      // CRITICAL: Zero ALL secret buffers before freeing
      memzero(out.cast<Void>(), _HASHBYTES); // Master key
      memzero(pwPtr.cast<Void>(), password.length); // Password copy
      memzero(saltPtr.cast<Void>(), _SALTBYTES); // Salt copy

      return result;
    } catch (e) {
      // On error, still zero memory before freeing
      memzero(out.cast<Void>(), _HASHBYTES);
      memzero(pwPtr.cast<Void>(), password.length);
      memzero(saltPtr.cast<Void>(), _SALTBYTES);
      rethrow;
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
