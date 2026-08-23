import 'dart:ffi';
import 'package:ffi/ffi.dart';

// Intent: FFI boundary to libsodium. Single load point for all crypto.
// Invariants: sodium_init() called exactly once; returns 0 on success.
// State Transition: unloaded -> init() -> inited -> usable.
// Dependencies: libsodium.so.23 (verified present on Linux), dart:ffi, dart:io.

typedef SodiumInitNative = Int32 Function();
typedef SodiumInitDart = int Function();
typedef SodiumVersionNative = Pointer<Utf8> Function();
typedef SodiumVersionDart = Pointer<Utf8> Function();

class SodiumFfi {
  final DynamicLibrary _lib;

  SodiumFfi._(this._lib);

  static SodiumFfi load() {
    final lib = DynamicLibrary.open('libsodium.so.23');
    return SodiumFfi._(lib);
  }

  int init() {
    final sodiumInit = _lib.lookupFunction<SodiumInitNative, SodiumInitDart>(
      'sodium_init',
    );
    return sodiumInit();
  }

  String versionString() {
    final sodiumVersionString = _lib.lookupFunction<SodiumVersionNative, SodiumVersionDart>(
      'sodium_version_string',
    );
    return sodiumVersionString().toDartString();
  }
}