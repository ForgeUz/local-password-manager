import 'dart:ffi';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import 'sodium_ffi.dart';
import 'dart:io';

// Intent: SHA-256 via libsodium crypto_hash_sha256.
// Used for: time-lock hash chain (v4 §5.2), integrity heartbeat (v3 §21.4).
// Dependencies: libsodium.so.23, dart:ffi, dart:typed_data, package:ffi.

const int _BYTES = 32;

typedef HashNative = Int32 Function(Pointer<Void>, Pointer<Void>, Int64);
typedef HashDart = int Function(Pointer<Void>, Pointer<Void>, int);

class Sha256 {
  static bool _inited = false;

  static Uint8List hash(Uint8List data) {
    _ensureInit();
    final lib = DynamicLibrary.open(Platform.isAndroid ? 'libsodium.so' : 'libsodium.so.23');
    final hash = lib.lookupFunction<HashNative, HashDart>('crypto_hash_sha256');
    final out = calloc.allocate<Uint8>(_BYTES);
    final dataPtr = calloc.allocate<Uint8>(data.length);
    try {
      dataPtr.asTypedList(data.length).setAll(0, data);
      final rc = hash(out.cast<Void>(), dataPtr.cast<Void>(), data.length);
      if (rc != 0) throw StateError('SHA-256 failed');
      return Uint8List.fromList(out.asTypedList(_BYTES));
    } finally {
      calloc.free(out);
      calloc.free(dataPtr);
    }
  }

  static void _ensureInit() {
    if (_inited) return;
    SodiumFfi.load().init();
    _inited = true;
  }
}