// ignore_for_file: constant_identifier_names
// Names mirror libsodium C constants (KEYBYTES, BYTES).

import 'dart:ffi';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import 'sodium_ffi.dart';
import 'dart:io';

// Intent: HMAC-SHA256 via libsodium crypto_auth_hmacsha256.
// Used for: search_tag (v4 §5.1), HKDF inner HMAC, TOTP (v3 §12).
// Dependencies: libsodium.so.23, dart:ffi, dart:typed_data, package:ffi.

const int _KEYBYTES = 32;
const int _BYTES = 32;

typedef HmacNative = Int32 Function(
    Pointer<Void>, Pointer<Void>, Int64, Pointer<Void>);
typedef HmacDart = int Function(
    Pointer<Void>, Pointer<Void>, int, Pointer<Void>);

class HmacSha256 {
  static bool _inited = false;

  static Uint8List compute(Uint8List key, Uint8List data) {
    if (key.length != _KEYBYTES) throw StateError('HMAC key must be 32 bytes');
    _ensureInit();
    final lib = DynamicLibrary.open(
        Platform.isAndroid ? 'libsodium.so' : 'libsodium.so.23');
    final hmac =
        lib.lookupFunction<HmacNative, HmacDart>('crypto_auth_hmacsha256');

    final out = calloc.allocate<Uint8>(_BYTES);
    final keyPtr = calloc.allocate<Uint8>(_KEYBYTES);
    final dataPtr = calloc.allocate<Uint8>(data.length);
    try {
      out.asTypedList(_BYTES).fillRange(0, _BYTES, 0);
      keyPtr.asTypedList(_KEYBYTES).setAll(0, key);
      dataPtr.asTypedList(data.length).setAll(0, data);

      final rc = hmac(out.cast<Void>(), dataPtr.cast<Void>(), data.length,
          keyPtr.cast<Void>());
      if (rc != 0) throw StateError('HMAC-SHA256 failed');
      return Uint8List.fromList(out.asTypedList(_BYTES));
    } finally {
      calloc.free(out);
      calloc.free(keyPtr);
      calloc.free(dataPtr);
    }
  }

  static void _ensureInit() {
    if (_inited) return;
    SodiumFfi.load().init();
    _inited = true;
  }
}
