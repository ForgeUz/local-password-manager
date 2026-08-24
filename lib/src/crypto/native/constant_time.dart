import 'dart:ffi';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import 'sodium_ffi.dart';
import 'dart:io';

// Intent: Constant-time byte comparison via libsodium sodium_compare.
// Invariants: returns true iff equal; runtime independent of content.
// Dependencies: libsodium.so.23, dart:ffi, dart:typed_data, package:ffi.

typedef SodiumCompareNative = Int32 Function(Pointer<Void>, Pointer<Void>, Int64);
typedef SodiumCompareDart = int Function(Pointer<Void>, Pointer<Void>, int);

class ConstantTime {
  static bool _inited = false;

  static bool equals(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    _ensureInit();
    final lib = DynamicLibrary.open(Platform.isAndroid ? 'libsodium.so' : 'libsodium.so.23');
    final sodiumCompare = lib.lookupFunction<SodiumCompareNative, SodiumCompareDart>(
      'sodium_compare',
    );
    final pa = calloc.allocate<Uint8>(a.length);
    final pb = calloc.allocate<Uint8>(b.length);
    try {
      pa.asTypedList(a.length).setAll(0, a);
      pb.asTypedList(b.length).setAll(0, b);
      return sodiumCompare(pa.cast<Void>(), pb.cast<Void>(), a.length) == 0;
    } finally {
      calloc.free(pa);
      calloc.free(pb);
    }
  }

  static void _ensureInit() {
    if (_inited) return;
    SodiumFfi.load().init();
    _inited = true;
  }
}