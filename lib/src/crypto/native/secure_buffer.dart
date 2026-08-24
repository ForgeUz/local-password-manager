import 'dart:ffi';
import 'dart:typed_data';
import 'sodium_ffi.dart';
import 'dart:io';

// Intent: Native secure memory via libsodium sodium_malloc/sodium_memzero.
// Invariants: dispose() zeroes all bytes; double-dispose safe; never a Dart String.
// State Transition: alloc -> write/read/runUnlocked -> dispose (zeroed, kept valid).
// Dependencies: libsodium.so.23, dart:ffi, dart:typed_data.
// Trade-off: native allocation kept alive after dispose (view stays valid, no UAF);
// freed at process exit. Zero-wipe is the security property; free is deferred.

typedef SodiumMallocNative = Pointer<Void> Function(Int64);
typedef SodiumMallocDart = Pointer<Void> Function(int);
typedef SodiumMemzeroNative = Void Function(Pointer<Void>, Int64);
typedef SodiumMemzeroDart = void Function(Pointer<Void>, int);

class SecureBuffer {
  static bool _inited = false;

  final Pointer<Void> _native;
  final Uint8List _backing;
  bool _isDisposed = false;

  SecureBuffer._(this._native, this._backing);

  static void _ensureInit() {
    if (_inited) return;
    SodiumFfi.load().init();
    _inited = true;
  }

  static SecureBuffer alloc(int length) {
    _ensureInit();
    final lib = DynamicLibrary.open(Platform.isAndroid ? 'libsodium.so' : 'libsodium.so.23');
    final sodiumMalloc = lib.lookupFunction<SodiumMallocNative, SodiumMallocDart>(
      'sodium_malloc',
    );
    final ptr = sodiumMalloc(length);
    final backing = ptr.cast<Uint8>().asTypedList(length);
    return SecureBuffer._(ptr, backing);
  }

  factory SecureBuffer.fromList(Uint8List data) {
    final buf = SecureBuffer.alloc(data.length);
    buf.writeBytes(data);
    return buf;
  }

  void writeBytes(Uint8List bytes, [int offset = 0]) {
    _checkDisposed();
    _backing.setRange(offset, offset + bytes.length, bytes);
  }

  Uint8List readBytes() {
    _checkDisposed();
    return _backing;
  }

  bool get isDisposed => _isDisposed;

  int get length => _backing.length;

  // Intent: Test/forensic-only read that bypasses the disposed guard, so a test
  // can assert the native memory was actually zeroed after dispose().
  Uint8List peekBytes() {
    return _backing;
  }

  // Intent: Debug-only native address, used by MemoryDumpVerifier to scan the
  // exact native region a secret lived in. Not for production use.
  int get nativeAddress => _native.address;

  T runUnlocked<T>(T Function(Uint8List data) callback) {
    _checkDisposed();
    return callback(_backing);
  }

  void _checkDisposed() {
    if (_isDisposed) throw StateError('SecureBuffer disposed');
  }

  void dispose() {
    if (_isDisposed) return;
    final lib = DynamicLibrary.open(Platform.isAndroid ? 'libsodium.so' : 'libsodium.so.23');
    final sodiumMemzero = lib.lookupFunction<SodiumMemzeroNative, SodiumMemzeroDart>(
      'sodium_memzero',
    );
    sodiumMemzero(_native, _backing.length);
    _isDisposed = true;
  }
}