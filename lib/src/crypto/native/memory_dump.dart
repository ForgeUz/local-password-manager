import 'dart:ffi';
import 'dart:typed_data';
import 'secure_buffer.dart';
import 'dart:io';

// Intent: Debug-only memory-dump verifier. Scans a SecureBuffer's native
// region for a residual plaintext marker, proving sodium_memzero wiped it.
// This is the unit-level proxy for the spec's "no residual plaintext post-lock"
// AC (v2 §4 / v3 §4 / v4 §8 Phase B). A full process-heap scan is not feasible
// in a Dart test; scanning the exact native region the secret lived in is the
// honest, deterministic equivalent.
// Invariants: scanFor returns true iff the marker is present in the region.
// Dependencies: SecureBuffer (nativeAddress), dart:ffi, dart:typed_data.

class MemoryDumpVerifier {
  static bool scanFor(SecureBuffer buf, Uint8List marker) {
    final addr = buf.nativeAddress;
    if (addr == 0) return false;
    final region = Pointer<Uint8>.fromAddress(addr).asTypedList(buf.length);
    if (region.length < marker.length) return false;
    for (var i = 0; i <= region.length - marker.length; i++) {
      var match = true;
      for (var j = 0; j < marker.length; j++) {
        if (region[i + j] != marker[j]) {
          match = false;
          break;
        }
      }
      if (match) return true;
    }
    return false;
  }
}