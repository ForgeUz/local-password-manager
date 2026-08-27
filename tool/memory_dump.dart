// File: tool/memory_dump.dart
// Intent: security.md gate 16.1 — Memory dump analysis.
// Verifies that after a SecureBuffer is disposed (lock), no residual plaintext
// remains in its native region. This is the unit-level proxy for the spec's
// "no residual plaintext post-lock" requirement.
// Invariants:
// - After vault lock: no MK, VRK, DEK in memory (native regions zeroed).
// - No accumulation of secrets over multiple lock/unlock cycles.
// Usage: dart run tool/memory_dump.dart
// Dependencies: secure_buffer.dart, memory_dump.dart.

import 'dart:typed_data';

import 'package:vault_crypto/src/crypto/native/memory_dump.dart';
import 'package:vault_crypto/src/crypto/native/secure_buffer.dart';

void main() {
  var failures = 0;

  // 1. Single lock/unlock cycle: marker must be wiped after dispose.
  final marker = Uint8List.fromList(List.generate(32, (i) => (0xA0 + i) & 0xFF));
  final buf = SecureBuffer.alloc(marker.length);
  buf.writeBytes(marker);
  final presentBefore = MemoryDumpVerifier.scanFor(buf, marker);
  buf.dispose();
  final presentAfter = MemoryDumpVerifier.scanFor(buf, marker);
  print('Single cycle: presentBefore=$presentBefore presentAfter=$presentAfter');
  if (!presentBefore || presentAfter) {
    print('FAIL: residual plaintext after dispose');
    failures++;
  }

  // 2. 1000 lock/unlock cycles: no accumulation.
  var accumulated = false;
  for (var i = 0; i < 1000; i++) {
    final m = Uint8List.fromList(List.generate(32, (j) => (0x10 + (i + j)) & 0xFF));
    final b = SecureBuffer.alloc(m.length);
    b.writeBytes(m);
    b.dispose();
    if (MemoryDumpVerifier.scanFor(b, m)) {
      accumulated = true;
      break;
    }
  }
  print('1000 cycles: accumulated=$accumulated');
  if (accumulated) {
    print('FAIL: secret accumulation over lock/unlock cycles');
    failures++;
  }

  if (failures > 0) {
    print('FAIL: $failures memory-dump check(s) failed.');
    // Exit non-zero to signal failure.
    throw StateError('memory dump verification failed');
  }
  print('PASS: no residual plaintext after lock; no accumulation over 1000 cycles.');
}
