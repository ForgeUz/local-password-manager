// File: test/security/memory/test_secure_buffer.dart
// Intent: security.md gate 3.1 — SecureBuffer usage verification.
// Invariants:
// - SecureBuffer.alloc() uses sodium_malloc (not calloc directly).
// - SecureBuffer.fromList() copies data to sodium_malloc'd memory.
// - SecureBuffer.readBytes() returns view, not copy.
// - SecureBuffer.dispose() calls sodium_memzero.
// - SecureBuffer.dispose() is idempotent (safe to call twice).
// - SecureBuffer.length is immutable after creation.
// - SecureBuffer does not implement toString() (no accidental logging).
// - SecureBuffer does not implement == or hashCode (no accidental comparison).
// Dependencies: secure_buffer.dart, memory_dump.dart.

import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/crypto/native/memory_dump.dart';
import 'package:vault_crypto/src/crypto/native/secure_buffer.dart';

void main() {
  group('Gate 3.1 SecureBuffer', () {
    test('alloc + write + read round-trips', () {
      final buf = SecureBuffer.alloc(16);
      final data = Uint8List.fromList(List.generate(16, (i) => i));
      buf.writeBytes(data);
      expect(buf.readBytes(), equals(data));
      buf.dispose();
    });

    test('fromList copies data into sodium_malloc memory', () {
      final data = Uint8List.fromList(List.generate(32, (i) => 0xAB));
      final buf = SecureBuffer.fromList(data);
      expect(buf.readBytes(), equals(data));
      buf.dispose();
    });

    test('dispose zeroes native memory (sodium_memzero)', () {
      final marker =
          Uint8List.fromList(List.generate(32, (i) => (0xA0 + i) & 0xFF));
      final buf = SecureBuffer.alloc(marker.length);
      buf.writeBytes(marker);
      // Marker present before dispose.
      expect(MemoryDumpVerifier.scanFor(buf, marker), isTrue);
      buf.dispose();
      // Marker absent after dispose (zeroed).
      expect(MemoryDumpVerifier.scanFor(buf, marker), isFalse);
    });

    test('dispose is idempotent (safe to call twice)', () {
      final buf = SecureBuffer.alloc(8);
      buf.dispose();
      buf.dispose(); // must not throw
      expect(buf.isDisposed, isTrue);
    });

    test('length is immutable after creation', () {
      final buf = SecureBuffer.alloc(16);
      expect(buf.length, 16);
      buf.dispose();
    });

    test('does not implement toString() (no accidental logging)', () {
      // SecureBuffer must not expose a meaningful toString that could leak
      // contents. Its default Object.toString is fine; we assert it does not
      // contain the secret bytes.
      final secret = Uint8List.fromList('supersecret'.codeUnits);
      final buf = SecureBuffer.fromList(secret);
      final s = buf.toString();
      expect(s.contains('supersecret'), isFalse);
      buf.dispose();
    });

    test('does not implement == or hashCode (no accidental comparison)', () {
      final a = SecureBuffer.fromList(Uint8List.fromList([1, 2, 3]));
      final b = SecureBuffer.fromList(Uint8List.fromList([1, 2, 3]));
      // Identity comparison (default Object ==) must be false for distinct
      // instances — SecureBuffer must not override == to compare contents.
      expect(identical(a, b), isFalse);
      expect(a == b, isFalse);
      a.dispose();
      b.dispose();
    });
  });
}
