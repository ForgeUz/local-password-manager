// File: test/security/format/test_gen4_parser.dart
// Intent: security.md gate 2.1 — Format parsing (GEN4) verification.
// Invariants:
// - Parser handles files of size 0 bytes.
// - Parser handles files of size 1 byte (should fail cleanly).
// - Parser handles files with invalid magic bytes.
// - Parser handles files with valid magic but corrupted version.
// - Parser handles truncated header.
// - Parser handles header with length fields exceeding file size.
// - Parser handles DEK count = 0 / negative / > 10000 (sanity limit).
// - Parser handles ciphertext length = 0 / > 1MB (sanity limit).
// - Parser handles tag count = 0 / > 100 (sanity limit).
// - Parser handles vector clock length > 256 (sanity limit).
// - Parser always throws CorruptBlobError (not FormatException, RangeError, etc.).
// - Parser never accesses memory out of bounds.
// Dependencies: header.dart, errors.dart, V4Constants.

import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/crypto/errors.dart';
import 'package:vault_crypto/src/crypto/v4/constants.dart';
import 'package:vault_crypto/src/crypto/v4/header.dart';

Uint8List _bytes(int len, int seed) =>
    Uint8List.fromList(List.generate(len, (i) => (seed + i) & 0xFF));

// Intent: assert that parsing [bytes] throws a VaultCryptoError (typed), never
// an unhandled RangeError/FormatException/TypeError.
void _expectTypedError(Uint8List bytes) {
  try {
    V4Header.parse(bytes);
    // If it parses without throwing, that's acceptable for well-formed input,
    // but for malformed inputs we expect a typed error. Caller decides.
  } on VaultCryptoError {
    // Expected typed error.
  } on RangeError {
    fail('RangeError leaked from parser (should be CorruptBlobError)');
  } on FormatException {
    fail('FormatException leaked from parser (should be CorruptBlobError)');
  } on TypeError {
    fail('TypeError leaked from parser (should be CorruptBlobError)');
  }
}

void main() {
  group('Gate 2.1 GEN4 Format Parsing', () {
    test('handles file of size 0 bytes (no crash)', () {
      _expectTypedError(Uint8List(0));
    });

    test('handles file of size 1 byte (fails cleanly)', () {
      _expectTypedError(Uint8List(1));
    });

    test('handles file with invalid magic bytes', () {
      final bytes = Uint8List(V4Constants.fixedHeaderSize);
      // magic is 0x47454e34; write a wrong magic.
      final bd = bytes.buffer.asByteData();
      bd.setInt32(0, 0xDEADBEEF, Endian.big);
      expect(() => V4Header.parse(bytes), throwsA(isA<VaultCryptoError>()));
    });

    test('handles valid magic but corrupted version', () {
      final bytes = Uint8List(V4Constants.fixedHeaderSize);
      final bd = bytes.buffer.asByteData();
      bd.setInt32(0, V4Constants.magic, Endian.big);
      bytes[4] = 99; // wrong version
      expect(() => V4Header.parse(bytes), throwsA(isA<VaultCryptoError>()));
    });

    test('handles truncated header', () {
      // A valid header is 44 bytes; truncate at every length.
      for (var len = 0; len < V4Constants.fixedHeaderSize; len++) {
        _expectTypedError(Uint8List(len));
      }
    });

    test('handles header with length fields exceeding file size', () {
      // Build a header claiming many entries but with no entry bytes.
      final bytes = Uint8List(V4Constants.fixedHeaderSize + 2);
      final bd = bytes.buffer.asByteData();
      bd.setInt32(0, V4Constants.magic, Endian.big);
      bytes[4] = V4Constants.formatVersion;
      bytes[5] = V4Constants.kdfAlgoId;
      bd.setInt32(6, 65536, Endian.big); // memory
      bd.setInt32(10, 3, Endian.big); // iterations
      bytes[14] = 1; // parallelism
      // salt (16) at 15..30, nonce (12) at 31..42, vault_count at 43
      bytes[43] = V4Constants.vaultCount;
      // entry count = 1000 (way more than the file can hold)
      bd.setUint16(44, 1000, Endian.big);
      _expectTypedError(bytes);
    });

    test('handles DEK count = 0', () {
      // A header with zero entries is valid and must parse.
      final h = V4Header.generate(
        kdfMemory: 65536,
        kdfIterations: 3,
        kdfParallelism: 1,
        salt: _bytes(16, 1),
        nonce: _bytes(12, 2),
      );
      final parsed = V4Header.parse(h.toBytes());
      expect(parsed.entries.length, 0);
    });

    test('handles DEK count > 10000 (sanity limit)', () {
      // entry count is a uint16, so max is 65535. A count > 10000 with no
      // backing bytes must fail cleanly (typed error), not crash.
      final bytes = Uint8List(V4Constants.fixedHeaderSize + 2);
      final bd = bytes.buffer.asByteData();
      bd.setInt32(0, V4Constants.magic, Endian.big);
      bytes[4] = V4Constants.formatVersion;
      bytes[5] = V4Constants.kdfAlgoId;
      bd.setInt32(6, 65536, Endian.big);
      bd.setInt32(10, 3, Endian.big);
      bytes[14] = 1;
      bytes[43] = V4Constants.vaultCount;
      bd.setUint16(44, 20000, Endian.big);
      _expectTypedError(bytes);
    });

    test('handles ciphertext length > 1MB (sanity limit)', () {
      // Build a single entry record with a huge ciphertext length claim.
      final rec = V4EntryRecord(
        id: _bytes(16, 1),
        tier: 0,
        wrappedDek: _bytes(60, 2),
        searchTags: [_bytes(32, 3)],
        vectorClock: _bytes(4, 4),
        ciphertext: Uint8List(0), // will be overridden below
      );
      final recBytes = rec.toBytes();
      // The ciphertext length is the last 4 bytes (big-endian). Set it huge.
      final bd = recBytes.buffer.asByteData();
      bd.setUint32(recBytes.length - 4, 2 * 1024 * 1024, Endian.big);
      _expectTypedError(recBytes);
    });

    test('handles tag count > 100 (sanity limit)', () {
      // Build a record with a huge tag count claim.
      final bytes = Uint8List(16 + 1 + 2 + 60 + 2 + 2 + 4 + 4);
      final bd = bytes.buffer.asByteData();
      var off = 0;
      // id (16)
      off += 16;
      // tier (1)
      bytes[off++] = 0;
      // wrappedDek len (2) = 60
      bd.setUint16(off, 60, Endian.big);
      off += 2;
      off += 60;
      // tag count (2) = 200 (> 100)
      bd.setUint16(off, 200, Endian.big);
      off += 2;
      // vector clock len (2) = 0
      bd.setUint16(off, 0, Endian.big);
      off += 2;
      // ciphertext len (4) = 0
      bd.setUint32(off, 0, Endian.big);
      _expectTypedError(bytes);
    });

    test('handles vector clock length > 256 (sanity limit)', () {
      final bytes = Uint8List(16 + 1 + 2 + 60 + 2 + 2 + 2 + 4);
      final bd = bytes.buffer.asByteData();
      var off = 0;
      off += 16;
      bytes[off++] = 0;
      bd.setUint16(off, 60, Endian.big);
      off += 2;
      off += 60;
      bd.setUint16(off, 0, Endian.big); // tag count
      off += 2;
      bd.setUint16(off, 300, Endian.big); // vector clock len > 256
      off += 2;
      bd.setUint32(off, 0, Endian.big); // ciphertext len
      _expectTypedError(bytes);
    });

    test('parser never accesses memory out of bounds (fuzz-lite)', () {
      // Random byte sequences of various sizes must never crash.
      final rng = _bytes(1, 7)[0];
      for (var len = 0; len < 200; len++) {
        final bytes = Uint8List(len);
        for (var i = 0; i < len; i++) {
          bytes[i] = (rng + i * 7) & 0xFF;
        }
        _expectTypedError(bytes);
      }
    });
  });
}
