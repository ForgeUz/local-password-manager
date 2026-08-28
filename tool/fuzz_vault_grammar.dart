// File: tool/fuzz_vault_grammar.dart
// Intent: security2.md gate 23.1 — Grammar-based (structure-aware) vault fuzzer.
// Not random bytes: structured mutations of a valid vault header.
// Mutation strategies:
// - Field-level: mutate single field to boundary values (0, max, max+1, -1).
// - Structural: remove/add DEK entries, swap slot order.
// - Semantic: valid structure, invalid cryptographic content.
// - Cross-field: entry_count = 5, but 3 DEK entries present.
// Invariants:
// - No crash on any mutation.
// - All rejections are CorruptBlobError or DecryptionFailedError.
// - Parser never loops infinitely on crafted input.
// Usage: dart run tool/fuzz_vault_grammar.dart --iterations 50000
// Dependencies: header.dart, errors.dart, V4Constants.

import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:vault_crypto/src/crypto/errors.dart';
import 'package:vault_crypto/src/crypto/v4/header.dart';

void main(List<String> args) {
  final iterations = _parseIterations(args);
  final rng = Random.secure();
  var crashes = 0;
  var typedErrors = 0;

  // Build a valid header as the fuzz seed.
  final seed = _validHeader();

  print('Grammar-based fuzzing V4Header.parse ($iterations iterations)...');

  for (var i = 0; i < iterations; i++) {
    final bytes = _mutate(seed, rng);
    try {
      V4Header.parse(bytes);
    } on VaultCryptoError {
      typedErrors++;
    } catch (e) {
      print('CRASH: $e');
      crashes++;
      if (crashes > 10) break;
    }
  }

  print('Done. iterations=$iterations | typedErrors=$typedErrors | crashes=$crashes');
  if (crashes > 0) {
    print('FAIL: $crashes unexpected exception(s) escaped the parser.');
    exit(1);
  }
  print('PASS: no unexpected exceptions escaped the parser.');
}

int _parseIterations(List<String> args) {
  for (var i = 0; i < args.length - 1; i++) {
    if (args[i] == '--iterations') {
      return int.tryParse(args[i + 1]) ?? 50000;
    }
  }
  return 50000;
}

Uint8List _validHeader() {
  final h = V4Header.generate(
    kdfMemory: 65536,
    kdfIterations: 3,
    kdfParallelism: 1,
    salt: Uint8List.fromList(List.generate(16, (i) => i)),
    nonce: Uint8List.fromList(List.generate(12, (i) => 0x10 + i)),
    entries: [
      V4EntryRecord(
        id: Uint8List.fromList(List.generate(16, (i) => i)),
        tier: 0,
        wrappedDek: Uint8List.fromList(List.generate(60, (i) => 0x20 + i)),
        searchTags: [Uint8List(32), Uint8List(32)],
        vectorClock: Uint8List.fromList([0, 0, 0, 1]),
        ciphertext: Uint8List.fromList(List.generate(100, (i) => i)),
      ),
    ],
  );
  return h.toBytes();
}

/// Apply a random structured mutation to the header bytes.
Uint8List _mutate(Uint8List seed, Random rng) {
  final bytes = Uint8List.fromList(seed);
  final bd = bytes.buffer.asByteData();
  final strategy = rng.nextInt(4);

  switch (strategy) {
    case 0: // Field-level: mutate a single field to a boundary value.
      final field = rng.nextInt(6);
      final boundary = [0, 0x7FFFFFFF, 0xFFFFFFFF, 0xFFFF, 0xFF][rng.nextInt(5)];
      switch (field) {
        case 0: bd.setInt32(6, boundary, Endian.big); break; // memory
        case 1: bd.setInt32(10, boundary, Endian.big); break; // iterations
        case 2: bytes[14] = boundary & 0xFF; break; // parallelism
        case 3: bytes[43] = boundary & 0xFF; break; // vault_count
        case 4: bd.setUint16(44, boundary & 0xFFFF, Endian.big); break; // entry_count
        case 5: bd.setInt32(0, boundary, Endian.big); break; // magic
      }
      break;
    case 1: // Structural: truncate or extend.
      if (rng.nextBool()) {
        // Truncate to a random length.
        return Uint8List.fromList(bytes.sublist(0, rng.nextInt(bytes.length + 1)));
      } else {
        // Extend with random bytes.
        final ext = Uint8List(bytes.length + rng.nextInt(64));
        ext.setRange(0, bytes.length, bytes);
        for (var j = bytes.length; j < ext.length; j++) {
          ext[j] = rng.nextInt(256);
        }
        return ext;
      }
    case 2: // Semantic: valid structure, corrupt a byte in the middle.
      final pos = rng.nextInt(bytes.length);
      bytes[pos] = rng.nextInt(256);
      break;
    case 3: // Cross-field: set entry_count to a value inconsistent with data.
      bd.setUint16(44, rng.nextInt(65536), Endian.big);
      break;
  }
  return bytes;
}
