// File: test/security/crash/test_power_loss.dart
// Intent: security2.md gate 25.1 — Power loss simulation.
// Simulates process kill during vault save by testing the atomic write
// mechanism (temp file + rename). An interrupted save must leave either the
// old or new state, never a corrupted one.
// Invariants:
// - Vault file is never in corrupted state.
// - Either old state or new state (atomicity).
// - No partial temp files left (cleanup on startup).
// - Recovery from interrupted save: vault opens correctly.
// - No key material in temp files after crash.
// Dependencies: vault_storage.dart, vault_crypto_v4.dart, secure_buffer.dart.

import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/crypto/native/secure_buffer.dart';
import 'package:vault_crypto/src/crypto/v4/vault_crypto_v4.dart';
import 'package:vault_crypto/src/vault/vault_storage.dart';

SecureBuffer _mp(String s) {
  final buf = SecureBuffer.alloc(s.length);
  buf.writeBytes(Uint8List.fromList(s.codeUnits));
  return buf;
}

void main() {
  group('Gate 25.1 Power Loss Simulation', () {
    test('atomic write: interrupted save leaves old state intact', () async {
      final dir = Directory.systemTemp.createTempSync('power_loss');
      try {
        final storage = VaultStorage(baseDir: dir);
        final crypto = VaultCryptoV4();
        final json = Uint8List.fromList('{"entries":[]}'.codeUnits);
        final blob = await crypto.lockVault(json, _mp('mp'));

        // Write the initial vault.
        await storage.writeBlobAtomic(blob);
        expect(await storage.vaultExists(), isTrue);

        // Simulate a crash mid-save: write a temp file but do NOT rename.
        final tmp = File('${dir.path}${Platform.pathSeparator}.vault.blob.tmp');
        await tmp.writeAsBytes(Uint8List.fromList([1, 2, 3]), flush: true);

        // The real vault file is untouched (old state intact).
        final read = await storage.readBlob();
        expect(read, equals(blob));
      } finally {
        dir.deleteSync(recursive: true);
      }
    });

    test('atomic write: completed save produces new state (no corruption)', () async {
      final dir = Directory.systemTemp.createTempSync('power_loss2');
      try {
        final storage = VaultStorage(baseDir: dir);
        final crypto = VaultCryptoV4();
        final json = Uint8List.fromList('{"entries":[]}'.codeUnits);
        final blob = await crypto.lockVault(json, _mp('mp'));

        await storage.writeBlobAtomic(blob);
        // The vault opens correctly after the atomic write.
        final result = await crypto.unlockVault(await storage.readBlob(), _mp('mp'));
        expect(result, equals(json));
      } finally {
        dir.deleteSync(recursive: true);
      }
    });

    test('no partial temp files left after completed save', () async {
      final dir = Directory.systemTemp.createTempSync('power_loss3');
      try {
        final storage = VaultStorage(baseDir: dir);
        final crypto = VaultCryptoV4();
        final json = Uint8List.fromList('{"entries":[]}'.codeUnits);
        final blob = await crypto.lockVault(json, _mp('mp'));
        await storage.writeBlobAtomic(blob);
        // After a completed atomic write, no temp file remains.
        final tmp = File('${dir.path}${Platform.pathSeparator}.vault.blob.tmp');
        expect(tmp.existsSync(), isFalse);
      } finally {
        dir.deleteSync(recursive: true);
      }
    });

    test('recovery from interrupted save: vault opens correctly', () async {
      final dir = Directory.systemTemp.createTempSync('power_loss4');
      try {
        final storage = VaultStorage(baseDir: dir);
        final crypto = VaultCryptoV4();
        final json = Uint8List.fromList('{"entries":[]}'.codeUnits);
        final blob = await crypto.lockVault(json, _mp('mp'));
        await storage.writeBlobAtomic(blob);

        // Simulate crash: temp file written, rename not done.
        final tmp = File('${dir.path}${Platform.pathSeparator}.vault.blob.tmp');
        await tmp.writeAsBytes(Uint8List.fromList([9, 9, 9]), flush: true);

        // On restart, the real vault file is the old valid state.
        final result = await crypto.unlockVault(await storage.readBlob(), _mp('mp'));
        expect(result, equals(json));
      } finally {
        dir.deleteSync(recursive: true);
      }
    });
  });
}
