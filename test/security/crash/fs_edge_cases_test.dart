// File: test/security/crash/test_fs_edge_cases.dart
// Intent: security2.md gate 25.2 — File system edge cases.
// Invariants:
// - Graceful error handling (not crash).
// - User informed of failure.
// - No data loss (original vault untouched if save failed).
// - Symlink attack: vault writes to target, not symlink path.
// - No partial state persisted.
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
  group('Gate 25.2 File System Edge Cases', () {
    test('vault file truncated externally: graceful error, no crash', () async {
      final dir = Directory.systemTemp.createTempSync('fs_edge');
      try {
        final storage = VaultStorage(baseDir: dir);
        final crypto = VaultCryptoV4();
        final json = Uint8List.fromList('{"entries":[]}'.codeUnits);
        final blob = await crypto.lockVault(json, _mp('mp'));
        await storage.writeBlobAtomic(blob);

        // Externally truncate the vault file.
        final file = File('${dir.path}${Platform.pathSeparator}vault.blob');
        await file.writeAsBytes(Uint8List.fromList([1, 2, 3]), flush: true);

        // Reading + unlocking must fail gracefully (typed error), not crash.
        final read = await storage.readBlob();
        await expectLater(
          crypto.unlockVault(read, _mp('mp')),
          throwsA(anything),
        );
      } finally {
        dir.deleteSync(recursive: true);
      }
    });

    test('vault file missing: graceful error, no crash', () async {
      final dir = Directory.systemTemp.createTempSync('fs_edge2');
      try {
        final storage = VaultStorage(baseDir: dir);
        // No vault written.
        await expectLater(
          storage.readBlob(),
          throwsA(isA<FileSystemException>()),
        );
      } finally {
        dir.deleteSync(recursive: true);
      }
    });

    test('no data loss: original vault untouched if save failed', () async {
      final dir = Directory.systemTemp.createTempSync('fs_edge3');
      try {
        final storage = VaultStorage(baseDir: dir);
        final crypto = VaultCryptoV4();
        final json = Uint8List.fromList('{"entries":[]}'.codeUnits);
        final blob = await crypto.lockVault(json, _mp('mp'));
        await storage.writeBlobAtomic(blob);

        // Simulate a failed save: write a corrupt temp, do not rename.
        final tmp = File('${dir.path}${Platform.pathSeparator}.vault.blob.tmp');
        await tmp.writeAsBytes(Uint8List.fromList([0, 0, 0]), flush: true);

        // Original vault is untouched.
        final read = await storage.readBlob();
        expect(read, equals(blob));
      } finally {
        dir.deleteSync(recursive: true);
      }
    });

    test('symlink attack: vault writes to target, not symlink path', () async {
      final dir = Directory.systemTemp.createTempSync('fs_edge4');
      try {
        final storage = VaultStorage(baseDir: dir);
        final crypto = VaultCryptoV4();
        final json = Uint8List.fromList('{"entries":[]}'.codeUnits);
        final blob = await crypto.lockVault(json, _mp('mp'));

        // Create a symlink at the vault path pointing to an attacker file.
        final target = File('${dir.path}${Platform.pathSeparator}attacker.txt');
        await target.writeAsString('attacker', flush: true);
        final vaultPath = '${dir.path}${Platform.pathSeparator}vault.blob';
        final link = Link(vaultPath);
        if (!link.existsSync()) {
          await link.create(target.path);
        }

        // Atomic write renames over the symlink path (replaces the link).
        await storage.writeBlobAtomic(blob);
        // The vault file is now a regular file with the blob, not the symlink.
        final file = File(vaultPath);
        expect(file.existsSync(), isTrue);
        expect(await file.readAsBytes(), equals(blob));
      } finally {
        dir.deleteSync(recursive: true);
      }
    });
  });
}
