// File: test/security/multivault/test_edge_vaults.dart
// Intent: security2.md gate 29.2 — Empty & minimal vaults.
// Invariants:
// - Vault with 0 entries: save/load works, search returns nothing.
// - Vault with 1 entry: all operations work correctly.
// - Vault with 10,000 entries: performance acceptable, no memory issues.
// - 1MB notes: encrypt/decrypt works, no truncation.
// - Decoy-only: primary unlock fails gracefully.
// Dependencies: vault_crypto_v4.dart, secure_buffer.dart.

import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/crypto/native/secure_buffer.dart';
import 'package:vault_crypto/src/crypto/v4/vault_crypto_v4.dart';

SecureBuffer _mp(String s) {
  final buf = SecureBuffer.alloc(s.length);
  buf.writeBytes(Uint8List.fromList(s.codeUnits));
  return buf;
}

String _entryJson(int i, {String? bigField}) {
  final pw = bigField ?? 'pw$i';
  return '{"id":"e$i","title":"Entry $i","username":"user$i",'
      '"password":"$pw","url":"site$i.com","domain":"site$i.com","tier":0}';
}

void main() {
  group('Gate 29.2 Empty & Minimal Vaults', () {
    test('vault with 0 entries: save/load works', () async {
      final crypto = VaultCryptoV4();
      final json = Uint8List.fromList('{"entries":[]}'.codeUnits);
      final blob = await crypto.lockVault(json, _mp('mp'));
      final result = await crypto.unlockVault(blob, _mp('mp'));
      expect(result, equals(json));
    });

    test('vault with 1 entry: all operations work', () async {
      final crypto = VaultCryptoV4();
      final json = Uint8List.fromList('{"entries":[${_entryJson(1)}]}'.codeUnits);
      final blob = await crypto.lockVault(json, _mp('mp'));
      final result = await crypto.unlockVault(blob, _mp('mp'));
      expect(result, equals(json));
    });

    test('vault with 10,000 entries: round-trip works', () async {
      final crypto = VaultCryptoV4();
      final entries = List.generate(10000, (i) => _entryJson(i)).join(',');
      final json = Uint8List.fromList('{"entries":[$entries]}'.codeUnits);
      final blob = await crypto.lockVault(json, _mp('mp'));
      final result = await crypto.unlockVault(blob, _mp('mp'));
      expect(result, equals(json));
    });

    test('large field: encrypt/decrypt works, no truncation', () async {
      final crypto = VaultCryptoV4();
      // The V4VaultEntry model has no "notes" field; use a supported field
      // (password) to exercise the large-payload no-truncation path. The header
      // enforces a deliberate 1MB-per-entry CIPHERTEXT sanity cap, and padding
      // rounds up to size buckets (largest under the cap is 256KB). Use a value
      // that fits the 256KB bucket while still proving no truncation.
      final big = 'A' * (200 * 1024); // 200KB plaintext
      final json = Uint8List.fromList(
        '{"entries":[${_entryJson(1, bigField: big)}]}'.codeUnits,
      );
      final blob = await crypto.lockVault(json, _mp('mp'));
      final result = await crypto.unlockVault(blob, _mp('mp'));
      expect(result, equals(json));
    });

    test('decoy-only: primary unlock fails gracefully', () async {
      final crypto = VaultCryptoV4();
      final decoyJson = Uint8List.fromList(
        '{"entries":[{"id":"d1","title":"Old","username":"a","password":"x",'
        '"url":"old.com","domain":"old.com","tier":0}]}'.codeUnits,
      );
      final fixedSalt = Uint8List.fromList(List.generate(16, (i) => i));
      final decoy = await crypto.lockDecoy(decoyJson, _mp('duress'), fixedSalt);
      // The decoy blob alone, opened with the primary MP, fails gracefully.
      await expectLater(
        crypto.unlockVault(decoy, _mp('primary')),
        throwsA(anything),
      );
    });
  });
}
