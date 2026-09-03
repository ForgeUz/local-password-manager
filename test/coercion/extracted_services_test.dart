import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/backup/csv_service.dart';
import 'package:vault_crypto/src/coercion/canary_service.dart';
import 'package:vault_crypto/src/coercion/decoy_service.dart';
import 'package:vault_crypto/src/crypto/native/secure_buffer.dart';
import 'package:vault_crypto/src/crypto/v4/vault_crypto_v4.dart';
import 'package:vault_crypto/src/security/recovery_service.dart';

// Intent: Phase 2.5 god-class split — verify the extracted services preserve
// the invariants that used to live in VaultService. Each extracted module has
// its own test file (one module = one security boundary = one test file).
void main() {
  group('CanaryService', () {
    test('generates 3 canaries marked isCanary', () {
      final canaries = CanaryService.generate();
      expect(canaries.length, 3);
      expect(canaries.every((e) => e.isCanary), isTrue);
    });

    test('no forbidden words leak into user-visible fields', () {
      final canaries = CanaryService.generate();
      const forbidden = ['canary', 'decoy', 'fake', 'dummy', 'test', 'example', 'bunker'];
      for (final c in canaries) {
        final visible = '${c.title}${c.username}${c.domain}'.toLowerCase();
        for (final w in forbidden) {
          expect(visible.contains(w), isFalse,
              reason: 'canary field must not contain "$w"');
        }
      }
    });
  });

  group('CsvService', () {
    test('parseImport maps rows to entries and skips empty', () {
      final entries = CsvService.parseImport(
          'name,username,password\nGoogle,u,p\nGithub,d,s\n,,\n');
      expect(entries.length, 2);
      expect(entries[0].title, 'Google');
      expect(entries[1].title, 'Github');
    });

    test('buildExport neutralizes formula injection', () {
      final csv = CsvService.buildExport([
        V4VaultEntry(
          id: '1',
          title: '=SUM(A1)',
          username: 'u',
          password: 'p',
          url: 'x.com',
          domain: 'x.com',
          tier: 0,
        ),
      ]);
      expect(csv, contains("'=SUM(A1)"));
    });

    test('buildExport excludes canaries', () {
      final csv = CsvService.buildExport([
        V4VaultEntry(
          id: '1',
          title: 'Real',
          username: 'u',
          password: 'p',
          url: 'x.com',
          domain: 'x.com',
          tier: 0,
        ),
        V4VaultEntry(
          id: 'c1',
          title: 'Canary',
          username: 'u',
          password: 'p',
          url: 'x.com',
          domain: 'x.com',
          tier: 0,
          isCanary: true,
        ),
      ]);
      expect(csv, contains('Real'));
      expect(csv, isNot(contains('Canary')));
    });
  });

  group('DecoyService', () {
    test('buildDecoyJson encodes entries', () {
      final json = DecoyService.buildDecoyJson([
        V4VaultEntry(
          id: 'd1',
          title: 'Old Email',
          username: 'a@b.c',
          password: 'low',
          url: 'mail.example.com',
          domain: 'mail.example.com',
          tier: 0,
        ),
      ]);
      final s = String.fromCharCodes(json);
      expect(s, contains('Old Email'));
      expect(s, contains('d1'));
    });
  });

  group('RecoveryService', () {
    test('generateShares returns N shares; reconstruct recovers MK', () async {
      // Build a minimal blob via VaultCryptoV4 to get a real header/salt.
      final crypto = VaultCryptoV4();
      final mp = SecureBuffer.fromList(Uint8List.fromList('right'.codeUnits));
      final blob = await crypto.lockVault(
          Uint8List.fromList('{"entries":[]}'.codeUnits), mp);
      final shares = await RecoveryService.generateShares(blob, mp, n: 5, k: 3);
      expect(shares.length, 5);
      final parsed = shares.sublist(0, 3)
          .map((s) => RecoveryService.parseShare(s))
          .toList();
      final mk = RecoveryService.reconstruct(parsed);
      expect(mk.length, 32);
      mk.fillRange(0, mk.length, 0);
    });
  });
}