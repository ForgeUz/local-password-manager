import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/screens/decoy_setup_screen.dart';
import 'package:vault_crypto/src/app/vault_service.dart';

// Intent: v5 — fake entries (canaries + secondary-vault decoys) must look like
// real accounts. NO forbidden words (decoy/fake/dummy/test/example/bunker/
// canary) in any user-visible field, or a coercer sees the mechanism and
// plausible deniability is destroyed.
void main() {
  group('decoy data sanitization', () {
    test('canaries have no forbidden substrings in any field', () {
      final canaries = VaultService.generateCanariesForTest();
      expect(canaries.length, 3);
      for (final e in canaries) {
        final blob =
            '${e.title} ${e.username} ${e.password} ${e.url} ${e.domain}'
                .toLowerCase();
        for (final w in const [
          'decoy',
          'fake',
          'dummy',
          'test',
          'example',
          'bunker',
          'canary'
        ]) {
          expect(blob.contains(w), isFalse,
              reason: 'forbidden word "$w" in $blob');
        }
      }
    });

    test('secondary-vault entries have no forbidden substrings', () {
      final entries = DecoySetupScreen.secondaryEntriesForTest();
      expect(entries.length, 8);
      for (final e in entries) {
        final blob =
            '${e.title} ${e.username} ${e.password} ${e.url} ${e.domain}'
                .toLowerCase();
        for (final w in _forbidden) {
          expect(blob.contains(w), isFalse,
              reason: 'forbidden word "$w" in $blob');
        }
      }
    });
  });
}

const _forbidden = [
  'decoy',
  'fake',
  'dummy',
  'test',
  'example',
  'bunker',
  'canary'
];
