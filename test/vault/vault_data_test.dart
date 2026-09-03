// File: test/vault/vault_data_test.dart
// Intent: Kill-tests for VaultEntry/VaultData JSON serialization (M121-M123).
// Invariants:
// - passkeyCredentialId is serialized when present.
// - Legacy V4 blobs (missing passkeyCredentialId) parse safely as null.
// - VaultData round-trips entries correctly without dropping them.

import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/vault/vault_data.dart';

void main() {
  group('M121: VaultEntry serializes passkeyCredentialId', () {
    test('toJson includes passkeyCredentialId when present', () {
      final entry = VaultEntry(
        id: '1',
        title: 'GitHub',
        username: 'user',
        password: 'pass',
        url: 'github.com',
        passkeyCredentialId: 'base64url_cred_id',
      );
      final json = entry.toJson();
      expect(json['passkeyCredentialId'], equals('base64url_cred_id'));
    });

    test('toJson includes null passkeyCredentialId when absent', () {
      final entry = VaultEntry(
        id: '2',
        title: 'Reddit',
        username: 'user2',
        password: 'pass2',
        url: 'reddit.com',
      );
      final json = entry.toJson();
      expect(json.containsKey('passkeyCredentialId'), isTrue);
      expect(json['passkeyCredentialId'], isNull);
    });
  });

  group('M122: VaultEntry parses legacy V4 blobs safely', () {
    test('fromJson handles missing passkeyCredentialId key', () {
      final legacyJson = {
        'id': '3',
        'title': 'Netflix',
        'username': 'user3',
        'password': 'pass3',
        'url': 'netflix.com',
      };
      final entry = VaultEntry.fromJson(legacyJson);
      expect(entry.id, equals('3'));
      expect(entry.passkeyCredentialId, isNull);
    });
  });

  group('M123: VaultData round-trips entries correctly', () {
    test('toJsonBytes and fromJsonBytes preserve all entries', () {
      final entries = [
        VaultEntry(
            id: '1', title: 'A', username: 'u', password: 'p', url: 'a.com'),
        VaultEntry(
          id: '2',
          title: 'B',
          username: 'u',
          password: 'p',
          url: 'b.com',
          passkeyCredentialId: 'cred_2',
        ),
      ];
      final data = VaultData(entries: entries);
      final bytes = data.toJsonBytes();

      final restored = VaultData.fromJsonBytes(bytes);
      expect(restored.entries.length, equals(2));
      expect(restored.entries[0].passkeyCredentialId, isNull);
      expect(restored.entries[1].passkeyCredentialId, equals('cred_2'));
    });
  });
}
