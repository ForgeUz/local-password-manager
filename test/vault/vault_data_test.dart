import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/vault/vault_data.dart';

void main() {
  test('VaultData serializes to JSON and back correctly', () {
    final original = VaultData(entries: [
      VaultEntry(id: '1', title: 'Google', username: 'user@g.com', password: 'pass123', url: 'google.com'),
    ]);

    final jsonBytes = original.toJsonBytes();
    final decoded = VaultData.fromJsonBytes(jsonBytes);

    expect(decoded.entries.length, 1);
    expect(decoded.entries.first.title, 'Google');
    expect(decoded.entries.first.password, 'pass123');
  });

  test('Empty VaultData serializes correctly', () {
    final original = VaultData(entries: []);
    final jsonBytes = original.toJsonBytes();
    final decoded = VaultData.fromJsonBytes(jsonBytes);

    expect(decoded.entries.isEmpty, isTrue);
  });
}