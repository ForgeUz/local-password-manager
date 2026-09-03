import 'dart:io';
import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/vault/vault_storage.dart';

void main() {
  late Directory tempDir;
  late VaultStorage storage;

  setUp(() {
    tempDir = Directory.systemTemp.createTempSync('storage_test');
    storage = VaultStorage(baseDir: tempDir);
  });

  tearDown(() {
    if (tempDir.existsSync()) tempDir.deleteSync(recursive: true);
  });

  test('vaultExists returns false initially', () async {
    expect(await storage.vaultExists(), isFalse);
  });

  test('writeBlob creates file and vaultExists returns true', () async {
    await storage.writeBlob(Uint8List.fromList([1, 2, 3]));
    expect(await storage.vaultExists(), isTrue);

    final read = await storage.readBlob();
    expect(read, equals(Uint8List.fromList([1, 2, 3])));
  });
}
