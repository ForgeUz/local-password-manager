import 'dart:io';
import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/app/app_store.dart';
import 'package:vault_crypto/src/app/vault_service.dart';
import 'package:vault_crypto/src/crypto/native/secure_buffer.dart';
import 'package:vault_crypto/src/crypto/v4/vault_crypto_v4.dart';
import 'package:vault_crypto/src/lock/state.dart';
import 'package:vault_crypto/src/vault/vault_storage.dart';

// Intent: startup existence + integrity gate (v5). Missing blob -> SetupRequired
// (SetupScreen). Corrupt/foreign blob -> BlobCorrupt (CorruptScreen with reset).
void main() {
  late Directory dir;

  setUp(() {
    dir = Directory.systemTemp.createTempSync('init_flow_');
  });

  tearDown(() {
    if (dir.existsSync()) dir.deleteSync(recursive: true);
  });

  AppStore store() => AppStore();
  VaultService service(AppStore st, VaultStorage s) =>
      VaultService(store: st, crypto: VaultCryptoV4(), storage: s);

  test('missing vault -> SetupRequired (routes to SetupScreen)', () async {
    final st = store();
    final svc = service(st, VaultStorage(baseDir: dir));
    await svc.init();
    expect(st.currentState, isA<SetupRequired>());
  });

  test('corrupt/foreign blob -> BlobCorrupt (CorruptScreen with reset)', () async {
    final st = store();
    final storage = VaultStorage(baseDir: dir);
    final svc = service(st, storage);
    // Not a GEN4 payload: an old V3 leftover or truncated file.
    await storage.writeBlob(Uint8List.fromList(List.generate(64, (i) => i)));
    await svc.init();
    expect(st.currentState, isA<BlobCorrupt>());
    // Reset path: delete + route to SetupRequired.
    await svc.resetVault();
    expect(st.currentState, isA<SetupRequired>());
    expect(await storage.vaultExists(), isFalse);
  });

  test('valid vault blob -> Locked (normal lock screen)', () async {
    final st = store();
    final storage = VaultStorage(baseDir: dir);
    final svc = service(st, storage);
    // Create a real vault through the service (writes a valid GEN4 blob).
    final mp = SecureBuffer.alloc(2);
    mp.writeBytes(Uint8List.fromList('mp'.codeUnits));
    await svc.createVault(mp);
    // Fresh service re-inits from disk -> Locked, not corrupt.
    final st2 = store();
    final svc2 = service(st2, storage);
    await svc2.init();
    expect(st2.currentState, isA<Locked>());
  });
}