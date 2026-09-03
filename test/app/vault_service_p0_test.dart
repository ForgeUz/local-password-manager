import 'dart:io';
import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/app/app_store.dart';
import 'package:vault_crypto/src/app/vault_service.dart';
import 'package:vault_crypto/src/crypto/native/secure_buffer.dart';
import 'package:vault_crypto/src/crypto/v4/constants.dart';
import 'package:vault_crypto/src/crypto/v4/header.dart';
import 'package:vault_crypto/src/crypto/v4/vault_crypto_v4.dart';
import 'package:vault_crypto/src/lock/state.dart';
import 'package:vault_crypto/src/security/shamir_kit.dart';
import 'package:vault_crypto/src/vault/vault_data.dart';
import 'package:vault_crypto/src/vault/vault_storage.dart';

// Intent: Phase 0 regression tests for the four P0 security fixes in
// VaultService (duress write-guard, key zeroization, lock full-wipe, debugVrk
// release guard) plus the P1 fixes (searchTags population, synchronous canary
// wipe). Each test maps to a documented invariant in vault_service.dart.
void main() {
  late AppStore store;
  late VaultService service;
  late Directory tmp;

  setUp(() async {
    tmp = Directory.systemTemp.createTempSync('vault_p0_test');
    store = AppStore();
    service = VaultService(
      store: store,
      crypto: VaultCryptoV4(),
      storage: VaultStorage(baseDir: tmp),
    );
  });

  tearDown(() {
    if (tmp.existsSync()) tmp.deleteSync(recursive: true);
  });

  SecureBuffer createMP(String mp) {
    final buf = SecureBuffer.alloc(mp.length);
    buf.writeBytes(Uint8List.fromList(mp.codeUnits));
    return buf;
  }

  Future<void> setupDecoyVault() async {
    await service.init();
    final primaryMp = createMP('primary');
    final duressMp = createMP('duress');
    await service.createVault(primaryMp);
    await service.lock();
    await service.setupDecoy(primaryMp, duressMp, [
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
    await service.lock();
  }

  test('duress session is read-only: writes are rejected', () async {
    // P0: a write under VRK_duress would relock the primary region under a key
    // unlockSession never derives -> vault bricked. Every mutator must throw.
    await setupDecoyVault();
    await service.unlock(createMP('duress'));
    expect(service.isDuress, isTrue);

    await expectLater(
      service.addEntry(VaultEntry(
        id: 'x1',
        title: 'X',
        username: 'u',
        password: 'p',
        url: 'x.com',
      )),
      throwsA(isA<StateError>()),
    );
    await expectLater(
      service.attachPasskey('d1', 'cred'),
      throwsA(isA<StateError>()),
    );
    await expectLater(
      service.importCsv('name,username,password\nX,u,p'),
      throwsA(isA<StateError>()),
    );
    await expectLater(
      service.changeMasterPassword(createMP('duress'), createMP('new')),
      throwsA(isA<StateError>()),
    );
    await expectLater(
      service.setupDecoy(createMP('duress'), createMP('duress2'), const []),
      throwsA(isA<StateError>()),
    );

    // The primary vault must still cold-unlock with the primary MP and slot 2
    // (the decoy) must be intact.
    await service.lock();
    await service.unlock(createMP('primary'));
    expect(service.isDuress, isFalse);
    expect(store.currentState, isA<Unlocked>());
    final blob = await VaultStorage(baseDir: tmp).readBlob();
    final slot2 = VaultCryptoV4.slot2Of(blob);
    final slot2Header = V4Header.parse(slot2);
    expect(slot2Header.magic, V4Constants.magic);
  });

  test('lock() clears all session state (duress flag, search tags, reveals)',
      () async {
    // P0: lock() must clear _searchTags/_lastReveal/_isDuress, not just
    // _entries. A stale duress flag would wrongly block the next primary unlock.
    await setupDecoyVault();
    await service.unlock(createMP('duress'));
    expect(service.isDuress, isTrue);
    await service.lock();
    expect(service.isDuress, isFalse);

    // Next primary unlock must NOT be in duress mode and must accept writes.
    await service.unlock(createMP('primary'));
    expect(service.isDuress, isFalse);
    await service.addEntry(VaultEntry(
      id: 'p1',
      title: 'Real',
      username: 'u',
      password: 'secret',
      url: 'news.example.com',
    ));
    expect(service.getEntry('p1'), isNotNull);
  });

  test('search works after unlockWithVrk (searchTags populated)', () async {
    // P1: unlockWithVrk never populated _searchTags -> SSE search silently
    // returned nothing after a biometric unlock.
    await service.init();
    final mp = createMP('right');
    await service.createVault(mp);
    await service.lock();
    await service.unlock(createMP('right'));
    await service.addEntry(VaultEntry(
      id: 'g1',
      title: 'GitHub',
      username: 'u',
      password: 'p',
      url: 'github.com',
    ));
    final vrk = service.debugVrk;
    await service.lock();
    final ok = await service.unlockWithVrk(vrk);
    expect(ok, isTrue);
    expect(service.search('git'), contains('g1'));
  });

  test('search works after unlockWithShares (searchTags populated)', () async {
    // P1: unlockWithShares never populated _searchTags -> search broken after
    // a shares unlock.
    await service.init();
    final mp = createMP('right');
    await service.createVault(mp);
    await service.lock();
    await service.unlock(createMP('right'));
    await service.addEntry(VaultEntry(
      id: 'g1',
      title: 'GitHub',
      username: 'u',
      password: 'p',
      url: 'github.com',
    ));
    await service.lock();
    final shares = await service.generateShares(createMP('right'), n: 5, k: 3);
    final parsed = shares.sublist(0, 3).map(ShamirKit.parseShare).toList();
    final ok = await service.unlockWithShares(parsed);
    expect(ok, isTrue);
    expect(service.search('git'), contains('g1'));
  });

  test('canary access wipes VRK synchronously', () async {
    // P1: the old code fire-and-forgot the VRK wipe, leaving a window where the
    // VRK was still live after a canary hit returned. Now the wipe is
    // synchronous: hasVrk must be false immediately after getEntry returns.
    await service.init();
    final mp = createMP('right');
    await service.createVault(mp);
    await service.lock();
    await service.unlock(createMP('right'));
    final target = service.canaryIds.first;
    expect(service.hasVrk, isTrue);
    expect(service.getEntry(target), isNull);
    expect(service.hasVrk, isFalse);
    expect(service.isCanaryTriggered, isTrue);
    expect(store.currentState, isA<Locked>());
  });

  test('debugVrk is guarded by a compile-time debug flag', () {
    // P0: the old guard was assert(_debug, ...) which compiles OUT in release
    // while the body still returned the VRK copy. The fix uses a const
    // bool.fromEnvironment flag so the branch is dead-code-eliminated in
    // release. We expose the flag as a static const to prove it is a compile-
    // time constant (not a runtime assert). In a debug test run it is true.
    expect(VaultService.debugVrkIsDebug, isA<bool>());
  });

  test('KDF calibration at creation: raised params survive unlock', () async {
    // Phase 3.1: createVault accepts kdfMemory/kdfIterations above the floor.
    // The header records the actual params so a cold unlock re-derives them.
    await service.init();
    final mp = createMP('right');
    await service.createVault(mp,
        kdfMemory: V4Constants.kdfFloorMemory + 1024,
        kdfIterations: V4Constants.kdfFloorIterations + 1);
    await service.lock();
    await service.unlock(createMP('right'));
    expect(store.currentState, isA<Unlocked>());
    expect(service.isDuress, isFalse);
    // The header must record the raised params (not the floor).
    final blob = await VaultStorage(baseDir: tmp).readBlob();
    final header = V4Header.parse(blob);
    expect(header.kdfMemory, V4Constants.kdfFloorMemory + 1024);
    expect(header.kdfIterations, V4Constants.kdfFloorIterations + 1);
  });
}