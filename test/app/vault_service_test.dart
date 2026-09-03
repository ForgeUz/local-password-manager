import 'dart:io';
import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/app/app_store.dart';
import 'package:vault_crypto/src/app/vault_service.dart';
import 'package:vault_crypto/src/crypto/native/argon2id.dart';
import 'package:vault_crypto/src/crypto/native/secure_buffer.dart';
import 'package:vault_crypto/src/crypto/v4/constants.dart';
import 'package:vault_crypto/src/crypto/v4/header.dart';
import 'package:vault_crypto/src/crypto/v4/vault_crypto_v4.dart';
import 'package:vault_crypto/src/security/shamir_kit.dart';
import 'package:vault_crypto/src/lock/state.dart';
import 'package:vault_crypto/src/vault/vault_data.dart';
import 'package:vault_crypto/src/vault/vault_storage.dart';

// Intent: Verify VaultService migration to VaultCryptoV4. unlock() derives VRK,
// holds it in a SecureBuffer, and dispatches Unlocked. lock() wipes VRK.
void main() {
  late AppStore store;
  late VaultService service;
  late Directory tmp;

  setUp(() async {
    tmp = Directory.systemTemp.createTempSync('vault_test');
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

  test('Critical-tier entry requires fresh MP re-auth before reveal', () async {
    await service.init();
    final mp = createMP('right');
    await service.createVault(mp);
    await service.lock();
    await service.unlock(createMP('right'));
    // bank domain triggers the heuristic -> Sensitive tier.
    await service.addEntry(VaultEntry(
      id: 'crit1',
      title: 'Bank',
      username: 'u',
      password: 'secret',
      url: 'bank.example.com',
    ));
    // Sensitive first access -> re-auth required -> getEntry returns null.
    expect(service.getEntry('crit1'), isNull);
    // Re-auth with correct MP -> reveal succeeds.
    final ok = await service.reauthFor('crit1', createMP('right'));
    expect(ok, isTrue);
    expect(service.getEntry('crit1'), isNotNull);
    // Standard domain entry reveals without re-auth.
    await service.addEntry(VaultEntry(
      id: 'std1',
      title: 'News',
      username: 'u',
      password: 'x',
      url: 'news.example.com',
    ));
    expect(service.getEntry('std1'), isNotNull);
  });

  test('unlockWithVrk skips Argon2id and unlocks', () async {
    await service.init();
    final mp = createMP('right');
    await service.createVault(mp);
    await service.lock();
    // Derive the VRK via a normal unlock to capture it, then re-lock.
    await service.unlock(createMP('right'));
    // Capture the held VRK bytes.
    final vrk = service.debugVrk;
    await service.lock();
    // Biometric fast path: unlock with the VRK directly (no Argon2id).
    final ok = await service.unlockWithVrk(vrk);
    expect(ok, isTrue);
    expect(store.currentState, isA<Unlocked>());
  });

  test('canary access triggers lock + lockdown', () async {
    await service.init();
    final mp = createMP('right');
    await service.createVault(mp); // seeds 3 canaries
    await service.lock();
    await service.unlock(createMP('right'));

    // Canaries exist but are hidden from the UI-facing entry list.
    expect(service.canaryIds.length, 3);
    final uiEntries = (store.currentState as Unlocked).vaultData.entries;
    expect(uiEntries.every((e) => !service.canaryIds.contains(e.id)), isTrue);

    // Attacker probes a canary id -> must lock + flag lockdown.
    final target = service.canaryIds.first;
    expect(service.getEntry(target), isNull);
    expect(service.isCanaryTriggered, isTrue);
    expect(store.currentState, isA<Locked>());
  });

  test('search("git") returns the github entry id without full decrypt',
      () async {
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
    await service.addEntry(VaultEntry(
      id: 'b1',
      title: 'Bank',
      username: 'u',
      password: 'p',
      url: 'bank.com',
    ));

    final results = service.search('git');
    expect(results, contains('g1'));
    expect(results, isNot(contains('b1')));
  });

  test('unlock succeeds and holds VRK in memory', () async {
    await service.init(); // -> VaultMissing -> SetupRequired
    final mp = createMP('testMP');
    await service.createVault(mp);
    await service.lock();

    final mp2 = createMP('testMP');
    await service.unlock(mp2);
    expect(store.currentState, isA<Unlocked>());
    expect(service.isUnlocked, isTrue);
    expect(service.hasVrk, isTrue);
  });

  test('getEntry returns the target entry', () async {
    await service.init();
    final mp = createMP('right');
    await service.createVault(mp);
    await service.lock();

    final mp2 = createMP('right');
    await service.unlock(mp2);
    // add an entry, then retrieve it
    await service.addEntry(VaultEntry(
      id: 'e1',
      title: 'Google',
      username: 'u',
      password: 'p',
      url: 'google.com',
    ));
    final got = service.getEntry('e1');
    expect(got, isNotNull);
    expect(got!.title, 'Google');
  });

  test('imports CSV entries and warns about plaintext exposure', () async {
    await service.init();
    final mp = createMP('right');
    await service.createVault(mp);
    await service.lock();
    await service.unlock(createMP('right'));

    final csv = 'name,username,password\n'
        'Google,user@test.com,pass123\n'
        'Github,devuser,secret456';
    final count = await service.importCsv(csv, sourcePath: 'export.csv');
    expect(count, 2);
    // Exposure warning about the plaintext source.
    expect(service.lastImportExposureWarning, contains('export.csv'));
  });

  test('snapshots on save and reloads latest', () async {
    await service.init();
    final mp = createMP('right');
    await service.createVault(mp);
    await service.lock();

    final latest = await service.loadLatestSnapshot();
    expect(latest, isNotNull);
    // Reload the persisted live blob and confirm it equals the saved blob.
    final live = await VaultStorage(baseDir: tmp).readBlob();
    expect(live, equals(latest));
  });

  test('wrong password keeps locked state', () async {
    await service.init(); // -> VaultMissing -> SetupRequired
    final mp = createMP('right');
    await service.createVault(mp);
    await service.lock();

    final wrongMp = createMP('wrong');
    await service.unlock(wrongMp);
    expect(store.currentState, isA<Locked>());
    expect(service.hasVrk, isFalse);
  });

  test('wrong password that also fails duress keeps locked (not duress)',
      () async {
    await service.init();
    final mp = createMP('right');
    await service.createVault(mp);
    await service.lock();

    // Wrong MP fails primary; deniability off -> decoy slot is noise -> duress
    // decrypt fails too -> stays locked, isDuress false.
    await service.unlock(createMP('wrong'));
    expect(store.currentState, isA<Locked>());
    expect(service.isDuress, isFalse);
  });

  test('exportCsv warns (not blocks) when MP is weak', () async {
    await service.init();
    final mp = createMP('weak');
    await service.createVault(mp);
    await service.lock();
    await service.unlock(createMP('weak'));
    await service.addEntry(VaultEntry(
      id: 'e1',
      title: 'Google',
      username: 'u',
      password: 'p',
      url: 'google.com',
    ));

    // Weak MP -> export still succeeds but carries a warning.
    final out = await service.exportCsv(createMP('weak'));
    expect(out.csv, contains('Google'));
    expect(out.warning, isNotNull);
    expect(out.warning!.toLowerCase(), contains('weak'));
  });

  test('exportCsv has no warning for a strong MP', () async {
    await service.init();
    final mp = createMP('Str0ng!Pass#2024');
    await service.createVault(mp);
    await service.lock();
    await service.unlock(createMP('Str0ng!Pass#2024'));
    await service.addEntry(VaultEntry(
      id: 'e1',
      title: 'Google',
      username: 'u',
      password: 'p',
      url: 'google.com',
    ));

    final out = await service.exportCsv(createMP('Str0ng!Pass#2024'));
    expect(out.csv, contains('Google'));
    expect(out.warning, isNull);
  });

  test('setupDecoy persists decoy vault; duress MP unlocks it in duress mode',
      () async {
    await service.init();
    final mp = createMP('primary-secret');
    await service.createVault(mp);
    await service.lock();

    final code = await service.setupDecoy(
      createMP('primary-secret'),
      createMP('duress-secret'),
      [
        V4VaultEntry(
          id: 'd1',
          title: 'Old Email',
          username: 'a@b.c',
          password: 'low',
          url: 'mail.example.com',
          domain: 'mail.example.com',
          tier: 0,
        ),
      ],
    );
    expect(code, matches(RegExp(r'^\d{8}$')));

    // Primary MP -> primary vault, not duress.
    await service.unlock(createMP('primary-secret'));
    expect(service.isDuress, isFalse);
    await service.lock();

    // Duress MP -> decoy vault, duress=true.
    await service.unlock(createMP('duress-secret'));
    expect(service.isDuress, isTrue);
    expect(store.currentState, isA<Unlocked>());
  });

  test('generateShares returns N share strings; parse + unlock works',
      () async {
    await service.init();
    final mp = createMP('right');
    await service.createVault(mp);
    await service.lock();

    final shares = await service.generateShares(createMP('right'), n: 5, k: 3);
    expect(shares.length, 5);
    // Each share is a non-empty base64 string (QR-ready).
    for (final s in shares) {
      expect(s, isNotEmpty);
    }

    // Parse 3 of them back and unlock.
    final parsed = shares.sublist(0, 3).map(ShamirKit.parseShare).toList();
    final ok = await service.unlockWithShares(parsed);
    expect(ok, isTrue);
    expect(store.currentState, isA<Unlocked>());
  });

  test('unlockWithShares reconstructs MK from K shares and unlocks', () async {
    await service.init();
    final mp = createMP('right');
    await service.createVault(mp);
    await service.lock();

    // Derive the MK from the MP (same KDF as createVault), split into shares.
    final blob = await VaultStorage(baseDir: tmp).readBlob();
    final header = V4Header.parse(blob);
    final mk = Argon2id.derive(
      Uint8List.fromList('right'.codeUnits),
      header.salt,
      memory: V4Constants.kdfFloorMemory,
      iterations: V4Constants.kdfFloorIterations,
      parallelism: V4Constants.kdfFloorParallelism,
    );
    final shares = ShamirKit.split(mk, n: 5, k: 3);

    // Reconstruct MK from 3 shares and unlock.
    final ok = await service.unlockWithShares(shares.sublist(0, 3));
    expect(ok, isTrue);
    expect(store.currentState, isA<Unlocked>());
  });

  test('exportVaultFile copies blob; importVaultFile replaces + MP-verifies',
      () async {
    await service.init();
    final mp = createMP('right');
    await service.createVault(mp);
    await service.lock();
    await service.unlock(createMP('right'));
    await service.addEntry(VaultEntry(
      id: 'e1',
      title: 'Google',
      username: 'u',
      password: 'p',
      url: 'google.com',
    ));
    await service.lock();

    // Export the raw V4 blob to a target path.
    final exportPath = '${tmp.path}${Platform.pathSeparator}export.vault';
    await service.exportVaultFile(exportPath);
    final exported = File(exportPath);
    expect(exported.existsSync(), isTrue);

    // Import it back into a fresh service (replaces live blob).
    final service2 = VaultService(
      store: AppStore(),
      crypto: VaultCryptoV4(),
      storage: VaultStorage(baseDir: tmp),
    );
    await service2.init();
    await service2.importVaultFile(exportPath, createMP('right'));
    await service2.unlock(createMP('right'));
    expect(service2.isUnlocked, isTrue);
    expect(service2.getEntry('e1'), isNotNull);
  });

  test('Two-Bunker: MP1 opens Primary, MP2 opens ONLY Decoy (isolated)',
      () async {
    await service.init();
    final primaryMp = createMP('primary');
    final duressMp = createMP('duress');
    await service.createVault(primaryMp);
    // createVault does not hold a VRK; unlock first so addEntry can persist.
    await service.lock();
    await service.unlock(createMP('primary'));
    // Add a real primary entry.
    await service.addEntry(VaultEntry(
      id: 'p1',
      title: 'Real News',
      username: 'u',
      password: 'real-secret',
      url: 'news.example.com',
    ));
    // Set up the decoy (Bunker 2) with a plausible low-value entry.
    final decoyEntries = [
      V4VaultEntry(
        id: 'd1',
        title: 'Old Forum',
        username: 'u',
        password: 'decoy-secret',
        url: 'forum.example.com',
        domain: 'forum.example.com',
        tier: 0,
      ),
    ];
    await service.setupDecoy(primaryMp, duressMp, decoyEntries);
    await service.lock();

    // MP1 -> Primary vault: real entry visible, decoy NOT.
    await service.unlock(createMP('primary'));
    expect(service.isDuress, isFalse);
    expect(service.getEntry('p1'), isNotNull);
    expect(service.getEntry('d1'), isNull);
    await service.lock();

    // MP2 -> Decoy vault: ONLY decoy entries, primary hidden, isDuress true.
    await service.unlock(createMP('duress'));
    expect(service.isDuress, isTrue);
    expect(service.getEntry('d1'), isNotNull);
    expect(service.getEntry('p1'), isNull);
  });

  test('KDF params survive edit round-trips (no floor downgrade brick)',
      () async {
    // Regression: relock used to record FLOOR params in the new header even
    // when the vault was created above the floor. A cold unlock then derived MK
    // under floor -> wrong VRK -> DecryptionFailedError (vault bricked). This
    // test simulates a raised-param vault via relock's explicit params, then
    // verifies an addEntry edit round-trip still unlocks with the MP.
    await service.init();
    final mp = createMP('right');
    await service.createVault(mp);
    // Capture the held VRK BEFORE lock (lock wipes it).
    final heldVrk = service.debugVrk;

    // Raise params above the floor by relocking the blob with explicit params.
    final blob = Uint8List.fromList(
        await File('${tmp.path}${Platform.pathSeparator}vault.blob')
            .readAsBytes());
    final header = V4Header.parse(blob);
    final raised = await VaultCryptoV4().relock(
      heldVrk,
      const [],
      salt: header.salt,
      kdfMemory: header.kdfMemory + 1024,
      kdfIterations: header.kdfIterations + 1,
      kdfParallelism: header.kdfParallelism,
    );
    await File('${tmp.path}${Platform.pathSeparator}vault.blob')
        .writeAsBytes(raised, flush: true);
    await service.lock();

    // Unlock under the raised params, then edit (addEntry) and re-unlock.
    await service.unlock(createMP('right'));
    await service.addEntry(VaultEntry(
      id: 'e1',
      title: 'Entry',
      username: 'u',
      password: 'p',
      url: 'site.com',
    ));
    await service.lock();

    // Cold unlock must still succeed (params preserved through the edit).
    await service.unlock(createMP('right'));
    expect(service.getEntry('e1'), isNotNull);
  });
}
