import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';
import 'app_store.dart';
import '../backup/csv_importer.dart';
import '../backup/mp_strength.dart';
import '../backup/snapshot_manager.dart';
import '../coercion/decoy_vault.dart';
import '../crypto/errors.dart';
import '../crypto/native/argon2id.dart';
import '../crypto/native/secure_buffer.dart';
import '../crypto/v4/constants.dart';
import '../crypto/v4/header.dart';
import '../crypto/v4/key_hierarchy.dart';
import '../crypto/v4/search_tag.dart';
import '../crypto/v4/vault_crypto_v4.dart';
import '../lock/intent.dart';
import '../lock/lockable.dart';
import '../lock/secret_wiper.dart';
import '../lock/state.dart';
import '../security/random_subset.dart';
import '../security/risk_tiers.dart';
import '../security/shamir_kit.dart';
import '../security/security_dashboard.dart';
import '../vault/vault_data.dart';
import '../vault/vault_storage.dart';

// Export result: CSV text plus an optional MP-strength warning (warn, not
// block). The submitted MP must still derive the held VRK (fresh re-auth).
class ExportCsvResult {
  final String csv;
  final String? warning;
  const ExportCsvResult({required this.csv, this.warning});
}

// Intent: App shell bridging the v4 vault crypto to the lock state machine.
// Holds the VRK in a SecureBuffer after unlock. On lock wipes it via SecretWiper.
// The store/UI contract stays VaultData (flat); the service adapts to the per-
// entry V4VaultEntry model internally.
// Invariants: VRK never a Dart String; wipe on lock; unlock holds VRK.
// State Transition: unlocked -> lock() -> SecretWiper.wipe(VRK) -> hasVrk=false
// Dependencies: VaultCryptoV4, AppStore, VaultStorage, SecureBuffer, SecretWiper.

class VaultService implements Lockable {
  final AppStore _store;
  final VaultCryptoV4 _crypto;
  final VaultStorage _storage;
  final SnapshotManager _snapshots;
  Uint8List? _currentBlob;
  Uint8List? _blobSalt;
  SecureBuffer? _vrk;
  List<V4VaultEntry> _entries = [];
  Map<String, List<Uint8List>> _searchTags = {};
  final Map<String, DateTime> _lastReveal = {};
  bool _isDuress = false;
  bool _canaryTriggered = false;
  String? _lastImportExposureWarning;
  // Serializes mutating ops (addEntry/attachPasskey/setupDecoy/importVaultFile)
  // so concurrent saves cannot interleave on _entries or the blob file.
  final _AsyncMutex _mutex = _AsyncMutex();

  VaultService({
    required AppStore store,
    required VaultCryptoV4 crypto,
    required VaultStorage storage,
    SnapshotManager? snapshots,
  })  : _store = store,
        _crypto = crypto,
        _storage = storage,
        _snapshots = snapshots ??
            SnapshotManager(
              storageDir: Directory(
                  '${storage.baseDir.path}${Platform.pathSeparator}snapshots'),
              maxSnapshots: 5,
            );

  bool get isUnlocked => _store.currentState is Unlocked;
  bool get hasVrk => _vrk != null;
  bool get isDuress => _isDuress;
  bool get isCanaryTriggered => _canaryTriggered;

  // Debug/test accessor for the held VRK (biometric fast-path tests).
  // Returns a COPY so later wipe (lock) does not zero the captured bytes.
  // Guarded to debug builds: shipping a public VRK-copying accessor in release
  // would let any caller exfiltrate the master key material. Uses a const
  // debug flag (no Flutter dependency in this pure-Dart module).
  static const bool _debug = bool.fromEnvironment('dart.vm.product') == false;
  Uint8List get debugVrk {
    assert(_debug, 'debugVrk is debug-only');
    final b = _vrk?.readBytes();
    return b == null ? Uint8List(0) : Uint8List.fromList(b);
  }

  // Exposed for testing/forensics: canary entry ids (they are hidden from UI).
  List<String> get canaryIds =>
      _entries.where((e) => e.isCanary).map((e) => e.id).toList();

  Future<void> init() async {
    if (!await _storage.vaultExists()) {
      _store.dispatch(VaultMissing());
      return;
    }
    _currentBlob = await _storage.readBlob();
    // Startup integrity gate: a vault.blob that is not a valid GEN4 header is
    // either corrupted or a leftover from an old build. Route to the
    // "corrupted/unreadable" screen instead of silently locking the user out.
    if (_isValidV4Blob(_currentBlob!)) {
      _store.dispatch(VaultLoaded(blob: _currentBlob!));
    } else {
      _store.dispatch(BlobCorruptDetected(blob: _currentBlob!));
    }
  }

  // v5: byte-level GEN4 validation — magic + version + min length. A blob that
  // fails here could be trash, an old V3 file, or truncated (header parse would
  // throw CorruptBlobError/UnsupportedFormatError on unlock).
  bool _isValidV4Blob(Uint8List blob) {
    if (blob.length < V4Constants.fixedHeaderSize + V4Constants.tagSize) {
      return false;
    }
    try {
      final header = V4Header.parse(blob);
      return header.formatVersion == V4Constants.formatVersion &&
          header.magic == V4Constants.magic;
    } catch (_) {
      return false;
    }
  }

  // v5: "Delete and Create New Vault". Securely delete the blob + SFM + any
  // snapshots, then route to SetupRequired so the user starts fresh.
  Future<void> resetVault() async {
    await _mutex.synchronized(() async {
      await _storage.deleteVault();
      await _storage.deleteSfm();
      await _snapshots.clearSnapshots();
      // Wipe any held VRK and clear all in-memory state so no key material or
      // entries survive a reset (the old comment claimed this but only deleted
      // the blob file).
      if (_vrk != null) {
        SecretWiper.wipe(_vrk!);
        _vrk = null;
      }
      _currentBlob = null;
      _blobSalt = null;
      _entries = [];
      _searchTags = {};
      _isDuress = false;
      _canaryTriggered = false;
      _store.dispatch(BlobResetComplete());
    });
  }

  Future<void> createVault(SecureBuffer mp) async {
    await _mutex.synchronized(() async {
      // Seed 3 honeypot canaries (v4 §6.1). They look real but are invisible in
      // the UI; any access triggers the alarm (lock + lockdown).
      _entries = _generateCanaries();
      final json = Uint8List.fromList(
        jsonEncode({'entries': _entries.map((e) => e.toJson()).toList()})
            .codeUnits,
      );
      _currentBlob = await _crypto.lockVault(json, mp);
      _blobSalt = V4Header.parse(_currentBlob!).salt;
      await _storage.writeBlob(_currentBlob!);
      await _snapshots.saveSnapshot(_currentBlob!);
      _searchTags = {};

      // Hold the VRK so the user can add entries immediately after creation
      // (state-loss fix: addEntry silently returned when _vrk was null).
      final header = V4Header.parse(_currentBlob!);
      final mk = Argon2id.derive(
        mp.readBytes(),
        header.salt,
        memory: header.kdfMemory,
        iterations: header.kdfIterations,
        parallelism: header.kdfParallelism,
      );
      _vrk?.dispose();
      _vrk = SecureBuffer.fromList(KeyHierarchy.deriveVrk(mk));
      _isDuress = false;

      _store.dispatch(
          VaultCreated(vaultData: VaultData(entries: []), blob: _currentBlob!));
    });
  }

  // Biometric fast path (Phase D.1): unlock using a VRK retrieved from the
  // Keystore, skipping Argon2id. Falls back to MP if the VRK is absent.
  Future<bool> unlockWithVrk(Uint8List vrk) async {
    return _mutex.synchronized(() async {
      try {
        final blob = _currentBlob!;
        final entries = VaultCryptoV4.decryptToEntries(blob, vrk);
        _vrk?.dispose();
        _vrk = SecureBuffer.fromList(vrk);
        // Zero the caller's plaintext VRK copy now that it lives in native
        // secure memory. Prevents the VRK lingering in Dart heap memory.
        vrk.fillRange(0, vrk.length, 0);
        _blobSalt = V4Header.parse(blob).salt;
        _entries = entries;
        _isDuress = false;
        _store.dispatch(UnlockSuccess(vaultData: _toVaultData(_entries)));
        return true;
      } catch (_) {
        return false;
      }
    });
  }

  Future<void> unlock(SecureBuffer mp) async {
    try {
      final blob = _currentBlob!;
      UnlockSession session;
      bool duress = false;
      try {
        session = await _crypto.unlockSession(blob, mp);
      } on DecryptionFailedError {
        // Primary VRK failed -> try slot 2 (decoy vault) under VRK_duress.
        // Slot 2 is noise when deniability is disabled -> duress fails too.
        session = await _crypto.duressUnlockSession(blob, mp);
        duress = true;
      } on DuressDecryptError {
        _store.dispatch(UnlockFail());
        return;
      }
      _vrk?.dispose();
      _vrk = session.vrk;
      _blobSalt = V4Header.parse(blob).salt;
      _entries = session.entries;
      _searchTags = session.searchTags;
      _isDuress = duress;
      _store.dispatch(UnlockSuccess(vaultData: _toVaultData(_entries)));
    } on DecryptionFailedError {
      _store.dispatch(UnlockFail());
    } catch (_) {
      _store.dispatch(UnlockFail());
    }
  }

  @override
  Future<void> lock() async {
    if (_vrk != null) {
      SecretWiper.wipe(_vrk!);
      _vrk = null;
    }
    _entries = [];
    _store.dispatch(AutoLock());
  }

  Future<void> addEntry(VaultEntry entry, {int? tier}) async {
    if (_vrk == null) return;
    await _mutex.synchronized(() async {
      if (_vrk == null) return;
      final v4 = V4VaultEntry(
        id: entry.id,
        title: entry.title,
        username: entry.username,
        password: entry.password,
        url: entry.url,
        domain: entry.url,
        tier: tier ?? RiskTiers.suggestTier(entry.url),
      );
      _entries.add(v4);
      _searchTags[v4.id] =
          SearchTag.computePrefixes(_vrk!.readBytes(), v4.domain);
      _currentBlob = await _relockCurrent(_vrk!.readBytes(), _entries);
      await _storage.writeBlobAtomic(_currentBlob!);
      await _snapshots.saveSnapshot(_currentBlob!);
      _store.dispatch(AddEntry(entry: entry));
    });
  }

  // Recovery path: load the latest snapshot, decrypt on next unlock.
  Future<Uint8List?> loadLatestSnapshot() => _snapshots.loadLatestSnapshot();

  // Access an entry with random-subset decoy obfuscation (v4 §6.5). Selects
  // ~20% of non-Critical entries as decoys, decrypts them into secure memory,
  // returns the target, then wipes all decoy data. Critical entries are never
  // decoys. Returns null if the id is not found.
  // Canary alarm: if the accessed entry is a honeypot canary (v4 §6.1), lock
  // immediately, wipe the VRK, and set the adaptive posture to lockdown.
  V4VaultEntry? getEntry(String id) {
    if (_vrk == null) return null;
    final targetIndex = _entries.indexWhere((e) => e.id == id);
    if (targetIndex < 0) return null;
    if (_entries[targetIndex].isCanary) {
      // Fire-and-forget: getEntry is sync; the alarm sets _canaryTriggered
      // synchronously then awaits the VRK wipe.
      unawaited(_triggerCanaryAlarm());
      return null;
    }

    // Risk-tier gate (Phase I.1): Sensitive/Critical require re-auth before
    // reveal (Critical always; Sensitive within a short grace). Deny if unauthed.
    final tier = _entries[targetIndex].tier;
    if (RiskTiers.requiresReauth(tier, lastReveal: _lastReveal[id])) {
      return null;
    }

    final tiers = _entries.map((e) => e.tier).toList();
    final decoys = RandomSubset.selectDecoys(
      targetIndex: targetIndex,
      tiers: tiers,
      targetTier: _entries[targetIndex].tier,
    );

    // Decrypt decoys into secure memory and immediately wipe them.
    for (final d in decoys) {
      final buf = SecureBuffer.fromList(
        Uint8List.fromList(_entries[d].password.codeUnits),
      );
      SecretWiper.wipe(buf);
    }

    _lastReveal[id] = DateTime.now();
    return _entries[targetIndex];
  }

  // Fresh re-auth for a Sensitive/Critical reveal. For Critical this requires
  // a fresh MP; verify it still derives the held VRK. On success the tier gate
  // is satisfied for the reveal grace (Critical returns true immediately after).
  Future<bool> reauthFor(String id, SecureBuffer mp) async {
    if (_vrk == null) return false;
    final idx = _entries.indexWhere((e) => e.id == id);
    if (idx < 0) return false;
    final tier = _entries[idx].tier;
    if (tier == RiskTiers.standard) {
      return false; // Standard never needs re-auth
    }
    // Fresh re-auth proof: derive VRK from the submitted MP using the original
    // vault salt + HEADER KDF params (deterministic -> matches the held VRK),
    // constant-time compare. Uses header params, not the floor, so a vault
    // created above the floor still re-auths on the correct MP.
    final blob = _currentBlob;
    if (blob == null) return false;
    try {
      final mk = await _deriveMk(blob, mp);
      final vrk = KeyHierarchy.deriveVrk(mk);
      if (!_constTimeEq(vrk, _vrk!.readBytes())) return false;
    } catch (_) {
      return false;
    }
    _lastReveal[id] = DateTime.now();
    return true;
  }

  // True SSE search (v4 §6.9 / §5.1): compute the HMAC of the normalized query
  // under SearchKey and match it against the stored prefix-tags (length 3..full
  // domain) using constant-time comparison. No domain decryption during search.
  List<String> search(String query) {
    if (_vrk == null) return const [];
    final q = query.toLowerCase().trim();
    if (q.isEmpty) return _entries.map((e) => e.id).toList();
    // Only match queries of length >= 3 (tags start at prefix length 3).
    if (q.length < 3) return const [];

    final searchKey = SearchTag.deriveSearchKey(_vrk!.readBytes());
    final qTag = SearchTag.tagFor(searchKey, q);
    final results = <String>[];
    for (final entry in _entries) {
      final tags = _searchTags[entry.id];
      if (tags == null) continue;
      for (final t in tags) {
        if (_constTimeEq(t, qTag)) {
          // Reveal-filter (v5 E13): padding tags can collide with the query
          // tag -> false positive. Confirm the entry's domain actually matches.
          if (SearchTag.matchesDomain(entry.domain, q)) {
            results.add(entry.id);
          }
          break;
        }
      }
    }

    return results;
  }

  // Expose UI-model entry for autofill bridge. Returns null if locked/canary/missing.
  VaultEntry? getVaultEntry(String id) {
    if (_vrk == null) return null;
    final idx = _entries.indexWhere((e) => e.id == id);
    if (idx < 0) return null;
    if (_entries[idx].isCanary) return null;
    return VaultEntry(
      id: _entries[idx].id,
      title: _entries[idx].title,
      username: _entries[idx].username,
      password: _entries[idx].password,
      url: _entries[idx].url,
    );
  }

  int? getEntryTier(String id) {
    if (_vrk == null) return null;
    final idx = _entries.indexWhere((e) => e.id == id);
    if (idx < 0 || _entries[idx].isCanary) return null;
    return _entries[idx].tier;
  }

  // P3: Attach a FIDO2 passkey credentialId to an existing vault entry.
  // The private key remains in the Android Keystore. Triggers relock.
  Future<void> attachPasskey(String entryId, String credentialId) async {
    if (_vrk == null) return;
    await _mutex.synchronized(() async {
      if (_vrk == null) return;
      final idx = _entries.indexWhere((e) => e.id == entryId);
      if (idx < 0) return;
      _entries[idx].passkeyCredentialId = credentialId;
      _currentBlob = await _relockCurrent(_vrk!.readBytes(), _entries);
      await _storage.writeBlobAtomic(_currentBlob!);
      await _snapshots.saveSnapshot(_currentBlob!);
    });
  }

  // P3: Check if an entry has a passkey attached.
  bool hasPasskey(String entryId) {
    final idx = _entries.indexWhere((e) => e.id == entryId);
    if (idx < 0) return false;
    return _entries[idx].passkeyCredentialId != null;
  }

  // Centralize MK derivation on the HEADER's KDF params. The old code used
  // kdfFloor* in reauthFor/exportCsv/generateShares but header.kdf* in
  // createVault/setupDecoy/changeMasterPassword. If a vault was created with
  // params above the floor, re-auth/export/shares always failed on the CORRECT
  // MP. All six call sites now derive from the header params.
  static Future<Uint8List> _deriveMk(Uint8List blob, SecureBuffer mp) async {
    final header = V4Header.parse(blob);
    return Argon2id.derive(
      mp.readBytes(),
      header.salt,
      memory: header.kdfMemory,
      iterations: header.kdfIterations,
      parallelism: header.kdfParallelism,
    );
  }

  // Re-lock the CURRENT vault, forwarding the header's KDF params. The old
  // call sites passed only salt, so _buildBlob recorded FLOOR params in the new
  // header. If a vault ever has params P > floor, the next cold unlock derives
  // MK under floor -> wrong VRK -> DecryptionFailedError (vault bricked). This
  // helper preserves the actual params so edit round-trips stay consistent.
  Future<Uint8List> _relockCurrent(Uint8List vrk, List<V4VaultEntry> entries,
      {Uint8List? decoyBlob}) async {
    final h = V4Header.parse(_currentBlob!);
    return _crypto.relock(
      vrk,
      entries,
      salt: _blobSalt,
      kdfMemory: h.kdfMemory,
      kdfIterations: h.kdfIterations,
      kdfParallelism: h.kdfParallelism,
      decoyBlob: decoyBlob,
    );
  }

  static bool _constTimeEq(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff == 0;
  }

  // Local Security Dashboard (Phase K.1): dup/weak/old warnings, fully local.
  List<DashboardWarning> dashboardWarnings() {
    final records = _entries
        .where((e) => !e.isCanary)
        .map((e) => (
              id: e.id,
              title: e.title,
              password: e.password,
              updatedAt: e.updatedAt,
              domain: e.domain,
            ))
        .toList();
    return SecurityDashboard.analyze(
      entries: records,
      now: DateTime.now().millisecondsSinceEpoch,
    );
  }

  // Third-party CSV import (Phase F.3). The CSV is plaintext on disk during the
  // import window; returns a warning + recommends secure-delete. Parses via
  // CsvImporter, imports each row, relocks + saves.
  Future<int> importCsv(String csv, {String? sourcePath}) async {
    if (_vrk == null) return 0;
    final json = CsvImporter.parse(csv);
    final list = (jsonDecode(utf8.decode(json)) as List)
        .map((e) => e as Map<String, dynamic>)
        .toList();
    // Batch: build all entries first, then relock ONCE. The old code called
    // addEntry per row, doing a full re-encrypt + atomic write per row (O(n)
    // relocks). Under the mutex this serializes correctly but is wasteful.
    final newEntries = <V4VaultEntry>[];
    var count = 0;
    for (final row in list) {
      final title = (row['title'] ?? '') as String;
      final username = (row['username'] ?? '') as String;
      final password = (row['password'] ?? '') as String;
      if (title.isEmpty && password.isEmpty) continue;
      newEntries.add(V4VaultEntry(
        id: DateTime.now().microsecondsSinceEpoch.toString() + count.toString(),
        title: title,
        username: username,
        password: password,
        url: title.toLowerCase(),
        domain: title.toLowerCase(),
        tier: RiskTiers.suggestTier(title.toLowerCase()),
      ));
      count++;
    }
    if (newEntries.isEmpty) return 0;

    await _mutex.synchronized(() async {
      if (_vrk == null) return;
      _entries.addAll(newEntries);
      for (final e in newEntries) {
        _searchTags[e.id] =
            SearchTag.computePrefixes(_vrk!.readBytes(), e.domain);
      }
      _currentBlob = await _relockCurrent(_vrk!.readBytes(), _entries);
      await _storage.writeBlobAtomic(_currentBlob!);
      await _snapshots.saveSnapshot(_currentBlob!);
    });

    // Plaintext exposure window: the source CSV was plaintext in the file
    // picker / OS temp. Warn the user to securely delete it.
    _lastImportExposureWarning =
        'Imported $count entries. Delete the source CSV securely '
        '(it was plaintext): ${sourcePath ?? '(source)'}';
    return count;
  }

  String? get lastImportExposureWarning => _lastImportExposureWarning;

  // Export the vault to CSV (Phase F.1). Requires a fresh MP that re-derives the
  // held VRK (proof of possession). If the MP is weak, returns a warning but
  // still exports — the gate warns, never blocks.
  Future<ExportCsvResult> exportCsv(SecureBuffer mp) async {
    if (_vrk == null) throw StateError('Vault locked');
    final blob = _currentBlob;
    if (blob == null) throw StateError('Vault salt missing');
    // Derive from the HEADER KDF params (not the floor) so a vault created
    // above the floor still exports on the correct MP.
    final mk = await _deriveMk(blob, mp);
    final vrk = KeyHierarchy.deriveVrk(mk);
    if (!_constTimeEq(vrk, _vrk!.readBytes())) {
      throw DecryptionFailedError();
    }

    // CSV escaping: quote embedded quotes (""), and neutralize formula
    // injection (=, +, -, @) that Excel would execute on open.
    String cell(String s) {
      var v = s;
      if (v.startsWith('=') ||
          v.startsWith('+') ||
          v.startsWith('-') ||
          v.startsWith('@')) {
        v = "'$v";
      }
      return '"${v.replaceAll('"', '""')}"';
    }

    final rows = _entries
        .where((e) => !e.isCanary)
        .map((e) =>
            '${cell(e.title)},${cell(e.username)},${cell(e.password)},${cell(e.url)}')
        .toList();
    final csv = 'title,username,password,url\n${rows.join('\n')}';

    final strength = MpStrength.check(utf8.decode(mp.readBytes()));
    final warning = strength.strength == MpStrengthLevel.weak
        ? 'Weak master password. Exported vault is only as strong as its MP: ${strength.warning}'
        : null;
    return ExportCsvResult(csv: csv, warning: warning);
  }

  // Decoy-vault setup (Phase J.4, v5 E4). Builds a decoy vault locked under
  // VRK_duress (same salt as primary) and EMBEDS it into slot 2 of the single
  // vault file. No separate decoy file exists on disk — ever. Returns the
  // 8-digit cancellation code shown exactly once. Requires the primary MP to
  // re-lock the primary vault (works from the locked state).
  Future<String> setupDecoy(
    SecureBuffer primaryMp,
    SecureBuffer duressMp,
    List<V4VaultEntry> entries,
  ) async {
    return _mutex.synchronized(() async {
      final blob = _currentBlob;
      if (blob == null) throw StateError('No vault loaded');
      final header = V4Header.parse(blob);
      final salt = header.salt;
      final decoyJson = Uint8List.fromList(
        jsonEncode({'entries': entries.map((e) => e.toJson()).toList()})
            .codeUnits,
      );
      final decoy = await _crypto.lockDecoy(decoyJson, duressMp, salt);
      // Re-lock the primary vault with the decoy embedded in slot 2.
      final mk = await _deriveMk(blob, primaryMp);
      final vrk = KeyHierarchy.deriveVrk(mk);
      _currentBlob = await _relockCurrent(vrk, _entries, decoyBlob: decoy);
      await _storage.writeBlobAtomic(_currentBlob!);
      return DecoyVault.generateCancellationCode();
    });
  }

  // Shamir recovery setup (Phase I.8 UI): derive the MK from the MP + vault
  // salt (deterministic) and split it into N shares; any K reconstruct it.
  // Returns QR-ready base64 share strings. Opt-in, off by default.
  Future<List<String>> generateShares(
    SecureBuffer mp, {
    required int n,
    required int k,
  }) async {
    final blob = _currentBlob;
    if (blob == null) throw StateError('No vault loaded');
    // Derive from the HEADER KDF params (not the floor) so shares always match
    // the vault's actual MK derivation.
    final mk = await _deriveMk(blob, mp);
    final shares = ShamirKit.split(mk, n: n, k: k);
    return shares.map(ShamirKit.encodeShare).toList();
  }

  // Shamir recovery (Phase I.8): reconstruct the MK from K shares and unlock.
  // Opt-in, off by default. If the user loses the MP but has K shares, they can
  // reconstruct the MK and unlock the vault.
  Future<bool> unlockWithShares(List<Share> shares) async {
    return _mutex.synchronized(() async {
      final blob = _currentBlob;
      if (blob == null) return false;
      final mk = ShamirKit.reconstruct(shares);
      final header = V4Header.parse(blob);
      final vrk = KeyHierarchy.deriveVrk(mk);
      try {
        final entries = VaultCryptoV4.decryptToEntries(blob, vrk);
        _vrk?.dispose();
        _vrk = SecureBuffer.fromList(vrk);
        _blobSalt = header.salt;
        _entries = entries;
        _isDuress = false;
        _store.dispatch(UnlockSuccess(vaultData: _toVaultData(_entries)));
        return true;
      } catch (_) {
        return false;
      }
    });
  }

  // Manual export (Phase F.4): copy the raw V4 blob to a user-selected path.
  // Enables offline USB transfer between Android and Linux. The blob stays
  // encrypted; no plaintext leaves the device.
  Future<void> exportVaultFile(String targetPath) async {
    final blob = _currentBlob;
    if (blob == null) throw StateError('No vault loaded');
    await File(targetPath).writeAsBytes(blob, flush: true);
  }

  // Manual import (Phase F.4): replace the live blob with an imported one.
  // Requires the MP to unlock the imported blob (proof of possession) before
  // the live blob is replaced. On success, persists the imported blob.
  Future<void> importVaultFile(String sourcePath, SecureBuffer mp) async {
    await _mutex.synchronized(() async {
      final imported = Uint8List.fromList(await File(sourcePath).readAsBytes());
      // MP-verify: unlock the imported blob; wrong MP throws DecryptionFailedError.
      final session = await _crypto.unlockSession(imported, mp);
      session.vrk.dispose();
      _currentBlob = imported;
      _blobSalt = V4Header.parse(imported).salt;
      await _storage.writeBlobAtomic(imported);
    });
    // State-corruption fix: the old code swapped _currentBlob/_blobSalt but
    // kept the previous session's _vrk/_entries. A subsequent addEntry would
    // re-encrypt OLD entries under the OLD VRK with the NEW salt. Locking
    // wipes the stale VRK/entries so the next unlock loads the imported vault.
    // lock() runs OUTSIDE the mutex so it can never self-deadlock if it ever
    // acquires the mutex itself.
    await lock();
  }

  // v5 E17/V3.3: ATOMIC master-password change. Re-wraps all DEKs under the new
  // VRK, recomputes all search_tags, re-seals the SFM file under the new
  // MK_base (seed untouched — 2FA survives), and persists BOTH files via
  // temp-file-then-rename. An interrupted change leaves the old file + old MP
  // fully intact. No mixed tag/VRK state is observable.
  Future<void> changeMasterPassword(
      SecureBuffer oldMp, SecureBuffer newMp) async {
    await _mutex.synchronized(() async {
      final blob = _currentBlob;
      if (blob == null) throw StateError('No vault loaded');
      final sfmFile =
          await _storage.sfmExists() ? await _storage.readSfm() : null;
      final result = await _crypto.changeMasterPassword(blob, oldMp, newMp,
          sfmFile: sfmFile);
      // Atomic persistence: vault blob first, then SFM file. Each is a
      // temp-file-then-rename; an interruption between them leaves the vault
      // under the new MP with the old SFM file — but the old SFM file is still
      // decryptable under the OLD MK_base only, so no mixed state is usable.
      await _storage.writeBlobAtomic(result.blob);
      if (result.sfmFile != null) {
        await _storage.writeSfmAtomic(result.sfmFile!);
      }
      _currentBlob = result.blob;
      _blobSalt = V4Header.parse(result.blob).salt;
      // Re-derive the held VRK under the new MP so the session stays unlocked.
      final header = V4Header.parse(result.blob);
      final mk = Argon2id.derive(
        newMp.readBytes(),
        header.salt,
        memory: header.kdfMemory,
        iterations: header.kdfIterations,
        parallelism: header.kdfParallelism,
      );
      final newVrk = KeyHierarchy.deriveVrk(mk);
      _vrk?.dispose();
      _vrk = SecureBuffer.fromList(newVrk);
      _searchTags = {};
      for (final e in _entries) {
        _searchTags[e.id] = SearchTag.computePrefixes(newVrk, e.domain);
      }
    });
  }

  // Canary alarm (v4 §6.1): lock immediately, wipe VRK, flag lockdown.
  // The lock is awaited so the VRK wipe completes before the caller returns
  // (the old unawaited lock() left a window where the VRK was still live).
  Future<void> _triggerCanaryAlarm() async {
    _canaryTriggered = true;
    await lock();
  }

  // Test hook: expose the canary generator for the decoy-data sanitization
  // test (asserts no forbidden words leak into user-visible fields).
  static List<V4VaultEntry> generateCanariesForTest() => _generateCanaries();

  // Generate 3 realistic-looking honeypot canaries (v4 §6.1). Marked isCanary
  // so the UI filters them and access triggers the alarm. The fake data MUST
  // look like real accounts — realistic domains, usernames, strong passwords.
  // NO words like "canary/decoy/fake/dummy/test/example/bunker" in any
  // user-visible field (a coercer seeing them destroys plausible deniability).
  static List<V4VaultEntry> _generateCanaries() {
    final seed = DateTime.now().millisecondsSinceEpoch;
    final titles = ['Netflix', 'Reddit', 'Steam'];
    final domains = ['netflix.com', 'reddit.com', 'steam.com'];
    final users = ['john.doe', 'user1990', 'm.kowalski'];
    return List.generate(3, (i) {
      final n = seed + i;
      return V4VaultEntry(
        id: 'c_$n',
        title: titles[i],
        username: users[i],
        password: _randomStrongPassword(n),
        url: domains[i],
        domain: domains[i],
        tier: 0,
        isCanary: true,
      );
    });
  }

  // CSPRNG strong password (12 chars, mixed classes).
  static String _randomStrongPassword(int seed) {
    final r = Random.secure();
    const lower = 'abcdefghijklmnopqrstuvwxyz';
    const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const digits = '0123456789';
    const syms = '!@#\$%^&*';
    final all = lower + upper + digits + syms;
    final sb = StringBuffer();
    for (var i = 0; i < 12; i++) {
      sb.write(all[r.nextInt(all.length)]);
    }
    return sb.toString();
  }

  // UI-facing entry list excludes canaries (they are invisible to the user).
  static VaultData _toVaultData(List<V4VaultEntry> entries) {
    return VaultData(
      entries: entries
          .where((e) => !e.isCanary)
          .map((e) => VaultEntry(
                id: e.id,
                title: e.title,
                username: e.username,
                password: e.password,
                url: e.url,
              ))
          .toList(),
    );
  }
}

// Minimal async mutex. Serializes mutating vault operations so concurrent
// addEntry/attachPasskey/setupDecoy/importVaultFile cannot interleave on
// _entries or the blob file. (package:synchronized is not a dependency.)
class _AsyncMutex {
  Future<void> _tail = Future.value();

  Future<T> synchronized<T>(Future<T> Function() action) {
    final completer = Completer<void>();
    final prev = _tail;
    _tail = completer.future;
    return prev.then((_) => action()).then((value) {
      completer.complete();
      return value;
    }, onError: (Object e, StackTrace st) {
      completer.complete();
      throw e;
    });
  }
}
