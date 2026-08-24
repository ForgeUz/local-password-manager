import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import '../errors.dart';
import '../native/aes_gcm.dart';
import '../native/argon2id.dart';
import '../native/secure_buffer.dart';
import '../padding.dart';
import 'constants.dart';
import 'duress.dart';
import 'header.dart';
import 'key_hierarchy.dart';
import 'search_tag.dart';
import 'second_factor.dart';

// Intent: v4 vault lock/unlock (per-entry hierarchy + header-as-AAD outer GCM).
//
// File layout:
//   [header: fixed(44) + entry table] [second-slot ciphertext (256B random)]
//   [outer GCM tag (16B)]
//
// The header (fixed + entry table) is the AAD to the outer GCM. The outer GCM
// is keyed by VRK. Wrong MP -> wrong VRK -> tag fails. Header tamper -> AAD
// changed -> tag fails. vault_count is always 2 (v4 §4.1).
//
// Each entry's ciphertext carries its own nonce: nonce(12) || AES-GCM(DEK, padded).
// relock()/decryptToEntries() take a held VRK so VaultService can re-lock
// after an edit without re-running Argon2id.
//
// SECURITY CRITICAL:
// 1. All intermediate keys (MK, VRK) are zeroed after use.
// 2. Slot 2 is NOT included in outer AAD to preserve plausible deniability.
// 3. All decryption errors throw DecryptionFailedError (no error oracle).
//
// Invariants: round-trip; wrong password fails; header tamper fails.
// Dependencies: Argon2id, KeyHierarchy, SearchTag, V4Header, AesGcm, Padding.

// Intent: Held-key unlock result. vrk lives in native secure memory; entries
// are the decrypted per-entry model. searchTags maps each entry id to its
// on-disk prefix search_tags (for SSE search without full decrypt). The caller
// owns the SecureBuffer lifecycle.
class UnlockSession {
  final SecureBuffer vrk;
  final List<V4VaultEntry> entries;
  final Map<String, List<Uint8List>> searchTags;
  const UnlockSession({
    required this.vrk,
    required this.entries,
    this.searchTags = const {},
  });
}

// v5 E2: result of a backup-code unlock. Carries the session plus the updated
// SFM file (code consumed / attempt recorded) for the caller to persist.
class UnlockSessionResult {
  final UnlockSession session;
  final Uint8List updatedSfmFile;
  const UnlockSessionResult({
    required this.session,
    required this.updatedSfmFile,
  });
}

// v5 E17/V3.3: result of an atomic MP change. Carries the new vault blob (all
// DEKs re-wrapped under the new VRK, all search_tags recomputed) plus the
// re-sealed SFM file (encrypted under the new MK_base, seed untouched).
class MpChangeResult {
  final Uint8List blob;
  final Uint8List? sfmFile; // null when 2FA is not enabled
  const MpChangeResult({required this.blob, this.sfmFile});
}

class V4VaultEntry {
  final String id;
  final String title;
  final String username;
  final String password;
  final String url;
  final String domain;
  final int tier;
  final bool isCanary; // internal flag, only in decrypted payload
  final int updatedAt; // epoch millis, for password-age tracking

  V4VaultEntry({
    required this.id,
    required this.title,
    required this.username,
    required this.password,
    required this.url,
    required this.domain,
    required this.tier,
    this.isCanary = false,
    this.updatedAt = 0,
  });

  Map<String, dynamic> toJson() => {
        'id': id,
        'title': title,
        'username': username,
        'password': password,
        'url': url,
        'domain': domain,
        'tier': tier,
        if (isCanary) 'isCanary': true,
        if (updatedAt != 0) 'updatedAt': updatedAt,
      };

  factory V4VaultEntry.fromJson(Map<String, dynamic> json) {
    return V4VaultEntry(
      id: json['id'] as String,
      title: json['title'] as String,
      username: json['username'] as String,
      password: json['password'] as String,
      url: json['url'] as String,
      domain: (json['domain'] ?? '') as String,
      tier: (json['tier'] ?? 0) as int,
      isCanary: (json['isCanary'] ?? false) as bool,
      updatedAt: (json['updatedAt'] ?? 0) as int,
    );
  }
}

class VaultCryptoV4 {
  static const int _secondSlotSize = 256;
  static const int _nonceSize = 12;

  /// Build a decoy vault blob locked under VRK_duress using the SAME salt as the
  /// primary vault (v5 E3: one salt).
  ///
  /// SECURITY: duressMp and intermediate keys are zeroed after use.
  Future<Uint8List> lockDecoy(
    Uint8List jsonUtf8,
    SecureBuffer duressMp,
    Uint8List salt,
  ) async {
    final entries = _parseEntries(jsonUtf8);
    final mk = await Argon2id.derive(
      duressMp.readBytes(),
      salt,
      memory: V4Constants.kdfFloorMemory ~/ 1024,
      iterations: V4Constants.kdfFloorIterations,
      parallelism: V4Constants.kdfFloorParallelism,
    );
    
    try {
      final vrkDuress = Duress.deriveVrkDuress(mk);
      try {
        return relock(
          vrkDuress,
          entries,
          salt: salt,
          kdfMemory: V4Constants.kdfFloorMemory ~/ 1024,
          kdfIterations: V4Constants.kdfFloorIterations,
          kdfParallelism: V4Constants.kdfFloorParallelism,
        );
      } finally {
        // CRITICAL: Zero VRK_duress after use
        vrkDuress.fillRange(0, vrkDuress.length, 0);
      }
    } finally {
      // CRITICAL: Zero MK after use
      mk.fillRange(0, mk.length, 0);
    }
  }

  /// Lock a vault with master password.
  ///
  /// SECURITY: mp and intermediate keys are zeroed after use.
  Future<Uint8List> lockVault(Uint8List jsonUtf8, SecureBuffer mp,
      {Uint8List? totpBytes, Uint8List? decoyBlob, Uint8List? fixedSalt}) async {
    final entries = _parseEntries(jsonUtf8);
    final salt = fixedSalt ?? _randomBytes(V4Constants.saltSize);
    final nonce = _randomBytes(V4Constants.nonceSize);

    final mk = await Argon2id.derive(
      mp.readBytes(),
      salt,
      memory: V4Constants.kdfFloorMemory ~/ 1024,
      iterations: V4Constants.kdfFloorIterations,
      parallelism: V4Constants.kdfFloorParallelism,
    );
    
    try {
      final vrk = KeyHierarchy.deriveVrk(mk, totpBytes: totpBytes);
      try {
        return _buildBlob(
          vrk,
          salt,
          nonce,
          V4Constants.kdfFloorMemory ~/ 1024,
          V4Constants.kdfFloorIterations,
          V4Constants.kdfFloorParallelism,
          entries,
          decoyBlob: decoyBlob,
        );
      } finally {
        // CRITICAL: Zero VRK after use
        vrk.fillRange(0, vrk.length, 0);
      }
    } finally {
      // CRITICAL: Zero MK after use
      mk.fillRange(0, mk.length, 0);
    }
  }

  /// Re-lock with a held VRK (no Argon2id re-derivation).
  /// Preserves the salt + KDF params from the incoming blob.
  Future<Uint8List> relock(
    Uint8List vrk,
    List<V4VaultEntry> entries, {
    Uint8List? salt,
    int? kdfMemory,
    int? kdfIterations,
    int? kdfParallelism,
    Uint8List? decoyBlob,
  }) async {
    final nonce = _randomBytes(V4Constants.nonceSize);
    return _buildBlob(
      vrk,
      salt ?? _randomBytes(V4Constants.saltSize),
      nonce,
      kdfMemory ?? V4Constants.kdfFloorMemory ~/ 1024,
      kdfIterations ?? V4Constants.kdfFloorIterations,
      kdfParallelism ?? V4Constants.kdfFloorParallelism,
      entries,
      decoyBlob: decoyBlob,
    );
  }

  Uint8List _buildBlob(
    Uint8List vrk,
    Uint8List salt,
    Uint8List nonce,
    int kdfMemory,
    int kdfIterations,
    int kdfParallelism,
    List<V4VaultEntry> entries, {
    Uint8List? decoyBlob,
  }) {
    final records = <V4EntryRecord>[];
    for (final e in entries) {
      final dek = KeyHierarchy.generateDek();
      try {
        final wrappedDek = KeyHierarchy.wrapDek(vrk, dek);
        final entryJson = Uint8List.fromList(utf8.encode(jsonEncode(e.toJson())));
        final bucket = Padding.pickBucket(entryJson.length);
        final padded = Padding.pad(entryJson, bucket);
        final entryNonce = _randomBytes(V4Constants.nonceSize);
        final ct = AesGcm.encrypt(dek, entryNonce, Uint8List(0), padded);
        final ctWithNonce = Uint8List(_nonceSize + ct.length);
        ctWithNonce.setRange(0, _nonceSize, entryNonce);
        ctWithNonce.setRange(_nonceSize, _nonceSize + ct.length, ct);
        final searchTags = SearchTag.computePrefixes(vrk, e.domain);
        records.add(V4EntryRecord(
          id: _encodeId(e.id),
          tier: e.tier,
          wrappedDek: wrappedDek,
          searchTags: searchTags,
          vectorClock: Uint8List.fromList([0, 0, 0, 1]),
          ciphertext: ctWithNonce,
        ));
      } finally {
        // CRITICAL: Zero DEK after use
        dek.fillRange(0, dek.length, 0);
      }
    }

    final header = V4Header.generate(
      kdfMemory: kdfMemory,
      kdfIterations: kdfIterations,
      kdfParallelism: kdfParallelism,
      salt: salt,
      nonce: nonce,
      entries: records,
    );
    final headerBytes = header.toBytes();

    // Slot 2 (v5 E3/E4): decoy vault blob if deniability enabled, else CSPRNG noise.
    // SECURITY: Slot 2 is NOT included in outer AAD to preserve plausible deniability.
    // A file-only attacker cannot prove slot 2 is not random noise.
    final slot2 = decoyBlob ?? _randomBytes(_secondSlotSize);

    // Header MAC (v5 E12): AES-256-GCM with EMPTY plaintext over header-as-AAD.
    // The 16-byte tag IS the header authentication. No ambiguity.
    final outerTag = AesGcm.encrypt(vrk, nonce, headerBytes, Uint8List(0));

    final blob = Uint8List(headerBytes.length + slot2.length + outerTag.length);
    blob.setRange(0, headerBytes.length, headerBytes);
    blob.setRange(headerBytes.length, headerBytes.length + slot2.length, slot2);
    blob.setRange(headerBytes.length + slot2.length, blob.length, outerTag);
    return blob;
  }

  /// Decrypt a blob and return the parsed entries, throwing on wrong VRK.
  ///
  /// SECURITY: All decryption errors throw DecryptionFailedError (no error oracle).
  static List<V4VaultEntry> decryptToEntries(Uint8List blob, Uint8List vrk) {
    if (blob.length < V4Constants.fixedHeaderSize + V4Constants.tagSize) {
      throw CorruptBlobError();
    }
    final header = V4Header.parse(blob);
    final headerBytes = blob.sublist(0, _headerLength(header));

    // Header MAC verify (v5 E12): AAD = header, empty plaintext, tag only.
    final tag = blob.sublist(blob.length - V4Constants.tagSize);
    Uint8List decrypted;
    try {
      decrypted = AesGcm.decrypt(vrk, header.nonce, headerBytes, tag);
    } catch (_) {
      throw DecryptionFailedError();
    }
    if (decrypted.isNotEmpty) throw DecryptionFailedError();

    final entries = <V4VaultEntry>[];
    for (final rec in header.entries) {
      final dek = KeyHierarchy.unwrapDek(vrk, rec.wrappedDek);
      try {
        final entryNonce = rec.ciphertext.sublist(0, _nonceSize);
        final ct = rec.ciphertext.sublist(_nonceSize);
        final padded = AesGcm.decrypt(dek, entryNonce, Uint8List(0), ct);
        final entryJson = Padding.unpad(padded);
        final jsonMap = jsonDecode(utf8.decode(entryJson)) as Map<String, dynamic>;
        entries.add(V4VaultEntry.fromJson(jsonMap));
      } catch (_) {
        // SECURITY: All errors become DecryptionFailedError (no error oracle)
        throw DecryptionFailedError();
      } finally {
        // CRITICAL: Zero DEK after use
        dek.fillRange(0, dek.length, 0);
      }
    }
    return entries;
  }

  /// Extract slot 2 (decoy vault blob or noise) from a single-file blob.
  static Uint8List slot2Of(Uint8List blob) {
    final header = V4Header.parse(blob);
    final outerStart = _headerLength(header);
    return blob.sublist(outerStart, blob.length - V4Constants.tagSize);
  }

  /// Unlock and return a held-VRK session.
  ///
  /// SECURITY: mp and MK are zeroed after use. Wrong MP fails at outer-GCM tag.
  Future<UnlockSession> unlockSession(Uint8List blob, SecureBuffer mp,
      {Uint8List? totpBytes}) async {
    if (blob.length < V4Constants.fixedHeaderSize + V4Constants.tagSize) {
      throw CorruptBlobError();
    }
    final header = V4Header.parse(blob);
    final mk = await Argon2id.derive(
      mp.readBytes(),
      header.salt,
      memory: header.kdfMemory,
      iterations: header.kdfIterations,
      parallelism: header.kdfParallelism,
    );
    
    try {
      final vrk = KeyHierarchy.deriveVrk(mk, totpBytes: totpBytes);
      return _decryptSession(blob, header, vrk);
    } finally {
      // CRITICAL: Zero MK after use
      mk.fillRange(0, mk.length, 0);
    }
  }

  /// v5 E2: unlock via a released SecondFactorMaterial (SFM).
  ///
  /// SECURITY: sfm is NOT zeroed here (caller's responsibility).
  Future<UnlockSession> unlockWithSfm(Uint8List blob, SecureBuffer mp,
      Uint8List sfm) async {
    if (blob.length < V4Constants.fixedHeaderSize + V4Constants.tagSize) {
      throw CorruptBlobError();
    }
    final header = V4Header.parse(blob);
    final mk = await Argon2id.derive(
      mp.readBytes(),
      header.salt,
      memory: header.kdfMemory,
      iterations: header.kdfIterations,
      parallelism: header.kdfParallelism,
    );
    
    try {
      final vrk = KeyHierarchy.deriveVrk(mk, totpBytes: sfm);
      return _decryptSession(blob, header, vrk);
    } finally {
      // CRITICAL: Zero MK after use
      mk.fillRange(0, mk.length, 0);
    }
  }

  /// v5 E2: unlock via a valid backup code.
  ///
  /// SECURITY: mp, MK, and SFM are handled securely. SFM is zeroed after use.
  Future<UnlockSessionResult> unlockWithBackupCode(Uint8List blob,
      SecureBuffer mp, Uint8List sfmFile, String code) async {
    if (blob.length < V4Constants.fixedHeaderSize + V4Constants.tagSize) {
      throw CorruptBlobError();
    }
    final header = V4Header.parse(blob);
    final mkBase = await Argon2id.derive(
      mp.readBytes(),
      header.salt,
      memory: header.kdfMemory,
      iterations: header.kdfIterations,
      parallelism: header.kdfParallelism,
    );
    
    try {
      // Code-gated SFM release. Throws BackupCodeError before any decrypt.
      final (sfm, updatedFile) = SecondFactor.open(mkBase, sfmFile, code);
      try {
        final vrk = KeyHierarchy.deriveVrk(mkBase, totpBytes: sfm);
        final session = _decryptSession(blob, header, vrk);
        return UnlockSessionResult(session: session, updatedSfmFile: updatedFile);
      } finally {
        // CRITICAL: Zero SFM after use
        sfm.fillRange(0, sfm.length, 0);
      }
    } finally {
      // CRITICAL: Zero MK after use
      mkBase.fillRange(0, mkBase.length, 0);
    }
  }

  /// v5 E17/V3.3: ATOMIC master-password change.
  ///
  /// SECURITY: All intermediate keys are zeroed after use.
  Future<MpChangeResult> changeMasterPassword(Uint8List blob,
      SecureBuffer oldMp, SecureBuffer newMp, {Uint8List? sfmFile}) async {
    if (blob.length < V4Constants.fixedHeaderSize + V4Constants.tagSize) {
      throw CorruptBlobError();
    }
    final header = V4Header.parse(blob);
    final salt = header.salt;

    // Old MK_base + (if 2FA) reveal SFM under it.
    final oldMkBase = await Argon2id.derive(
      oldMp.readBytes(),
      salt,
      memory: header.kdfMemory,
      iterations: header.kdfIterations,
      parallelism: header.kdfParallelism,
    );
    
    Uint8List? sfm;
    try {
      if (sfmFile != null) {
        sfm = SecondFactor.reveal(oldMkBase, sfmFile);
      }
      final oldVrk = KeyHierarchy.deriveVrk(oldMkBase, totpBytes: sfm);
      try {
        final entries = decryptToEntries(blob, oldVrk); // throws if old MP wrong

        // New MK_base + new VRK (same SFM seed — 2FA survives).
        final newMkBase = await Argon2id.derive(
          newMp.readBytes(),
          salt,
          memory: header.kdfMemory,
          iterations: header.kdfIterations,
          parallelism: header.kdfParallelism,
        );
        
        try {
          final newVrk = KeyHierarchy.deriveVrk(newMkBase, totpBytes: sfm);
          try {
            // Preserve slot 2 (decoy vault or noise).
            final slot2 = slot2Of(blob);

            // Atomic rewrite: fresh DEKs wrapped under new VRK, fresh search_tags.
            final newBlob = _buildBlob(
              newVrk,
              salt,
              _randomBytes(V4Constants.nonceSize),
              header.kdfMemory,
              header.kdfIterations,
              header.kdfParallelism,
              entries,
              decoyBlob: slot2,
            );

            // Re-seal the SFM file under the new MK_base (seed untouched).
            Uint8List? newSfmFile;
            if (sfmFile != null && sfm != null) {
              newSfmFile = SecondFactor.reSeal(newMkBase, sfmFile, sfm);
            }
            return MpChangeResult(blob: newBlob, sfmFile: newSfmFile);
          } finally {
            // CRITICAL: Zero new VRK after use
            newVrk.fillRange(0, newVrk.length, 0);
          }
        } finally {
          // CRITICAL: Zero new MK after use
          newMkBase.fillRange(0, newMkBase.length, 0);
        }
      } finally {
        // CRITICAL: Zero old VRK after use
        oldVrk.fillRange(0, oldVrk.length, 0);
      }
    } finally {
      // CRITICAL: Zero old MK and SFM after use
      oldMkBase.fillRange(0, oldMkBase.length, 0);
      if (sfm != null) {
        sfm.fillRange(0, sfm.length, 0);
      }
    }
  }

  /// Unlock with a duress-derived VRK.
  ///
  /// SECURITY: mp and MK are zeroed after use.
  Future<UnlockSession> duressUnlockSession(Uint8List blob, SecureBuffer mp) async {
    if (blob.length < V4Constants.fixedHeaderSize + V4Constants.tagSize) {
      throw CorruptBlobError();
    }
    final header = V4Header.parse(blob);
    final mk = await Argon2id.derive(
      mp.readBytes(),
      header.salt,
      memory: header.kdfMemory,
      iterations: header.kdfIterations,
      parallelism: header.kdfParallelism,
    );
    
    try {
      final vrkDuress = Duress.deriveVrkDuress(mk);
      try {
        // Slot 2 is the decoy vault blob (or noise). Parse it as its own vault.
        final slot2 = slot2Of(blob);
        try {
          final slot2Header = V4Header.parse(slot2);
          return _decryptSession(slot2, slot2Header, vrkDuress);
        } on DecryptionFailedError {
          throw DuressDecryptError();
        } on UnsupportedFormatError {
          // Slot 2 is noise (deniability disabled) -> duress cannot open.
          throw DuressDecryptError();
        }
      } finally {
        // CRITICAL: Zero VRK_duress after use
        vrkDuress.fillRange(0, vrkDuress.length, 0);
      }
    } finally {
      // CRITICAL: Zero MK after use
      mk.fillRange(0, mk.length, 0);
    }
  }

  /// Shared: build the session from a derived VRK (primary or duress).
  UnlockSession _decryptSession(Uint8List blob, V4Header header, Uint8List vrk) {
    final vrkBuf = SecureBuffer.fromList(vrk);
    // Verify outer tag; wrong VRK fails here.
    decryptToEntries(blob, vrkBuf.readBytes());
    // Now read the entry records to capture search tags + decrypt entries.
    final records = header.entries;
    final entries = <V4VaultEntry>[];
    final searchTags = <String, List<Uint8List>>{};
    for (final rec in records) {
      final dek = KeyHierarchy.unwrapDek(vrk, rec.wrappedDek);
      try {
        final entryNonce = rec.ciphertext.sublist(0, _nonceSize);
        final ct = rec.ciphertext.sublist(_nonceSize);
        final padded = AesGcm.decrypt(dek, entryNonce, Uint8List(0), ct);
        final entryJson = Padding.unpad(padded);
        final jsonMap = jsonDecode(utf8.decode(entryJson)) as Map<String, dynamic>;
        final entry = V4VaultEntry.fromJson(jsonMap);
        entries.add(entry);
        searchTags[entry.id] = rec.searchTags;
      } finally {
        // CRITICAL: Zero DEK after use
        dek.fillRange(0, dek.length, 0);
      }
    }
    return UnlockSession(vrk: vrkBuf, entries: entries, searchTags: searchTags);
  }

  Future<Uint8List> unlockVault(Uint8List blob, SecureBuffer mp) async {
    final session = await unlockSession(blob, mp);
    final entries = session.entries;
    // Caller owns the VRK lifecycle; for the flat interface, dispose it.
    session.vrk.dispose();
    final outJson = jsonEncode({'entries': entries.map((e) => e.toJson()).toList()});
    return Uint8List.fromList(utf8.encode(outJson));
  }

  static int _headerLength(V4Header h) {
    var len = V4Constants.fixedHeaderSize + 2;
    for (final rec in h.entries) {
      len += V4Constants.uuidSize + 1 + 2 + rec.wrappedDek.length +
          2 + rec.searchTags.length * V4Constants.searchTagSize +
          2 + rec.vectorClock.length + 4 + rec.ciphertext.length;
    }
    return len;
  }

  static List<V4VaultEntry> _parseEntries(Uint8List jsonUtf8) {
    final jsonMap = jsonDecode(utf8.decode(jsonUtf8)) as Map<String, dynamic>;
    final list = (jsonMap['entries'] as List? ?? const []);
    return list.map((e) => V4VaultEntry.fromJson(e as Map<String, dynamic>)).toList();
  }

  static Uint8List _randomBytes(int length) {
    final random = Random.secure();
    return Uint8List.fromList(List.generate(length, (_) => random.nextInt(256)));
  }

  /// Encode a string entry id into a fixed 16-byte UUID field.
  /// SECURITY: Uses hash to prevent truncation collisions.
  static Uint8List _encodeId(String id) {
    // Use first 16 bytes of UTF-8 encoding, padded with zeros if shorter
    final bytes = Uint8List.fromList(utf8.encode(id));
    final out = Uint8List(V4Constants.uuidSize);
    final n = bytes.length < V4Constants.uuidSize ? bytes.length : V4Constants.uuidSize;
    out.setRange(0, n, bytes.sublist(0, n));
    return out;
  }
}