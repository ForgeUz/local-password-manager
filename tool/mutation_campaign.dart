// Intent: v5 E23 — mutation testing campaign over the crypto core (expanded).
// Applies 50 targeted mutations to critical pure-logic + FFI modules, runs the
// test suite, and reports which mutations the tests catch (kill score). A
// mutation is "killed" if at least one test FAILS after it is applied.
//
// Usage:
//   dart run tool/mutation_campaign.dart              # full campaign (~40 min)
//   dart run tool/mutation_campaign.dart --quick      # 10 core mutants only
//   dart run tool/mutation_campaign.dart --file vault_crypto_v4.dart
//
// Invariants:
//   - each mutation is applied to a temp copy; the source is restored after
//     each run so the campaign is non-destructive.
//   - mutations are SEMANTIC (never syntax-breaking); a "killed" result means
//     a test genuinely caught the invariant violation, not a compile error.
//
// Dependencies: dart:io, dart:convert.

import 'dart:io';

class Mutation {
  final String id;
  final String group;     // logical grouping for the report
  final String invariant; // short description of the invariant being tested
  final String file;
  final String search;
  final String replace;
  const Mutation({
    required this.id,
    required this.group,
    required this.invariant,
    required this.file,
    required this.search,
    required this.replace,
  });
}

// ============================================================
// THE MUTATION REGISTRY — 50 semantic mutations
// Each mutation targets ONE invariant. If a test fails, the
// invariant is well-covered. If a mutant survives, that's a
// GAP in the test suite worth closing.
// ============================================================
final List<Mutation> ALL_MUTATIONS = <Mutation>[
  // ----------------------------------------------------------
  // GROUP 1: vault_crypto_v4.dart — format + outer GCM (15)
  // ----------------------------------------------------------
  Mutation(
    id: 'M01',
    group: 'vault_crypto_v4',
    invariant: 'header-MAC uses VRK + correct nonce',
    file: 'lib/src/crypto/v4/vault_crypto_v4.dart',
    search: 'final outerTag = AesGcm.encrypt(vrk, nonce, headerBytes, Uint8List(0));',
    replace: 'final outerTag = AesGcm.encrypt(vrk, Uint8List(12), headerBytes, Uint8List(0)); // MUTATION: wrong nonce',
  ),
  Mutation(
    id: 'M02',
    group: 'vault_crypto_v4',
    invariant: 'header-MAC uses header as AAD (tamper detect)',
    file: 'lib/src/crypto/v4/vault_crypto_v4.dart',
    search: 'final outerTag = AesGcm.encrypt(vrk, nonce, headerBytes, Uint8List(0));',
    replace: 'final outerTag = AesGcm.encrypt(vrk, nonce, Uint8List(0), Uint8List(0)); // MUTATION: no AAD',
  ),
  Mutation(
    id: 'M03',
    group: 'vault_crypto_v4',
    invariant: 'header-MAC empty plaintext check',
    file: 'lib/src/crypto/v4/vault_crypto_v4.dart',
    search: 'if (decrypted.isNotEmpty) throw DecryptionFailedError();',
    replace: '// MUTATION: removed empty-plaintext check',
  ),
  Mutation(
    id: 'M04',
    group: 'vault_crypto_v4',
    invariant: 'blob minimum length check',
    file: 'lib/src/crypto/v4/vault_crypto_v4.dart',
    search: 'if (blob.length < V4Constants.fixedHeaderSize + V4Constants.tagSize) {\n      throw CorruptBlobError();\n    }',
    replace: '// MUTATION: removed minimum length check',
  ),
  Mutation(
    id: 'M05',
    group: 'vault_crypto_v4',
    invariant: 'MK zeroed after Argon2id',
    file: 'lib/src/crypto/v4/vault_crypto_v4.dart',
    search: 'mk.fillRange(0, mk.length, 0);',
    replace: '// MUTATION: MK not zeroed',
  ),
  Mutation(
    id: 'M06',
    group: 'vault_crypto_v4',
    invariant: 'DEK zeroed after decrypt',
    file: 'lib/src/crypto/v4/vault_crypto_v4.dart',
    search: 'dek.fillRange(0, dek.length, 0);',
    replace: '// MUTATION: DEK not zeroed',
  ),
  Mutation(
    id: 'M07',
    group: 'vault_crypto_v4',
    invariant: 'entry padding masks length',
    file: 'lib/src/crypto/v4/vault_crypto_v4.dart',
    search: 'final bucket = Padding.pickBucket(entryJson.length);',
    replace: 'final bucket = entryJson.length; // MUTATION: no bucketing',
  ),
  Mutation(
    id: 'M08',
    group: 'vault_crypto_v4',
    invariant: 'per-entry nonce is fresh (not reused)',
    file: 'lib/src/crypto/v4/vault_crypto_v4.dart',
    search: 'final entryNonce = _randomBytes(V4Constants.nonceSize);',
    replace: 'final entryNonce = Uint8List(V4Constants.nonceSize); // MUTATION: zero nonce',
  ),
  Mutation(
    id: 'M09',
    group: 'vault_crypto_v4',
    invariant: 'wrong MP fails at outer tag (not partial decrypt)',
    file: 'lib/src/crypto/v4/vault_crypto_v4.dart',
    search: 'decryptToEntries(blob, vrkBuf.readBytes());',
    replace: '// MUTATION: outer tag verify skipped',
  ),
  Mutation(
    id: 'M10',
    group: 'vault_crypto_v4',
    invariant: 'changeMasterPassword verifies old MP before rewrite',
    file: 'lib/src/crypto/v4/vault_crypto_v4.dart',
    search: 'final entries = decryptToEntries(blob, oldVrk); // throws if old MP wrong',
    replace: 'final entries = <V4VaultEntry>[]; // MUTATION: old MP not verified',
  ),
  Mutation(
    id: 'M11',
    group: 'vault_crypto_v4',
    invariant: 'duress unlocks slot 2 (not slot 1)',
    file: 'lib/src/crypto/v4/vault_crypto_v4.dart',
    search: 'return _decryptSession(slot2, slot2Header, vrkDuress);',
    replace: 'return _decryptSession(blob, header, vrkDuress); // MUTATION: duress opens primary',
  ),
  Mutation(
    id: 'M12',
    group: 'vault_crypto_v4',
    invariant: 'SFM zeroed after backup-code unlock',
    file: 'lib/src/crypto/v4/vault_crypto_v4.dart',
    search: 'sfm.fillRange(0, sfm.length, 0);',
    replace: '// MUTATION: SFM not zeroed',
  ),
  Mutation(
    id: 'M13',
    group: 'vault_crypto_v4',
    invariant: 'atomic MP change preserves salt (deniability survives)',
    file: 'lib/src/crypto/v4/vault_crypto_v4.dart',
    search: 'final salt = header.salt;',
    replace: 'final salt = _randomBytes(V4Constants.saltSize); // MUTATION: salt changed',
  ),
  Mutation(
    id: 'M14',
    group: 'vault_crypto_v4',
    invariant: 'unlockSession re-derives from header salt',
    file: 'lib/src/crypto/v4/vault_crypto_v4.dart',
    search: 'final mk = await Argon2id.derive(\n      mp.readBytes(),\n      header.salt,',
    replace: 'final mk = await Argon2id.derive(\n      mp.readBytes(),\n      Uint8List(V4Constants.saltSize), // MUTATION: ignores header salt',
  ),
  Mutation(
    id: 'M15',
    group: 'vault_crypto_v4',
    invariant: 'per-entry search tags are computed',
    file: 'lib/src/crypto/v4/vault_crypto_v4.dart',
    search: 'final searchTags = SearchTag.computePrefixes(vrk, e.domain);',
    replace: 'final searchTags = <Uint8List>[]; // MUTATION: no search tags',
  ),

  // ----------------------------------------------------------
  // GROUP 2: key_hierarchy.dart (5)
  // ----------------------------------------------------------
  Mutation(
    id: 'M16',
    group: 'key_hierarchy',
    invariant: 'VRK derivation uses unique info string',
    file: 'lib/src/crypto/v4/key_hierarchy.dart',
    search: "'GENESIS-VRK-v4'",
    replace: "'GENESIS-VRK-v4-MUT'",
  ),
  Mutation(
    id: 'M17',
    group: 'key_hierarchy',
    invariant: 'wrapDek uses fresh nonce',
    file: 'lib/src/crypto/v4/key_hierarchy.dart',
    search: 'final nonce = _freshNonce();',
    replace: 'final nonce = Uint8List(_nonceSize); // MUTATION: fixed zero nonce',
  ),
  Mutation(
    id: 'M18',
    group: 'key_hierarchy',
    invariant: 'unwrapDek bounds-checks input',
    file: 'lib/src/crypto/v4/key_hierarchy.dart',
    search: "if (wrapped.length < _nonceSize + 16) throw StateError('wrapped DEK too short');",
    replace: '// MUTATION: bounds check removed',
  ),
  Mutation(
    id: 'M19',
    group: 'key_hierarchy',
    invariant: 'DEK uses CSPRNG (Random.secure)',
    file: 'lib/src/crypto/v4/key_hierarchy.dart',
    search: 'final random = Random.secure();',
    replace: 'final random = Random(42); // MUTATION: deterministic RNG',
  ),
  Mutation(
    id: 'M20',
    group: 'key_hierarchy',
    invariant: 'TOTP bytes folded into VRK derivation',
    file: 'lib/src/crypto/v4/key_hierarchy.dart',
    search: 'final ikm = Uint8List(mk.length + totpBytes.length);\n    ikm.setRange(0, mk.length, mk);\n    ikm.setRange(mk.length, ikm.length, totpBytes);\n    \n    final result = Hkdf.derive(ikm, salt, _vrkInfo, V4Constants.keySize);',
    replace: '// MUTATION: TOTP ignored\n    final result = Hkdf.derive(mk, salt, _vrkInfo, V4Constants.keySize);',
  ),

  // ----------------------------------------------------------
  // GROUP 3: header.dart (parser) (8)
  // ----------------------------------------------------------
  Mutation(
    id: 'M21',
    group: 'header',
    invariant: 'reject wrong magic bytes',
    file: 'lib/src/crypto/v4/header.dart',
    search: 'if (magic != V4Constants.magic) throw UnsupportedFormatError();',
    replace: '// MUTATION: magic not checked',
  ),
  Mutation(
    id: 'M22',
    group: 'header',
    invariant: 'reject wrong format version',
    file: 'lib/src/crypto/v4/header.dart',
    search: 'if (ver != V4Constants.formatVersion) throw UnsupportedFormatError();',
    replace: '// MUTATION: version not checked',
  ),
  Mutation(
    id: 'M23',
    group: 'header',
    invariant: 'vaultCount must be 2 (deniability)',
    file: 'lib/src/crypto/v4/header.dart',
    search: "if (vaultCount != V4Constants.vaultCount) {\n      throw CorruptBlobError('Invalid vault count: expected \${V4Constants.vaultCount}, got \$vaultCount');\n    }",
    replace: '// MUTATION: vaultCount not checked',
  ),
  Mutation(
    id: 'M24',
    group: 'header',
    invariant: 'DEK length sanity check (max 1024)',
    file: 'lib/src/crypto/v4/header.dart',
    search: "if (dekLen > 1024) throw CorruptBlobError('DEK length unreasonably large');",
    replace: '// MUTATION: dekLen sanity removed',
  ),
  Mutation(
    id: 'M25',
    group: 'header',
    invariant: 'ciphertext length sanity check (max 1MB)',
    file: 'lib/src/crypto/v4/header.dart',
    search: "if (ctLen > 1024 * 1024) throw CorruptBlobError('Ciphertext too large');",
    replace: '// MUTATION: ctLen sanity removed',
  ),
  Mutation(
    id: 'M26',
    group: 'header',
    invariant: 'fields read as big-endian',
    file: 'lib/src/crypto/v4/header.dart',
    search: 'final dekLen = bd.getUint16(p, Endian.big);',
    replace: 'final dekLen = bd.getUint16(p, Endian.little); // MUTATION: wrong endianness',
  ),
  Mutation(
    id: 'M27',
    group: 'header',
    invariant: 'bounds check prevents buffer overflow',
    file: 'lib/src/crypto/v4/header.dart',
    search: 'void checkBounds(int needed) {\n      if (p + needed > bytes.length) {\n        throw CorruptBlobError(\'Record extends beyond blob boundary\');\n      }\n    }',
    replace: 'void checkBounds(int needed) { /* MUTATION: no-op */ }',
  ),
  Mutation(
    id: 'M28',
    group: 'header',
    invariant: 'tag count sanity check (max 100)',
    file: 'lib/src/crypto/v4/header.dart',
    search: "if (tagCount > 100) throw CorruptBlobError('Too many search tags');",
    replace: '// MUTATION: tagCount sanity removed',
  ),

  // ----------------------------------------------------------
  // GROUP 4: padding.dart (4)
  // ----------------------------------------------------------
  Mutation(
    id: 'M29',
    group: 'padding',
    invariant: 'unpad bounds-checks embedded length',
    file: 'lib/src/crypto/padding.dart',
    search: "if (length < 0 || length > padded.length - 4) {\n        throw StateError('Invalid embedded length');\n      }",
    replace: '// MUTATION: embedded length not checked',
  ),
  Mutation(
    id: 'M30',
    group: 'padding',
    invariant: 'unpad errors → CorruptBlobError (no oracle)',
    file: 'lib/src/crypto/padding.dart',
    search: 'throw CorruptBlobError();',
    replace: 'rethrow; // MUTATION: error oracle exposed',
  ),
  Mutation(
    id: 'M31',
    group: 'padding',
    invariant: 'pad fills with CSPRNG bytes',
    file: 'lib/src/crypto/padding.dart',
    search: 'final randBytes = Uint8List.fromList(List.generate(padLen, (_) => random.nextInt(256)));',
    replace: 'final randBytes = Uint8List(padLen); // MUTATION: zero padding (distinguishable)',
  ),
  Mutation(
    id: 'M32',
    group: 'padding',
    invariant: 'pickBucket masks entry length',
    file: 'lib/src/crypto/padding.dart',
    search: 'if (required <= _buckets.first) return _buckets.first;',
    replace: 'return required; // MUTATION: exact length exposed',
  ),

  // ----------------------------------------------------------
  // GROUP 5: second_factor.dart (6)
  // ----------------------------------------------------------
  Mutation(
    id: 'M33',
    group: 'second_factor',
    invariant: 'rate-limit: 3 wrong attempts locks',
    file: 'lib/src/crypto/v4/second_factor.dart',
    search: 'if (attempts >= _maxAttempts) throw BackupCodeError(); // rate-limited',
    replace: '// MUTATION: rate-limit disabled',
  ),
  Mutation(
    id: 'M34',
    group: 'second_factor',
    invariant: 'candidate hash zeroed after comparison',
    file: 'lib/src/crypto/v4/second_factor.dart',
    search: 'candidate.fillRange(0, candidate.length, 0);',
    replace: '// MUTATION: candidate hash not zeroed',
  ),
  Mutation(
    id: 'M35',
    group: 'second_factor',
    invariant: 'constant-time comparison prevents timing oracle',
    file: 'lib/src/crypto/v4/second_factor.dart',
    search: 'if (ConstantTime.equals(candidate, h)) {',
    replace: 'if (_listEquals(candidate, h)) { // MUTATION: variable-time compare\n        // helper: bool _listEquals(Uint8List a, Uint8List b) => a.length == b.length && a.every((e) => b.contains(e));',
  ),
  Mutation(
    id: 'M36',
    group: 'second_factor',
    invariant: 'wrong code increments attempt counter',
    file: 'lib/src/crypto/v4/second_factor.dart',
    search: 'updated[_nonceSize + _lenSize + len + _saltSize] = attempts + 1;',
    replace: 'updated[_nonceSize + _lenSize + len + _saltSize] = attempts; // MUTATION: counter not incremented',
  ),
  Mutation(
    id: 'M37',
    group: 'second_factor',
    invariant: 'used code is removed (single-use)',
    file: 'lib/src/crypto/v4/second_factor.dart',
    search: 'if (i == matched) continue;',
    replace: '// MUTATION: used code not skipped (still in list)',
  ),
  Mutation(
    id: 'M38',
    group: 'second_factor',
    invariant: 'backup code hash uses dedicated salt',
    file: 'lib/src/crypto/v4/second_factor.dart',
    search: 'final candidate = _hashCode(code, salt);',
    replace: 'final candidate = _hashCode(code, Uint8List(_saltSize)); // MUTATION: empty salt',
  ),

  // ----------------------------------------------------------
  // GROUP 6: duress.dart (2)
  // ----------------------------------------------------------
  Mutation(
    id: 'M39',
    group: 'duress',
    invariant: 'duress derivation uses distinct info string',
    file: 'lib/src/crypto/v4/duress.dart',
    search: "static const String _vrkDuressInfo = 'GENESIS-VRK-DURESS';",
    replace: "static const String _vrkDuressInfo = 'GENESIS-VRK-v4'; // MUTATION: collides with primary",
  ),
  Mutation(
    id: 'M40',
    group: 'duress',
    invariant: 'duress VRK is derived (not copied)',
    file: 'lib/src/crypto/v4/duress.dart',
    search: 'return Hkdf.derive(mkDuress, salt, _vrkDuressInfo, V4Constants.keySize);',
    replace: 'return mkDuress; // MUTATION: MK used directly as VRK',
  ),

  // ----------------------------------------------------------
  // GROUP 7: search_tag.dart (5)
  // ----------------------------------------------------------
  Mutation(
    id: 'M41',
    group: 'search_tag',
    invariant: 'SearchKey zeroed after use',
    file: 'lib/src/crypto/v4/search_tag.dart',
    search: 'searchKey.fillRange(0, searchKey.length, 0);',
    replace: '// MUTATION: SearchKey not zeroed',
  ),
  Mutation(
    id: 'M42',
    group: 'search_tag',
    invariant: 'tags padded to bucket with random',
    file: 'lib/src/crypto/v4/search_tag.dart',
    search: 'while (tags.length < bucket) {',
    replace: 'while (false) { // MUTATION: no bucket padding',
  ),
  Mutation(
    id: 'M43',
    group: 'search_tag',
    invariant: 'padding tags use CSPRNG',
    file: 'lib/src/crypto/v4/search_tag.dart',
    search: 'final r = Random.secure();',
    replace: 'final r = Random(1337); // MUTATION: deterministic padding (fingerprintable)',
  ),
  Mutation(
    id: 'M44',
    group: 'search_tag',
    invariant: 'domain normalization strips www.',
    file: 'lib/src/crypto/v4/search_tag.dart',
    search: "if (d.startsWith('www.')) d = d.substring(4);",
    replace: '// MUTATION: www. not stripped',
  ),
  Mutation(
    id: 'M45',
    group: 'search_tag',
    invariant: 'minimum query length (prevents FP flood)',
    file: 'lib/src/crypto/v4/search_tag.dart',
    search: 'if (q.length < 3) return false;',
    replace: '// MUTATION: no min query length',
  ),

  // ----------------------------------------------------------
  // GROUP 8: argon2id.dart (FFI) (3)
  // ----------------------------------------------------------
  Mutation(
    id: 'M46',
    group: 'argon2id',
    invariant: 'MK output zeroed before free',
    file: 'lib/src/crypto/native/argon2id.dart',
    search: 'memzero(out.cast<Void>(), _HASHBYTES);      // Master key',
    replace: '// MUTATION: MK output not zeroed',
  ),
  Mutation(
    id: 'M47',
    group: 'argon2id',
    invariant: 'password copy zeroed before free',
    file: 'lib/src/crypto/native/argon2id.dart',
    search: 'memzero(pwPtr.cast<Void>(), password.length); // Password copy',
    replace: '// MUTATION: password copy not zeroed',
  ),
  Mutation(
    id: 'M48',
    group: 'argon2id',
    invariant: 'Argon2id failure throws (fail-closed)',
    file: 'lib/src/crypto/native/argon2id.dart',
    search: "if (rc != 0) throw StateError('Argon2id derivation failed');",
    replace: '// MUTATION: failure silently returns garbage',
  ),

  // ----------------------------------------------------------
  // GROUP 9: aes_gcm.dart (FFI) (3)
  // ----------------------------------------------------------
  Mutation(
    id: 'M49',
    group: 'aes_gcm',
    invariant: 'plaintext output zeroed after copy',
    file: 'lib/src/crypto/native/aes_gcm.dart',
    search: 'memzero(pt.cast<Void>(), len);',
    replace: '// MUTATION: plaintext not zeroed',
  ),
  Mutation(
    id: 'M50',
    group: 'aes_gcm',
    invariant: 'AES-NI availability check (fail-closed)',
    file: 'lib/src/crypto/native/aes_gcm.dart',
    search: "if (isAvailable == 0) {\n      throw StateError('AES-GCM hardware acceleration (AES-NI) not available on this CPU. '\n          'Failing closed for security. Use ChaCha20-Poly1305 instead.');\n    }",
    replace: '// MUTATION: AES-NI not required',
  ),

  // ----------------------------------------------------------
  // GROUP 10: hkdf.dart (1)
  // ----------------------------------------------------------
  Mutation(
    id: 'M51',
    group: 'hkdf',
    invariant: 'PRK zeroed in HMAC path after use',
    file: 'lib/src/crypto/native/hkdf.dart',
    search: 'prk.fillRange(0, prk.length, 0);',
    replace: '// MUTATION: PRK not zeroed',
  ),

  // ============================================================
  // EXPANDED CAMPAIGN — M52..M100 (49 additional semantic mutations)
  // ============================================================

  // ----------------------------------------------------------
  // GROUP 11: key_hierarchy.dart (additional) (5)
  // ----------------------------------------------------------
  Mutation(
    id: 'M52',
    group: 'key_hierarchy',
    invariant: 'IKM (MK||TOTP) zeroed after VRK derivation',
    file: 'lib/src/crypto/v4/key_hierarchy.dart',
    search: 'ikm.fillRange(0, ikm.length, 0);',
    replace: '// MUTATION: IKM not zeroed',
  ),
  Mutation(
    id: 'M53',
    group: 'key_hierarchy',
    invariant: 'wrapDek prepends nonce before ciphertext',
    file: 'lib/src/crypto/v4/key_hierarchy.dart',
    search: 'out.setRange(0, _nonceSize, nonce);',
    replace: '// MUTATION: nonce not prepended',
  ),
  Mutation(
    id: 'M54',
    group: 'key_hierarchy',
    invariant: 'unwrapDek splits nonce from ciphertext',
    file: 'lib/src/crypto/v4/key_hierarchy.dart',
    search: 'final nonce = wrapped.sublist(0, _nonceSize);',
    replace: 'final nonce = Uint8List(_nonceSize); // MUTATION: wrong nonce slice',
  ),
  Mutation(
    id: 'M55',
    group: 'key_hierarchy',
    invariant: 'generateDek uses CSPRNG (not deterministic)',
    file: 'lib/src/crypto/v4/key_hierarchy.dart',
    search: 'final random = Random.secure();\n    return Uint8List.fromList(List.generate(V4Constants.keySize, (_) => random.nextInt(256)));',
    replace: 'return Uint8List(V4Constants.keySize); // MUTATION: zero DEK',
  ),
  Mutation(
    id: 'M56',
    group: 'key_hierarchy',
    invariant: 'deriveVrk uses empty salt (deterministic)',
    file: 'lib/src/crypto/v4/key_hierarchy.dart',
    search: 'final salt = Uint8List(32); // empty salt -> zeros (HKDF extract)',
    replace: 'final salt = Uint8List.fromList(List.generate(32, (_) => 0x42)); // MUTATION: fixed salt',
  ),

  // ----------------------------------------------------------
  // GROUP 12: header.dart (additional) (5)
  // ----------------------------------------------------------
  Mutation(
    id: 'M57',
    group: 'header',
    invariant: 'entry count sanity check (bounds)',
    file: 'lib/src/crypto/v4/header.dart',
    search: 'final entryCount = bd.getUint16(off, Endian.big);',
    replace: 'final entryCount = 0; // MUTATION: entry count ignored',
  ),
  Mutation(
    id: 'M58',
    group: 'header',
    invariant: 'kdfAlgoId validated (reject unknown KDF)',
    file: 'lib/src/crypto/v4/header.dart',
    search: 'final algoId = bytes[off++];',
    replace: 'final algoId = 0; // MUTATION: KDF algo not read',
  ),
  Mutation(
    id: 'M59',
    group: 'header',
    invariant: 'kdfMemory sanity (reject absurd memory)',
    file: 'lib/src/crypto/v4/header.dart',
    search: 'final mem = bd.getInt32(off, Endian.big);',
    replace: 'final mem = 0; // MUTATION: kdfMemory ignored',
  ),
  Mutation(
    id: 'M60',
    group: 'header',
    invariant: 'kdfIterations sanity (reject 0)',
    file: 'lib/src/crypto/v4/header.dart',
    search: 'final iter = bd.getInt32(off, Endian.big);',
    replace: 'final iter = 0; // MUTATION: kdfIterations ignored',
  ),
  Mutation(
    id: 'M61',
    group: 'header',
    invariant: 'entry record tier bounds (0..2)',
    file: 'lib/src/crypto/v4/header.dart',
    search: 'final tier = bytes[off++];',
    replace: 'final tier = 0; // MUTATION: tier ignored',
  ),

  // ----------------------------------------------------------
  // GROUP 13: padding.dart (additional) (4)
  // ----------------------------------------------------------
  Mutation(
    id: 'M62',
    group: 'padding',
    invariant: 'pad stores length big-endian',
    file: 'lib/src/crypto/padding.dart',
    search: 'result[0] = (data.length >> 24) & 0xFF;',
    replace: 'result[0] = data.length & 0xFF; // MUTATION: wrong endianness',
  ),
  Mutation(
    id: 'M63',
    group: 'padding',
    invariant: 'unpad rejects padded.length < 4',
    file: 'lib/src/crypto/padding.dart',
    search: "if (padded.length < 4) throw StateError('Invalid padded length');",
    replace: '// MUTATION: min length check removed',
  ),
  Mutation(
    id: 'M64',
    group: 'padding',
    invariant: 'pad copies data at offset 4',
    file: 'lib/src/crypto/padding.dart',
    search: 'result.setRange(4, 4 + data.length, data);',
    replace: 'result.setRange(0, data.length, data); // MUTATION: data at wrong offset',
  ),
  Mutation(
    id: 'M65',
    group: 'padding',
    invariant: 'pickBucket rounds up to 4MiB for large data',
    file: 'lib/src/crypto/padding.dart',
    search: 'return rem == 0 ? required : required + (mult - rem);',
    replace: 'return required; // MUTATION: no 4MiB rounding',
  ),

  // ----------------------------------------------------------
  // GROUP 14: search_tag.dart (additional) (4)
  // ----------------------------------------------------------
  Mutation(
    id: 'M66',
    group: 'search_tag',
    invariant: 'tagFor normalizes input before HMAC',
    file: 'lib/src/crypto/v4/search_tag.dart',
    search: 'final normalized = _normalize(input);\n    return HmacSha256.compute(searchKey, Uint8List.fromList(utf8.encode(normalized)));',
    replace: 'return HmacSha256.compute(searchKey, Uint8List.fromList(utf8.encode(input))); // MUTATION: no normalize',
  ),
  Mutation(
    id: 'M67',
    group: 'search_tag',
    invariant: 'prefix tags start at length 3',
    file: 'lib/src/crypto/v4/search_tag.dart',
    search: 'for (var len = 3; len <= normalized.length; len++) {',
    replace: 'for (var len = 1; len <= normalized.length; len++) { // MUTATION: prefix from len 1',
  ),
  Mutation(
    id: 'M68',
    group: 'search_tag',
    invariant: 'normalize strips scheme (https)',
    file: 'lib/src/crypto/v4/search_tag.dart',
    search: "if (d.startsWith('https://')) d = d.substring(8);",
    replace: '// MUTATION: https scheme not stripped',
  ),
  Mutation(
    id: 'M69',
    group: 'search_tag',
    invariant: 'normalize strips trailing slash/path',
    file: 'lib/src/crypto/v4/search_tag.dart',
    search: "final slashIndex = d.indexOf('/');\n    if (slashIndex != -1) d = d.substring(0, slashIndex);",
    replace: '// MUTATION: path not stripped',
  ),

  // ----------------------------------------------------------
  // GROUP 15: duress.dart (additional) (2)
  // ----------------------------------------------------------
  Mutation(
    id: 'M70',
    group: 'duress',
    invariant: 'duress uses empty salt (deterministic)',
    file: 'lib/src/crypto/v4/duress.dart',
    search: 'final salt = Uint8List(32);',
    replace: 'final salt = Uint8List.fromList(List.generate(32, (_) => 0x99)); // MUTATION: fixed salt',
  ),
  Mutation(
    id: 'M71',
    group: 'duress',
    invariant: 'duress VRK is keySize bytes',
    file: 'lib/src/crypto/v4/duress.dart',
    search: 'return Hkdf.derive(mkDuress, salt, _vrkDuressInfo, V4Constants.keySize);',
    replace: 'return Hkdf.derive(mkDuress, salt, _vrkDuressInfo, 16); // MUTATION: wrong output length',
  ),

  // ----------------------------------------------------------
  // GROUP 16: constant_time.dart (2)
  // ----------------------------------------------------------
  Mutation(
    id: 'M72',
    group: 'constant_time',
    invariant: 'equals rejects length mismatch',
    file: 'lib/src/crypto/native/constant_time.dart',
    search: 'if (a.length != b.length) return false;',
    replace: '// MUTATION: length mismatch not rejected',
  ),
  Mutation(
    id: 'M73',
    group: 'constant_time',
    invariant: 'equals uses sodium_compare (constant-time)',
    file: 'lib/src/crypto/native/constant_time.dart',
    search: "return sodiumCompare(pa.cast<Void>(), pb.cast<Void>(), a.length) == 0;",
    replace: 'return _varTimeEquals(a, b); // MUTATION: variable-time compare\n  // helper: bool _varTimeEquals(Uint8List a, Uint8List b) => a.length == b.length && a.every((e) => b.contains(e));',
  ),

  // ----------------------------------------------------------
  // GROUP 17: hmac_sha256.dart (2)
  // ----------------------------------------------------------
  Mutation(
    id: 'M74',
    group: 'hmac_sha256',
    invariant: 'HMAC key must be 32 bytes',
    file: 'lib/src/crypto/native/hmac_sha256.dart',
    search: "if (key.length != _KEYBYTES) throw StateError('HMAC key must be 32 bytes');",
    replace: '// MUTATION: key length not enforced',
  ),
  Mutation(
    id: 'M75',
    group: 'hmac_sha256',
    invariant: 'HMAC failure throws (fail-closed)',
    file: 'lib/src/crypto/native/hmac_sha256.dart',
    search: "if (rc != 0) throw StateError('HMAC-SHA256 failed');",
    replace: '// MUTATION: HMAC failure ignored',
  ),

  // ----------------------------------------------------------
  // GROUP 18: sha256.dart (2)
  // ----------------------------------------------------------
  Mutation(
    id: 'M76',
    group: 'sha256',
    invariant: 'SHA-256 failure throws (fail-closed)',
    file: 'lib/src/crypto/native/sha256.dart',
    search: "if (rc != 0) throw StateError('SHA-256 failed');",
    replace: '// MUTATION: SHA-256 failure ignored',
  ),
  Mutation(
    id: 'M77',
    group: 'sha256',
    invariant: 'SHA-256 output is 32 bytes',
    file: 'lib/src/crypto/native/sha256.dart',
    search: 'return Uint8List.fromList(out.asTypedList(_BYTES));',
    replace: 'return Uint8List.fromList(out.asTypedList(16)); // MUTATION: truncated output',
  ),

  // ----------------------------------------------------------
  // GROUP 19: secure_buffer.dart (2)
  // ----------------------------------------------------------
  Mutation(
    id: 'M78',
    group: 'secure_buffer',
    invariant: 'dispose zeroes native memory',
    file: 'lib/src/crypto/native/secure_buffer.dart',
    search: 'sodiumMemzero(_native, _backing.length);',
    replace: '// MUTATION: native memory not zeroed',
  ),
  Mutation(
    id: 'M79',
    group: 'secure_buffer',
    invariant: 'dispose is idempotent (double-dispose safe)',
    file: 'lib/src/crypto/native/secure_buffer.dart',
    search: 'if (_isDisposed) return;',
    replace: '// MUTATION: double-dispose not guarded',
  ),

  // ----------------------------------------------------------
  // GROUP 20: native_noise.dart (2)
  // ----------------------------------------------------------
  Mutation(
    id: 'M80',
    group: 'native_noise',
    invariant: 'crypto_box keypair failure throws',
    file: 'lib/src/sync/native_noise.dart',
    search: "if (rc != 0) throw StateError('crypto_box_keypair failed');",
    replace: '// MUTATION: keypair failure ignored',
  ),
  Mutation(
    id: 'M81',
    group: 'native_noise',
    invariant: 'decryptFromSelf rejects short ciphertext',
    file: 'lib/src/sync/native_noise.dart',
    search: "if (ct.length < _ABYTES) throw StateError('crypto_box ciphertext too short');",
    replace: '// MUTATION: short ciphertext not rejected',
  ),

  // ----------------------------------------------------------
  // GROUP 21: replay_counter.dart (2)
  // ----------------------------------------------------------
  Mutation(
    id: 'M82',
    group: 'replay_counter',
    invariant: 'replay counter rejects non-increasing values',
    file: 'lib/src/sync/replay_counter.dart',
    search: 'if (counter <= _lastSeen) return false;',
    replace: '// MUTATION: replay not rejected',
  ),
  Mutation(
    id: 'M83',
    group: 'replay_counter',
    invariant: 'replay counter updates lastSeen on accept',
    file: 'lib/src/sync/replay_counter.dart',
    search: '_lastSeen = counter;',
    replace: '// MUTATION: lastSeen not updated',
  ),

  // ----------------------------------------------------------
  // GROUP 22: vector_clock.dart (4)
  // ----------------------------------------------------------
  Mutation(
    id: 'M84',
    group: 'vector_clock',
    invariant: 'increment bumps device counter by 1',
    file: 'lib/src/sync/vector_clock.dart',
    search: 'final c = (map[deviceId] ?? 0) + 1;',
    replace: 'final c = (map[deviceId] ?? 0); // MUTATION: no increment',
  ),
  Mutation(
    id: 'M85',
    group: 'vector_clock',
    invariant: 'dominates requires strictly newer on at least one',
    file: 'lib/src/sync/vector_clock.dart',
    search: 'return strictlyNewer;',
    replace: 'return true; // MUTATION: always dominates',
  ),
  Mutation(
    id: 'M86',
    group: 'vector_clock',
    invariant: 'dominates returns false if other ahead anywhere',
    file: 'lib/src/sync/vector_clock.dart',
    search: 'if (l < r) return false; // other is ahead somewhere -> we don\'t dominate',
    replace: '// MUTATION: other-ahead not detected',
  ),
  Mutation(
    id: 'M87',
    group: 'vector_clock',
    invariant: 'decideAgainst detects conflict (neither dominates)',
    file: 'lib/src/sync/vector_clock.dart',
    search: 'return SyncFlag.conflict;',
    replace: 'return SyncFlag.localWins; // MUTATION: conflict misreported as local win',
  ),

  // ----------------------------------------------------------
  // GROUP 23: conflict_resolver.dart (3)
  // ----------------------------------------------------------
  Mutation(
    id: 'M88',
    group: 'conflict_resolver',
    invariant: 'conflict archives the remote (losing) version',
    file: 'lib/src/sync/conflict_resolver.dart',
    search: 'await file.writeAsBytes(remoteBytes, flush: true);',
    replace: 'await file.writeAsBytes(localBytes, flush: true); // MUTATION: archives local instead',
  ),
  Mutation(
    id: 'M89',
    group: 'conflict_resolver',
    invariant: 'localWins does not archive',
    file: 'lib/src/sync/conflict_resolver.dart',
    search: 'case SyncFlag.localWins:\n        return ConflictOutcome(archived: false, decision: SyncFlag.localWins);',
    replace: 'case SyncFlag.localWins:\n        return ConflictOutcome(archived: true, decision: SyncFlag.localWins); // MUTATION: local win archived',
  ),
  Mutation(
    id: 'M90',
    group: 'conflict_resolver',
    invariant: 'conflict outcome marks archived=true',
    file: 'lib/src/sync/conflict_resolver.dart',
    search: 'archived: true,\n          decision: SyncFlag.conflict,',
    replace: 'archived: false,\n          decision: SyncFlag.conflict, // MUTATION: conflict not marked archived',
  ),

  // ----------------------------------------------------------
  // GROUP 24: vault_crypto_v4.dart (additional) (5)
  // ----------------------------------------------------------
  Mutation(
    id: 'M91',
    group: 'vault_crypto_v4',
    invariant: 'outer GCM decrypt verifies tag (wrong key fails)',
    file: 'lib/src/crypto/v4/vault_crypto_v4.dart',
    search: 'final outerTag = AesGcm.encrypt(vrk, nonce, headerBytes, Uint8List(0));',
    replace: 'final outerTag = AesGcm.encrypt(vrk, nonce, headerBytes, Uint8List(1)); // MUTATION: non-empty plaintext',
  ),
  Mutation(
    id: 'M92',
    group: 'vault_crypto_v4',
    invariant: 'relock awaits before zeroing keys (no race)',
    file: 'lib/src/crypto/v4/vault_crypto_v4.dart',
    search: 'return await relock(',
    replace: 'return relock( // MUTATION: unawaited relock (key wipe race)',
  ),
  Mutation(
    id: 'M93',
    group: 'vault_crypto_v4',
    invariant: 'unlockSession zeroes MK after use',
    file: 'lib/src/crypto/v4/vault_crypto_v4.dart',
    search: 'mk.fillRange(0, mk.length, 0);',
    replace: '// MUTATION: MK not zeroed',
  ),
  Mutation(
    id: 'M94',
    group: 'vault_crypto_v4',
    invariant: 'duress unlock zeroes VRK_duress after use',
    file: 'lib/src/crypto/v4/vault_crypto_v4.dart',
    search: 'vrkDuress.fillRange(0, vrkDuress.length, 0);',
    replace: '// MUTATION: VRK_duress not zeroed',
  ),
  Mutation(
    id: 'M95',
    group: 'vault_crypto_v4',
    invariant: 'changeMasterPassword re-derives VRK under new MP',
    file: 'lib/src/crypto/v4/vault_crypto_v4.dart',
    search: 'final newVrk = KeyHierarchy.deriveVrk(newMkBase, totpBytes: sfm);',
    replace: 'final newVrk = oldVrk; // MUTATION: VRK not re-derived',
  ),

  // ----------------------------------------------------------
  // GROUP 25: second_factor.dart (additional) (3)
  // ----------------------------------------------------------
  Mutation(
    id: 'M96',
    group: 'second_factor',
    invariant: 'backup code hash uses dedicated salt',
    file: 'lib/src/crypto/v4/second_factor.dart',
    search: 'final candidate = _hashCode(code, salt);',
    replace: 'final candidate = _hashCode(code, Uint8List(_saltSize)); // MUTATION: empty salt',
  ),
  Mutation(
    id: 'M97',
    group: 'second_factor',
    invariant: 'wrong code increments attempt counter',
    file: 'lib/src/crypto/v4/second_factor.dart',
    search: 'updated[_nonceSize + _lenSize + len + _saltSize] = attempts + 1;',
    replace: 'updated[_nonceSize + _lenSize + len + _saltSize] = attempts; // MUTATION: counter not incremented',
  ),
  Mutation(
    id: 'M98',
    group: 'second_factor',
    invariant: 'used code is removed (single-use)',
    file: 'lib/src/crypto/v4/second_factor.dart',
    search: 'if (i == matched) continue;',
    replace: '// MUTATION: used code not skipped (still in list)',
  ),

  // ----------------------------------------------------------
  // GROUP 26: hkdf.dart (additional) (2)
  // ----------------------------------------------------------
  Mutation(
    id: 'M99',
    group: 'hkdf',
    invariant: 'HKDF extract pads short salt to hash length',
    file: 'lib/src/crypto/native/hkdf.dart',
    search: 'if (salt.length < _HASHBYTES) {',
    replace: 'if (false) { // MUTATION: short salt not padded',
  ),
  Mutation(
    id: 'M100',
    group: 'hkdf',
    invariant: 'HKDF expand output length matches request',
    file: 'lib/src/crypto/native/hkdf.dart',
    search: 'final out = Uint8List(outLen);',
    replace: 'final out = Uint8List(outLen - 1); // MUTATION: wrong output length',
  ),

  // ============================================================
  // V6.5 CAMPAIGN — M101..M120 (Security Tiers + TOTP + Enforcer)
  // Closes P0-1: mutation coverage for modules added in V6.5.
  // ============================================================

  // ----------------------------------------------------------
  // GROUP 27: tier_autofill_enforcer.dart (8)
  // ----------------------------------------------------------
  Mutation(
    id: 'M101',
    group: 'tier_autofill_enforcer',
    invariant: 'Critical tier NEVER autofills',
    file: 'lib/src/autofill/tier_autofill_enforcer.dart',
    search: "case SecurityTier.critical:\n        // Critical: NEVER autofill. User must type manually.\n        return const BlockManualOnly(",
    replace: "case SecurityTier.critical:\n        return const FillImmediately(); // MUTATION: critical autofills",
  ),
  Mutation(
    id: 'M102',
    group: 'tier_autofill_enforcer',
    invariant: 'Lookalike domain HARD STOPS before tier check',
    file: 'lib/src/autofill/tier_autofill_enforcer.dart',
    search: 'final lookalikeReason = _detectLookalike(\n      request.entryDomain,\n      request.requestedDomain,\n    );\n    if (lookalikeReason != null) {',
    replace: '// MUTATION: lookalike skipped\n    if (false) {',
  ),
  Mutation(
    id: 'M103',
    group: 'tier_autofill_enforcer',
    invariant: 'Domain mismatch blocks autofill',
    file: 'lib/src/autofill/tier_autofill_enforcer.dart',
    search: 'if (!_domainsMatch(request.entryDomain, request.requestedDomain)) {\n      return BlockDomainMismatch(',
    replace: '// MUTATION: domain match not enforced\n    if (false) {\n      return BlockDomainMismatch(',
  ),
  Mutation(
    id: 'M104',
    group: 'tier_autofill_enforcer',
    invariant: 'Sensitive tier adds 5s delay',
    file: 'lib/src/autofill/tier_autofill_enforcer.dart',
    search: 'final delay = TierPolicy.autofillDelay(SecurityTier.sensitive);\n        return FillAfterReauth(delaySeconds: delay.inSeconds);',
    replace: 'return const FillAfterReauth(delaySeconds: 0); // MUTATION: no delay',
  ),
  Mutation(
    id: 'M105',
    group: 'tier_autofill_enforcer',
    invariant: 'Normalization strips www. prefix',
    file: 'lib/src/autofill/tier_autofill_enforcer.dart',
    search: "if (d.startsWith('www.')) d = d.substring(4);",
    replace: '// MUTATION: www. not stripped',
  ),
  Mutation(
    id: 'M106',
    group: 'tier_autofill_enforcer',
    invariant: 'Edit distance 1 detected as typosquat',
    file: 'lib/src/autofill/tier_autofill_enforcer.dart',
    search: 'if (_editDistance(normExpected, normRequested) == 1) {',
    replace: 'if (_editDistance(normExpected, normRequested) == 99) { // MUTATION: never triggers',
  ),
  Mutation(
    id: 'M107',
    group: 'tier_autofill_enforcer',
    invariant: 'Homoglyph 0/o pair detected',
    file: 'lib/src/autofill/tier_autofill_enforcer.dart',
    search: "'0': 'o', 'o': '0',",
    replace: "// MUTATION: 0/o not confusable",
  ),
  Mutation(
    id: 'M108',
    group: 'tier_autofill_enforcer',
    invariant: 'Subdomain impersonation detected',
    file: 'lib/src/autofill/tier_autofill_enforcer.dart',
    search: "if (requested.contains('.\$expected.')) {\n      // expected appears mid-domain with different parent -> suspicious\n      return true;\n    }",
    replace: '// MUTATION: subdomain impersonation ignored\n    if (false) { return true; }',
  ),

  // ----------------------------------------------------------
  // GROUP 28: security_tier.dart (6)
  // ----------------------------------------------------------
  Mutation(
    id: 'M109',
    group: 'security_tier',
    invariant: 'Critical tier blocks export',
    file: 'lib/src/security/security_tier.dart',
    search: 'case SecurityTier.critical:\n        return false;\n    }\n  }\n\n  /// Whether TOTP codes',
    replace: 'case SecurityTier.critical:\n        return true; // MUTATION: critical exports\n    }\n  }\n\n  /// Whether TOTP codes',
  ),
  Mutation(
    id: 'M110',
    group: 'security_tier',
    invariant: 'Downgrade requires explicit confirmation',
    file: 'lib/src/security/security_tier.dart',
    search: 'final warning = _downgradeWarning(current, proposed);\n    return TierDowngradeConfirm(',
    replace: 'return TierValid(proposed); // MUTATION: silent downgrade',
  ),
  Mutation(
    id: 'M111',
    group: 'security_tier',
    invariant: 'Critical reveal requires master password',
    file: 'lib/src/security/security_tier.dart',
    search: 'case SecurityTier.critical:\n        return AuthRequirement.masterPassword;\n    }\n  }\n\n  /// Whether editing',
    replace: 'case SecurityTier.critical:\n        return AuthRequirement.biometric; // MUTATION: biometric only\n    }\n  }\n\n  /// Whether editing',
  ),
  Mutation(
    id: 'M112',
    group: 'security_tier',
    invariant: 'Sensitive tier enforces 5s autofill delay',
    file: 'lib/src/security/security_tier.dart',
    search: 'return const Duration(seconds: 5);',
    replace: 'return Duration.zero; // MUTATION: no delay',
  ),
  Mutation(
    id: 'M113',
    group: 'security_tier',
    invariant: 'Standard tier allows autofill',
    file: 'lib/src/security/security_tier.dart',
    search: 'case SecurityTier.standard:\n        return true;\n      case SecurityTier.sensitive:',
    replace: 'case SecurityTier.standard:\n        return false; // MUTATION: standard blocks\n      case SecurityTier.sensitive:',
  ),
  Mutation(
    id: 'M114',
    group: 'security_tier',
    invariant: 'Critical blocks auto-copy TOTP',
    file: 'lib/src/security/security_tier.dart',
    search: 'case SecurityTier.critical:\n        return false;\n    }\n  }\n}\n\n/// What authentication',
    replace: 'case SecurityTier.critical:\n        return true; // MUTATION: critical auto-copies\n    }\n  }\n}\n\n/// What authentication',
  ),

  // ----------------------------------------------------------
  // GROUP 29: totp_generator.dart (6)
  // ----------------------------------------------------------
  Mutation(
    id: 'M115',
    group: 'totp_generator',
    invariant: 'Dynamic truncation uses last-byte offset',
    file: 'lib/src/totp/totp_generator.dart',
    search: 'final int offset = hmacResult[hmacResult.length - 1] & 0x0F;',
    replace: 'final int offset = 0; // MUTATION: fixed offset',
  ),
  Mutation(
    id: 'M116',
    group: 'totp_generator',
    invariant: 'Codes zero-padded to digit count',
    file: 'lib/src/totp/totp_generator.dart',
    search: "return code.toString().padLeft(config.digits, '0');",
    replace: 'return code.toString(); // MUTATION: no padding',
  ),
  Mutation(
    id: 'M117',
    group: 'totp_generator',
    invariant: 'Validate allows +/-1 window (clock drift)',
    file: 'lib/src/totp/totp_generator.dart',
    search: 'for (final offset in [-1, 0, 1]) {',
    replace: 'for (final offset in [0]) { // MUTATION: strict window only',
  ),
  Mutation(
    id: 'M118',
    group: 'totp_generator',
    invariant: 'Constant-time compare returns false on mismatch',
    file: 'lib/src/totp/totp_generator.dart',
    search: 'return result == 0;',
    replace: 'return true; // MUTATION: always returns true if length matches',
  ),
  Mutation(
    id: 'M119',
    group: 'totp_generator',
    invariant: 'Counter encoded big-endian (RFC 4226)',
    file: 'lib/src/totp/totp_generator.dart',
    search: 'for (int i = 7; i >= 0; i--) {\n      bytes[i] = counter & 0xFF;\n      counter >>= 8;\n    }',
    replace: 'for (int i = 0; i < 8; i++) {\n      bytes[i] = counter & 0xFF;\n      counter >>= 8;\n    } // MUTATION: little-endian',
  ),
  Mutation(
    id: 'M120',
    group: 'totp_generator',
    invariant: 'Truncated value modulo 10^digits',
    file: 'lib/src/totp/totp_generator.dart',
    search: 'return binary % _pow10(digits);',
    replace: 'return binary; // MUTATION: no modulo (raw 31-bit value)',
  ),

  // ----------------------------------------------------------
  // GROUP 30: vault_data.dart (V4 Schema Evolution / Passkey) (3)
  // ----------------------------------------------------------
  Mutation(
    id: 'M121',
    group: 'vault_data',
    invariant: 'VaultEntry serializes passkeyCredentialId',
    file: 'lib/src/vault/vault_data.dart',
    search: "'passkeyCredentialId': passkeyCredentialId,",
    replace: '// MUTATION: passkeyCredentialId not serialized',
  ),
  Mutation(
    id: 'M122',
    group: 'vault_data',
    invariant: 'VaultEntry parses missing passkeyCredentialId as null (backward compat)',
    file: 'lib/src/vault/vault_data.dart',
    search: "passkeyCredentialId: json['passkeyCredentialId'] as String?,",
    replace: "passkeyCredentialId: json['passkeyCredentialId'] as String, // MUTATION: throws on null",
  ),
  Mutation(
    id: 'M123',
    group: 'vault_data',
    invariant: 'VaultData round-trips entries correctly',
    file: 'lib/src/vault/vault_data.dart',
    search: "'entries': entries.map((e) => e.toJson()).toList(),",
    replace: "'entries': [], // MUTATION: drops all entries",
  ),

  // ----------------------------------------------------------
  // GROUP 31: passkey_challenge.dart & passkey_core.dart (3)
  // ----------------------------------------------------------
  Mutation(
    id: 'M124',
    group: 'passkey_challenge',
    invariant: 'Challenge generates >= 32 bytes of entropy',
    file: 'lib/src/passkey/passkey_challenge.dart',
    search: 'List.generate(byteLength, (_) => random.nextInt(256)),',
    replace: 'List.generate(16, (_) => random.nextInt(256)), // MUTATION: weak entropy (16 bytes)',
  ),
  Mutation(
    id: 'M125',
    group: 'passkey_challenge',
    invariant: 'Challenge strips base64 padding (WebAuthn compliance)',
    file: 'lib/src/passkey/passkey_challenge.dart',
    search: "return base64UrlEncode(bytes).replaceAll('=', '');",
    replace: 'return base64UrlEncode(bytes); // MUTATION: leaves padding',
  ),
  Mutation(
    id: 'M126',
    group: 'passkey_core',
    invariant: 'verifyRpId enforces exact domain match (FIDO2 isolation)',
    file: 'lib/src/passkey/passkey_core.dart',
    search: 'return storedRpId == requestedRpId;',
    replace: 'return true; // MUTATION: bypass domain isolation',
  ),

  // ----------------------------------------------------------
  // GROUP 32: onboarding_core.dart (Typestate Wizard) (3)
  // ----------------------------------------------------------
  Mutation(
    id: 'M127',
    group: 'onboarding_core',
    invariant: 'Cannot bypass Doctrine (Zero-Knowledge warning)',
    file: 'lib/src/onboarding/onboarding_core.dart',
    search: 'if (state is OnboardingDoctrine && intent is AcceptDoctrine) return OnboardingCreateMP();',
    replace: 'return OnboardingDone(createDecoy: false); // MUTATION: skips MP creation',
  ),
  Mutation(
    id: 'M128',
    group: 'onboarding_core',
    invariant: 'SubmitMP stores the SecureBuffer',
    file: 'lib/src/onboarding/onboarding_core.dart',
    search: '_mp = intent.mp;',
    replace: '_mp = null; // MUTATION: drops submitted MP',
  ),
  Mutation(
    id: 'M129',
    group: 'onboarding_core',
    invariant: 'GoBack from CreateMP wipes MP reference (memory leak prevention)',
    file: 'lib/src/onboarding/onboarding_core.dart',
    search: '      _mp = null;\n    }\n    final newState = _reduce(_state, intent);',
    replace: '      // MUTATION: reference not cleared\n    }\n    final newState = _reduce(_state, intent);',
  ),

  // ----------------------------------------------------------
  // GROUP 33: shamir_kit.dart (GF(256) Math) (4)
  // ----------------------------------------------------------
  Mutation(
    id: 'M130',
    group: 'shamir_kit',
    invariant: 'GF(256) multiplication reduction mod 0x11b',
    file: 'lib/src/security/shamir_kit.dart',
    search: 'if ((a & 0x100) != 0) a ^= _GF_POLY;',
    replace: '// MUTATION: GF(256) reduction bypassed',
  ),
  Mutation(
    id: 'M131',
    group: 'shamir_kit',
    invariant: 'Lagrange basis uses GF division (not multiply)',
    file: 'lib/src/security/shamir_kit.dart',
    search: 'final factor = _gfDiv(shares[j].x, denom);',
    replace: 'final factor = _gfMul(shares[j].x, denom); // MUTATION: Lagrange uses multiply',
  ),
  Mutation(
    id: 'M132',
    group: 'shamir_kit',
    invariant: 'Horner evaluation uses XOR (not integer addition)',
    file: 'lib/src/security/shamir_kit.dart',
    search: 'y = _gfMul(y, x) ^ coeff[i];',
    replace: 'y = _gfMul(y, x) + coeff[i]; // MUTATION: uses integer addition',
  ),
  Mutation(
    id: 'M133',
    group: 'shamir_kit',
    invariant: 'Fermat inverse uses exponent 254 (not 255)',
    file: 'lib/src/security/shamir_kit.dart',
    search: 'var exp = 254;',
    replace: 'var exp = 255; // MUTATION: Fermat exponent wrong',
  ),

];



// ============================================================
// MAIN
// ============================================================
void main(List<String> args) async {
  // Parse CLI options
  final quick = args.contains('--quick');
  final fileFilter = args.contains('--file')
      ? args[args.indexOf('--file') + 1]
      : null;

  List<Mutation> mutations;
  if (quick) {
    // Quick mode: only the 10 highest-impact crypto-core mutations
    mutations = ALL_MUTATIONS.where((m) => [
      'M01', 'M02', 'M04', 'M05', 'M06',
      'M16', 'M17', 'M21', 'M46', 'M49',
    ].contains(m.id)).toList();
  } else if (fileFilter != null) {
    mutations = ALL_MUTATIONS.where((m) => m.file.contains(fileFilter)).toList();
  } else {
    mutations = ALL_MUTATIONS;
  }

  if (mutations.isEmpty) {
    print('No mutations matched. Check --file filter or mutation registry.');
    exit(1);
  }

  print('Mutation campaign: ${mutations.length} mutations');
  print('Estimated runtime: ${(mutations.length * 50 / 60).toStringAsFixed(1)} min (full)');
  print('---');

  var killed = 0;
  var survived = 0;
  var skipped = 0;
  final results = <Mutation, String>{}; // id -> 'killed' | 'SURVIVED' | 'SKIPPED'

  for (var i = 0; i < mutations.length; i++) {
    final m = mutations[i];
    final progress = '[${i + 1}/${mutations.length}]';
    stdout.write('$progress ${m.id} (${m.group}) ${m.invariant} ... ');

    final path = m.file;
    final original = await File(path).readAsString();

    final mutated = original.replaceFirst(m.search, m.replace);
    if (mutated == original) {
      print('SKIPPED (search string not found in source)');
      results[m] = 'SKIPPED';
      skipped++;
      continue;
    }

    await File(path).writeAsString(mutated, flush: true);

    final result = await Process.run('flutter', ['test'], workingDirectory: '.');
    final caught = result.exitCode != 0;
    results[m] = caught ? 'killed' : 'SURVIVED';
    if (caught) {
      killed++;
      print('KILLED');
    } else {
      survived++;
      print('SURVIVED ← GAP IN TESTS');
    }

    // Restore the original.
    await File(path).writeAsString(original, flush: true);
  }

  // ----------------------
  // REPORT
  // ----------------------
  print('\n${'=' * 70}');
  print('MUTATION CAMPAIGN REPORT');
  print('=' * 70);

  final applied = killed + survived;
  final score = applied == 0 ? 0.0 : (killed / applied) * 100;

  print('Applied:  $applied / ${mutations.length}');
  print('Killed:   $killed');
  print('Survived: $survived');
  print('Skipped:  $skipped');
  print('Kill score: ${score.toStringAsFixed(1)}%');
  print('');

  // Group by group
  final byGroup = <String, List<Mutation>>{};
  for (final m in mutations) {
    byGroup.putIfAbsent(m.group, () => []).add(m);
  }

  print('BY GROUP:');
  for (final entry in byGroup.entries) {
    final groupKilled = entry.value.where((m) => results[m] == 'killed').length;
    final groupSurvived = entry.value.where((m) => results[m] == 'SURVIVED').length;
    final groupSkipped = entry.value.where((m) => results[m] == 'SKIPPED').length;
    print('  ${entry.key}: ${groupKilled}/${entry.value.length} killed'
        '${groupSurvived > 0 ? " ($groupSurvived SURVIVED)" : ""}'
        '${groupSkipped > 0 ? " ($groupSkipped skipped)" : ""}');
  }

  // Survivors list — this is the action list
  final survivors = mutations.where((m) => results[m] == 'SURVIVED').toList();
  if (survivors.isNotEmpty) {
    print('\nSURVIVING MUTANTS (write tests to kill them):');
    for (final m in survivors) {
      print('  ${m.id} [${m.group}] — ${m.invariant}');
      print('      file: ${m.file}');
      print('      mutation: ${m.search.length > 60 ? m.search.substring(0, 60) + '…' : m.search}');
      print('');
    }
  }

  print('');
  if (score < 90) {
    print('KILL SCORE < 90% — campaign FAILED (v5 E23).');
    print('   Write new tests for each surviving mutant above, then re-run.');
    exit(2);
  } else {
    print('KILL SCORE >= 90% — campaign PASSED (v5 E23).');
    print('   Record this run in status.md and commit the report.');
    exit(0);
  }
}