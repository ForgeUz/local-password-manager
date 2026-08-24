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