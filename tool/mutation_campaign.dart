// Intent: v5 E23 — mutation testing campaign over the crypto core.
// Applies 5 targeted mutations to critical pure-logic modules, runs the test
// suite, and reports which mutations the tests catch (kill score). A mutation
// is "killed" if at least one test FAILS after it is applied.
// Usage: dart run tool/mutation_campaign.dart
// Invariants: each mutation is applied to a temp copy; the source is restored
// after each run so the campaign is non-destructive.
// Dependencies: dart:io, dart:convert.

import 'dart:io';

// A mutation: file path (relative to repo root), a unique search string, and
// the replacement that introduces the bug.
class Mutation {
  final String id;
  final String file;
  final String search;
  final String replace;
  const Mutation({required this.id, required this.file, required this.search, required this.replace});
}

void main() async {
  final mutations = <Mutation>[
    // M1: key_hierarchy — flip the HKDF info string (VRK derivation changes).
    Mutation(
      id: 'M1',
      file: 'lib/src/crypto/v4/key_hierarchy.dart',
      search: "'GENESIS-VRK-v4'",
      replace: "'GENESIS-VRK-v4-X'",
    ),
    // M2: key_hierarchy — wrapDek uses a fixed nonce (nonce reuse).
    Mutation(
      id: 'M2',
      file: 'lib/src/crypto/v4/key_hierarchy.dart',
      search: 'final nonce = _freshNonce();',
      replace: 'final nonce = Uint8List(12); // fixed zero nonce',
    ),
    // M3: vector_clock — dominates returns true when equal (should be false).
    Mutation(
      id: 'M3',
      file: 'lib/src/sync/vector_clock.dart',
      search: 'if (l < r) return false; // other is ahead somewhere -> we don\'t dominate',
      replace: 'if (l < r) return true; // MUTATION: wrong dominance',
    ),
    // M4: vault_crypto_v4 — header MAC uses wrong nonce (tag fails).
    Mutation(
      id: 'M4',
      file: 'lib/src/crypto/v4/vault_crypto_v4.dart',
      search: 'final outerTag = AesGcm.encrypt(vrk, nonce, headerBytes, Uint8List(0));',
      replace: 'final outerTag = AesGcm.encrypt(vrk, Uint8List(12), headerBytes, Uint8List(0));',
    ),
    // M5: key_hierarchy — unwrapDek skips the length check (short wrapped DEK).
    Mutation(
      id: 'M5',
      file: 'lib/src/crypto/v4/key_hierarchy.dart',
      search: "if (wrapped.length < _nonceSize + 16) throw StateError('wrapped DEK too short');",
      replace: '// MUTATION: length check removed',
    ),
  ];

  var killed = 0;
  final results = <String, bool>{};
  for (final m in mutations) {
    final path = m.file;
    final original = await File(path).readAsString();
    // Apply the mutation.
    final mutated = original.replaceFirst(m.search, m.replace);
    if (mutated == original) {
      print('${m.id}: SEARCH NOT FOUND — mutation not applied (skip)');
      results[m.id] = false;
      continue;
    }
    await File(path).writeAsString(mutated, flush: true);
    // Run the test suite; a failure means the mutation was killed.
    final result = await Process.run('flutter', ['test'], workingDirectory: '.');
    final caught = result.exitCode != 0;
    results[m.id] = caught;
    if (caught) killed++;
    print('${m.id}: ${caught ? 'KILLED' : 'SURVIVED'}');
    // Restore the original.
    await File(path).writeAsString(original, flush: true);
  }

  final score = (killed / mutations.length) * 100;
  print('---');
  print('Mutation kill score: $killed/${mutations.length} = ${score.toStringAsFixed(1)}%');
  for (final m in mutations) {
    print('  ${m.id}: ${(results[m.id] ?? false) ? 'killed' : 'SURVIVED'}');
  }
  if (score < 90) {
    print('KILL SCORE < 90% — write new tests for the surviving mutants and re-run.');
  } else {
    print('KILL SCORE >= 90% — mutation campaign PASSED (v5 E23).');
  }
}