import 'dart:math';

// Intent: Random-subset decoy selection (v4 §6.5). When accessing a target
// entry, also decrypt ~20% of other non-Critical entries into secure memory to
// obscure which entry was actually accessed. Critical entries are EXCLUDED
// from the decoy set (they require M-of-N approval). Vaults with <5 entries
// skip decoys entirely.
// Pure function: no I/O, no side effects.
// Invariants: ~20% of non-Critical; Critical never a decoy; target never a
// decoy; <5 entries -> empty.
// Dependencies: dart:math.

class RandomSubset {
  static const int _decoyRatioPercent = 20;
  static const int _minVaultSize = 5;
  static const int _criticalTier = 2;

  // tiers: list of tier values (0=Standard, 1=Sensitive, 2=Critical).
  // Returns indices of decoy entries to decrypt alongside the target.
  static List<int> selectDecoys({
    required int targetIndex,
    required List<int> tiers,
    required int targetTier,
  }) {
    if (tiers.length < _minVaultSize) return const [];

    // Candidate decoys: non-Critical, not the target.
    final candidates = <int>[];
    for (var i = 0; i < tiers.length; i++) {
      if (i == targetIndex) continue;
      if (tiers[i] == _criticalTier) continue;
      candidates.add(i);
    }

    final decoyCount = (candidates.length * _decoyRatioPercent) ~/ 100;
    if (decoyCount == 0) return const [];

    final random = Random.secure();
    final decoys = <int>[];
    final pool = List<int>.of(candidates);
    for (var i = 0; i < decoyCount && pool.isNotEmpty; i++) {
      final idx = random.nextInt(pool.length);
      decoys.add(pool.removeAt(idx));
    }
    return decoys;
  }
}