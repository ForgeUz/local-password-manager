import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/security/random_subset.dart';

// Intent: Verify random-subset decryption decoy selection (v4 §6.5).
// Rules: ~20% of non-Critical entries as decoys; Critical excluded; target
// excluded; vaults <5 entries skip decoys.
void main() {
  group('RandomSubset', () {
    test('selects ~20% of non-Critical entries as decoys', () {
      // 100 entries: 90 Standard/Sensitive, 10 Critical
      final entries =
          List.generate(100, (i) => i < 10 ? 2 : 0); // tier: 2=Critical
      final decoys = RandomSubset.selectDecoys(
        targetIndex: 0,
        tiers: entries,
        targetTier: 0,
      );
      // ~20% of 90 non-Critical = ~18
      expect(decoys.length, inInclusiveRange(10, 30));
      // Critical entries (indices 0-9) must never be decoys
      for (final d in decoys) {
        expect(entries[d], isNot(2));
      }
      // target (index 0) must not be a decoy
      expect(decoys.contains(0), isFalse);
    });

    test('vaults with fewer than 5 entries skip decoys', () {
      final entries = List.generate(4, (_) => 0);
      final decoys = RandomSubset.selectDecoys(
        targetIndex: 0,
        tiers: entries,
        targetTier: 0,
      );
      expect(decoys.isEmpty, isTrue);
    });

    test('Critical target still gets decoys from non-Critical', () {
      // 20 entries, target is Critical (index 0), rest Standard
      final entries = List.generate(20, (i) => i == 0 ? 2 : 0);
      final decoys = RandomSubset.selectDecoys(
        targetIndex: 0,
        tiers: entries,
        targetTier: 2,
      );
      expect(decoys.isNotEmpty, isTrue);
      for (final d in decoys) {
        expect(entries[d], isNot(2)); // never a Critical decoy
      }
    });
  });
}
