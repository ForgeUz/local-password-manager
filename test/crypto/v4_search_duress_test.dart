import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/crypto/native/constant_time.dart';
import 'package:vault_crypto/src/crypto/v4/duress.dart';
import 'package:vault_crypto/src/crypto/v4/search_tag.dart';

// Intent: Verify search_tag computation (v4 §5.1) and duress derivation (v4 §5.3).
// Invariants: search_tag is deterministic; prefix tags match; duress VRK differs
// from primary VRK.
void main() {
  group('SearchTag', () {
    test('computes deterministic tag for a domain', () {
      final vrk = Uint8List.fromList(List.generate(32, (i) => i));
      final t1 = SearchTag.compute(vrk, 'github.com');
      final t2 = SearchTag.compute(vrk, 'github.com');
      expect(t1.length, 32);
      expect(ConstantTime.equals(t1, t2), isTrue);
    });

    test('prefix search returns matching tags', () {
      final vrk = Uint8List.fromList(List.generate(32, (i) => i));
      final tags = SearchTag.computePrefixes(vrk, 'github.com');
      // prefixes of length 3..10 (github.com = 10 chars)
      expect(tags.length, 8);
      // the full-domain tag must equal the single-domain tag
      expect(ConstantTime.equals(tags.last, SearchTag.compute(vrk, 'github.com')), isTrue);
    });

    test('tag count is bucket-padded (E13): domain length leaks only the bucket', () {
      final vrk = Uint8List.fromList(List.generate(32, (i) => i));
      // 'a.com' (5 chars) -> 3 prefix tags; 'verylongdomain.example.com' (24) -> 22.
      // Both pad to a bucket size (4 and 32) so exact length is not leaked.
      final short = SearchTag.computePrefixes(vrk, 'a.com');
      final long = SearchTag.computePrefixes(vrk, 'verylongdomain.example.com');
      expect(short.length, 4); // 3 prefixes -> bucket 4
      expect(long.length, 32); // 22 prefixes -> bucket 32
      // Both are valid bucket sizes.
      expect(const [4, 8, 16, 32, 64], contains(short.length));
      expect(const [4, 8, 16, 32, 64], contains(long.length));
    });
  });

  group('Duress', () {
    test('derives a VRK_duress different from primary VRK', () {
      final mk = Uint8List.fromList(List.generate(32, (i) => i));
      final mkDuress = Uint8List.fromList(List.generate(32, (i) => 0xFF - i));
      final vrk = Duress.deriveVrkDuress(mkDuress);
      expect(vrk.length, 32);
      // different MK -> different VRK
      final vrkPrimary = Duress.deriveVrkDuress(mk);
      expect(ConstantTime.equals(vrk, vrkPrimary), isFalse);
    });
  });
}