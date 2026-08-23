import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/security/shamir_kit.dart';

// Intent: Verify ShamirKit splits a secret into N shares and reconstructs it
// from any K shares (SLIP-39 style, GF(256)). Opt-in recovery primitive.
void main() {
  test('split then reconstruct with all N shares returns the secret', () {
    final mk = Uint8List.fromList(List.generate(32, (i) => (i * 7 + 3) % 256));
    final shares = ShamirKit.split(mk, n: 5, k: 3);
    expect(shares.length, 5);
    final recovered = ShamirKit.reconstruct(shares);
    expect(recovered, equals(mk));
  });

  test('reconstruct works with any K of N shares', () {
    final mk = Uint8List.fromList(List.generate(32, (i) => (i * 13 + 1) % 256));
    final shares = ShamirKit.split(mk, n: 5, k: 3);
    // Use only the first 3 shares.
    final recovered = ShamirKit.reconstruct(shares.sublist(0, 3));
    expect(recovered, equals(mk));
  });

  test('reconstruct fails with fewer than K shares', () {
    final mk = Uint8List.fromList(List.generate(32, (i) => (i * 3 + 9) % 256));
    final shares = ShamirKit.split(mk, n: 5, k: 3);
    final recovered = ShamirKit.reconstruct(shares.sublist(0, 2));
    expect(recovered, isNot(equals(mk)));
  });
}