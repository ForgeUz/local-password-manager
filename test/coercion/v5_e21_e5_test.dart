import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/coercion/cancellation.dart';
import 'package:vault_crypto/src/coercion/group_shred.dart';
import 'package:vault_crypto/src/security/shamir_kit.dart';

bool _throws<T>(T Function() fn) {
  try {
    fn();
    return false;
  } catch (_) {
    return true;
  }
}

// Intent: v5 E21 (cancellation code storage + rate limit) and E5 (group shred
// for Shamir-split Critical DEKs). E21: code Argon2id-hashed, 3 wrong attempts
// -> full duress re-setup. E5: SHRED_SCHEDULED to all holders; each destroys
// its share; unrecoverable when surviving < K.
void main() {
  group('v5 E21 cancellation code', () {
    test('code verified via Argon2id hash; wrong code fails', () {
      final stored = CancellationCode.setup('12345678');
      expect(CancellationCode.verify('12345678', stored), isTrue);
      expect(CancellationCode.verify('87654321', stored), isFalse);
    });

    test('3 wrong attempts -> locked (re-setup required)', () {
      final stored = CancellationCode.setup('12345678');
      // 2 wrong attempts: still not locked, but counter increments.
      expect(CancellationCode.verify('00000000', stored), isFalse);
      expect(CancellationCode.verify('11111111', stored), isFalse);
      // 3rd wrong attempt -> locked.
      expect(
          _throws(() => CancellationCode.verify('22222222', stored)), isTrue);
      // Even the correct code is now rejected (locked).
      expect(
          _throws(() => CancellationCode.verify('12345678', stored)), isTrue);
    });
  });

  group('v5 E5 group shred', () {
    test('3 devices: A schedules, A+B destroy -> unrecoverable (1 < K=2)', () {
      // Split a Critical DEK into 3 shares (2-of-3).
      final dek = Uint8List.fromList(List.generate(32, (i) => i));
      final shares = ShamirKit.split(dek, n: 3, k: 2);
      final deviceShares = <String, Share>{
        'A': shares[0],
        'B': shares[1],
        'C': shares[2],
      };

      // Device A schedules shred on all holders (SHRED_SCHEDULED broadcast).
      final orders = GroupShred.schedule(
        deviceIds: ['A', 'B', 'C'],
        deadlineEpochMillis: 1000,
      );
      expect(orders.length, 3);
      expect(orders.every((o) => o.deadlineEpochMillis == 1000), isTrue);

      // A and B destroy their local shares at the deadline.
      var surviving = shares.length;
      surviving = GroupShred.destroyShare(
          shares: shares, deviceId: 'A', deviceShares: deviceShares);
      surviving = GroupShred.destroyShare(
          shares: shares, deviceId: 'B', deviceShares: deviceShares);

      // 1 surviving share < K=2 -> unrecoverable.
      expect(surviving, 1);
      expect(
          GroupShred.isUnrecoverable(survivingShares: surviving, k: 2), isTrue);
      // Reconstruction from the single surviving share cannot recover the DEK.
      final recovered = ShamirKit.reconstruct(shares);
      expect(recovered, isNot(equals(dek)));
    });

    test('not unrecoverable while surviving >= K', () {
      final dek = Uint8List.fromList(List.generate(32, (i) => i));
      final shares = ShamirKit.split(dek, n: 3, k: 2);
      final deviceShares = <String, Share>{
        'A': shares[0],
        'B': shares[1],
        'C': shares[2],
      };
      // Only A destroys -> 2 surviving >= K=2 -> still recoverable.
      final surviving = GroupShred.destroyShare(
          shares: shares, deviceId: 'A', deviceShares: deviceShares);
      expect(surviving, 2);
      expect(GroupShred.isUnrecoverable(survivingShares: surviving, k: 2),
          isFalse);
    });
  });
}
