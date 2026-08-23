import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/crypto/v4/inheritance.dart';
import 'package:vault_crypto/src/crypto/v4/liveness.dart';
import 'package:vault_crypto/src/security/shamir_kit.dart';

// Intent: v5 E1 — inheritance activation + revocation. Activation requires K
// shares + a liveness token OLDER than check-in + grace + short friction chain.
// Revocation re-encrypts under a fresh bundle secret -> old shares/tokens
// useless.
void main() {
  group('v5 E1 inheritance activation', () {
    test('succeeds with stale token + K shares; fails with fresh token / <K', () {
      // Setup in seconds: bundle secret split 3-of-5.
      final bundleSecret = Uint8List.fromList(List.generate(32, (i) => i));
      final sw = Stopwatch()..start();
      final setup = Inheritance.setup(bundleSecret, n: 5, k: 3);
      sw.stop();
      expect(setup.shares.length, 5);
      expect(sw.elapsed.inSeconds, lessThan(5));

      final vrk = Uint8List.fromList(List.generate(32, (i) => 0xFF - i));
      const checkIn = 30 * 24 * 3600 * 1000; // 30 days
      const grace = 14 * 24 * 3600 * 1000; // 14 days
      const nowMs = 2000000000000;
      // Latest token 100 days ago -> stale.
      final staleToken = Liveness.emit(vrk, 42, nowMs - 100 * 24 * 3600 * 1000);
      // A fresh token (1 hour ago) -> not stale.
      final freshToken = Liveness.emit(vrk, 43, nowMs - 3600 * 1000);

      // Activation with K=3 stale-token shares succeeds.
      final bundle = Inheritance.activate(
        shares: setup.shares.sublist(0, 3),
        k: 3,
        token: staleToken,
        vrk: vrk,
        nowMillis: nowMs,
        checkInMs: checkIn,
        graceMs: grace,
        frictionIterations: 1000,
      );
      expect(bundle.length, 32);

      // Fresh token -> fails (not stale).
      final f1 = () => Inheritance.activate(
            shares: setup.shares.sublist(0, 3),
            k: 3,
            token: freshToken,
            vrk: vrk,
            nowMillis: nowMs,
            checkInMs: checkIn,
            graceMs: grace,
            frictionIterations: 1000,
          );
      expect(f1, throwsA(isA<InheritanceActivationError>()));

      // < K shares -> fails.
      final f2 = () => Inheritance.activate(
            shares: setup.shares.sublist(0, 2), // 2 < K=3
            k: 3,
            token: staleToken,
            vrk: vrk,
            nowMillis: nowMs,
            checkInMs: checkIn,
            graceMs: grace,
            frictionIterations: 1000,
          );
      expect(f2, throwsA(isA<InheritanceActivationError>()));
    });
  });

  group('v5 E1 inheritance revocation', () {
    test('revocation invalidates old shares + old tokens', () {
      // Setup: bundle secret A, entries encrypted under A.
      final secretA = Uint8List.fromList(List.generate(32, (i) => i));
      final setupA = Inheritance.setup(secretA, n: 3, k: 2);
      final entryA = Uint8List.fromList('heir-secret'.codeUnits);

      // Revoke: fresh bundle secret B, re-encrypt entries under B.
      final secretB = Uint8List.fromList(List.generate(32, (i) => 0xAA + i));
      final revoked = Inheritance.revokeEntries(
        entryBytes: [entryA],
        freshBundleSecret: secretB,
        n: 3,
        k: 2,
      );

      // OLD shares (of A) reconstruct A — which cannot unwrap entries under B.
      final oldKey = ShamirKit.reconstruct(setupA.shares.sublist(0, 2));
      expect(
        () => Inheritance.decryptEntry(revoked.newWrappedEntries.first, oldKey),
        throwsA(isA<InheritanceActivationError>()),
      );

      // NEW shares (of B) reconstruct B -> can unwrap.
      final newKey = ShamirKit.reconstruct(revoked.newShares.sublist(0, 2));
      final decrypted = Inheritance.decryptEntry(revoked.newWrappedEntries.first, newKey);
      expect(utf8.decode(decrypted), 'heir-secret');

      // Old token: epoch-invalidated via Liveness.verify with the new epoch.
      final vrk = Uint8List.fromList(List.generate(32, (i) => 0xFF + i));
      final oldToken = Liveness.emit(vrk, 5, 1000000);
      // After revocation the live vault's expected epoch advances; the old
      // token (epoch 5) is rejected when a newer epoch is expected.
      expect(
        () => Liveness.verify(vrk, oldToken, 6),
        throwsA(isA<LivenessNewerEpochError>()),
      );
    });
  });
}