import 'dart:math';
import 'dart:typed_data';
import '../../security/shamir_kit.dart';
import '../native/aes_gcm.dart';
import 'liveness.dart';
import 'time_lock.dart';

// Intent: v5 E1 — cryptographic inheritance (opt-in, off by default).
// ACTIVATION: heir requires K-of-N Shamir shares (reconstruct bundle key) +
// heir's latest liveness token older than check-in interval + grace (proves
// staleness/death) + short friction-chain unwrap of the bundle key.
// REVOCATION: re-encrypts designated entries under a FRESH bundle key (new
// shares), invalidates the epoch. Old shares reconstruct a different key ->
// cannot unwrap the new entries. Old tokens are epoch-invalid.
// Invariants: activation fails with a fresh token or <K shares; revocation
// renders old shares + old tokens mathematically useless.
// Dependencies: ShamirKit, Liveness, TimeLock, KeyHierarchy, AesGcm.

class InheritanceSetup {
  final List<Share> shares; // N shares reconstructing the bundle secret
  const InheritanceSetup({required this.shares});
}

class InheritanceRevokeResult {
  final List<Share> newShares; // shares of the FRESH bundle secret
  final List<Uint8List> newWrappedEntries; // entries under the fresh secret
  const InheritanceRevokeResult({
    required this.newShares,
    required this.newWrappedEntries,
  });
}

class Inheritance {
  static const int _nonceSize = 12;

  // Setup: split the bundle secret into N shares (any K reconstruct it).
  static InheritanceSetup setup(Uint8List bundleSecret,
      {required int n, required int k}) {
    return InheritanceSetup(shares: ShamirKit.split(bundleSecret, n: n, k: k));
  }

  // Encrypt designated inheritance entries under the bundle secret.
  // Each entry -> nonce(12) || AES-GCM(bundleSecret, entryBytes).
  static List<Uint8List> encryptEntries(
      List<Uint8List> entries, Uint8List bundleSecret) {
    return entries.map((e) {
      final nonce = _randomNonce();
      final ct = AesGcm.encrypt(bundleSecret, nonce, Uint8List(0), e);
      final out = Uint8List(_nonceSize + ct.length);
      out.setRange(0, _nonceSize, nonce);
      out.setRange(_nonceSize, out.length, ct);
      return out;
    }).toList();
  }

  // Decrypt an inheritance entry under the unwrapped bundle secret. A wrong key
  // (old shares after revocation) -> GCM tag mismatch -> InheritanceActivationError.
  static Uint8List decryptEntry(Uint8List wrapped, Uint8List bundleSecret) {
    if (wrapped.length < _nonceSize + 16)
      throw InheritanceActivationError('bad entry');
    final nonce = wrapped.sublist(0, _nonceSize);
    try {
      final ct = wrapped.sublist(_nonceSize);
      return AesGcm.decrypt(bundleSecret, nonce, Uint8List(0), ct);
    } catch (_) {
      throw InheritanceActivationError('wrong bundle secret (old shares)');
    }
  }

  // ACTIVATION: K shares + stale token + short friction chain -> bundle secret.
  static Uint8List activate({
    required List<Share> shares,
    required int k,
    required LivenessToken token,
    required Uint8List vrk,
    required int nowMillis,
    required int checkInMs,
    required int graceMs,
    required int frictionIterations,
  }) {
    if (shares.length < k)
      throw InheritanceActivationError('fewer than K shares');
    // Verify the token signature + epoch (forged/newer rejected).
    final (_, ts) = Liveness.verify(vrk, token, token.epoch);
    // Staleness: token must be OLDER than check-in + grace.
    if ((nowMillis - ts) < (checkInMs + graceMs)) {
      throw InheritanceActivationError('token too fresh (not stale)');
    }
    // Reconstruct the bundle secret from K shares.
    final bundleSecret = ShamirKit.reconstruct(shares);
    // Short friction-chain unwrap (seconds/minutes, not days).
    return TimeLock.computeChain(bundleSecret, frictionIterations);
  }

  // REVOCATION: re-encrypt the given plaintext entry bytes under a FRESH bundle
  // secret and issue new shares. Old shares reconstruct a different secret ->
  // cannot unwrap these. Old tokens are invalidated by a new epoch on the live
  // vault (verify() rejects the old epoch).
  static InheritanceRevokeResult revokeEntries({
    required List<Uint8List> entryBytes,
    required Uint8List freshBundleSecret,
    required int n,
    required int k,
  }) {
    final newShares = ShamirKit.split(freshBundleSecret, n: n, k: k);
    final newWrapped = encryptEntries(entryBytes, freshBundleSecret);
    return InheritanceRevokeResult(
        newShares: newShares, newWrappedEntries: newWrapped);
  }

  static Uint8List _randomNonce() {
    final r = Random.secure();
    return Uint8List.fromList(List.generate(_nonceSize, (_) => r.nextInt(256)));
  }
}

class InheritanceActivationError implements Exception {
  final String reason;
  const InheritanceActivationError(this.reason);
}
