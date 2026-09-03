import 'dart:typed_data';

import '../crypto/native/argon2id.dart';
import '../crypto/native/secure_buffer.dart';
import '../crypto/v4/header.dart';
import '../security/shamir_kit.dart';

// Intent: Shamir recovery setup + unlock (Phase I.8). Pure logic, no state.
// Extracted from VaultService (god-class split, Part IV item 7) so the recovery
// security boundary (MK split into N shares, K reconstruct) has its own module
// + test file.
// Invariants:
// - MK derived from the HEADER KDF params (not the floor) so shares always
//   match the vault's actual MK derivation.
// - MK zeroed after use (CWE-226).
// Dependencies: Argon2id, ShamirKit, V4Header, SecureBuffer.
class RecoveryService {
  const RecoveryService._();

  // Derive the MK from the MP + vault salt and split into N shares; any K
  // reconstruct it. Returns QR-ready base64 share strings.
  static Future<List<String>> generateShares(
    Uint8List blob,
    SecureBuffer mp, {
    required int n,
    required int k,
  }) async {
    final header = V4Header.parse(blob);
    final mk = Argon2id.derive(
      mp.readBytes(),
      header.salt,
      memory: header.kdfMemory,
      iterations: header.kdfIterations,
      parallelism: header.kdfParallelism,
    );
    try {
      final shares = ShamirKit.split(mk, n: n, k: k);
      return shares.map(ShamirKit.encodeShare).toList();
    } finally {
      mk.fillRange(0, mk.length, 0);
    }
  }

  // Reconstruct the MK from K shares. Returns the MK (caller zeroes it).
  static Uint8List reconstruct(List<Share> shares) {
    return ShamirKit.reconstruct(shares);
  }

  // Parse a base64 share string back into a Share.
  static Share parseShare(String encoded) {
    return ShamirKit.parseShare(encoded);
  }
}