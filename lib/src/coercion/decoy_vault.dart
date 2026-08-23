import 'dart:math';
import 'dart:typed_data';

import '../crypto/native/argon2id.dart';
import '../crypto/native/secure_buffer.dart';
import '../crypto/v4/constants.dart';
import '../crypto/v4/duress.dart';
import '../crypto/v4/vault_crypto_v4.dart';

// Intent: Decoy-vault setup (v4 §6.8 / Phase J.4). Produces a vault blob locked
// under VRK_duress (separate from the primary VRK) plus an 8-digit cancellation
// code issued exactly once. Honest limitation: a knowledgeable attacker can
// *suspect* deniability exists but cannot prove it — the decoy vault is
// cryptographically indistinguishable from a normal vault.
// Invariants: decoy blob opens only via the duress unlock path, never the
// primary path; cancellation code is 8 digits and CSPRNG-derived.
// Dependencies: Argon2id, Duress, VaultCryptoV4.relock, dart:math, dart:typed_data.

class DecoySetupResult {
  final String cancellationCode; // 8-digit, shown once
  final Uint8List decoyBlob;

  const DecoySetupResult({required this.cancellationCode, required this.decoyBlob});
}

class DecoyVault {
  final VaultCryptoV4 _crypto;

  DecoyVault({VaultCryptoV4? crypto}) : _crypto = crypto ?? VaultCryptoV4();

  Future<DecoySetupResult> setup({
    required SecureBuffer duressMp,
    required List<V4VaultEntry> entries,
  }) async {
    final salt = _randomBytes(V4Constants.saltSize);
    final mk = await Argon2id.derive(
      duressMp.readBytes(),
      salt,
      memory: V4Constants.kdfFloorMemory ~/ 1024,
      iterations: V4Constants.kdfFloorIterations,
      parallelism: V4Constants.kdfFloorParallelism,
    );
    // VRK_duress (separate key) -> blob locked under it with the same salt/KDF
    // params so duressUnlockSession re-derives the identical VRK deterministically.
    final vrkDuress = Duress.deriveVrkDuress(mk);
    final blob = await _crypto.relock(
      vrkDuress,
      entries,
      salt: salt,
      kdfMemory: V4Constants.kdfFloorMemory ~/ 1024,
      kdfIterations: V4Constants.kdfFloorIterations,
      kdfParallelism: V4Constants.kdfFloorParallelism,
    );
    return DecoySetupResult(
      cancellationCode: generateCancellationCode(),
      decoyBlob: blob,
    );
  }

  // 8-digit cancellation code, CSPRNG-derived, shown exactly once.
  static String generateCancellationCode() {
    final r = Random.secure();
    return (10000000 + r.nextInt(90000000)).toString(); // 8 digits, no leading 0
  }

  static Uint8List _randomBytes(int length) {
    final r = Random.secure();
    return Uint8List.fromList(List.generate(length, (_) => r.nextInt(256)));
  }
}
