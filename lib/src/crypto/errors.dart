// Intent: Fail-closed error hierarchy for vault crypto operations.
import 'dart:typed_data';

sealed class VaultCryptoError implements Exception {}

class DecryptionFailedError extends VaultCryptoError {}

class UnsupportedFormatError extends VaultCryptoError {}

class KdfFloorViolationError extends VaultCryptoError {}

class NonceCollisionError extends VaultCryptoError {}

class CorruptBlobError extends VaultCryptoError {}

class DuressDecryptError extends VaultCryptoError {}

// E2: a backup code was wrong, already consumed, or rate-limited. Thrown BEFORE
// any vault decrypt — the code only authorizes SFM release, never a bypass.
// updatedFile carries the SFM file with the attempt counter / consumed code so
// the caller can persist it.
class BackupCodeError extends VaultCryptoError {
  final Uint8List? updatedFile;
  BackupCodeError({this.updatedFile});
}
