// Intent: Fail-closed error hierarchy for vault crypto operations.
// All errors support optional diagnostic messages for debugging while
// maintaining a consistent exception interface.

import 'dart:typed_data';

/// Base class for all vault crypto errors.
/// Supports an optional diagnostic message accessible via [message] or [toString].
sealed class VaultCryptoError implements Exception {
  final String? message;

  const VaultCryptoError([this.message]);

  @override
  String toString() {
    final typeName = runtimeType.toString();
    return message == null ? typeName : '$typeName: $message';
  }
}

/// Thrown when decryption fails (wrong key, corrupted data, tag mismatch).
class DecryptionFailedError extends VaultCryptoError {
  const DecryptionFailedError([super.message]);
}

/// Thrown when the vault file format is unsupported (wrong magic, wrong version).
class UnsupportedFormatError extends VaultCryptoError {
  const UnsupportedFormatError([super.message]);
}

/// Thrown when KDF parameters fall below the security floor.
class KdfFloorViolationError extends VaultCryptoError {
  const KdfFloorViolationError([super.message]);
}

/// Thrown when a nonce collision is detected (critical security violation).
class NonceCollisionError extends VaultCryptoError {
  const NonceCollisionError([super.message]);
}

/// Thrown when the vault blob is structurally corrupt or fails bounds checks.
class CorruptBlobError extends VaultCryptoError {
  const CorruptBlobError([super.message]);
}

/// Thrown when duress decryption fails (wrong duress password or no decoy vault).
class DuressDecryptError extends VaultCryptoError {
  const DuressDecryptError([super.message]);
}

/// E2: a backup code was wrong, already consumed, or rate-limited. Thrown BEFORE
/// any vault decrypt — the code only authorizes SFM release, never a bypass.
/// [updatedFile] carries the SFM file with the attempt counter / consumed code
/// so the caller can persist it.
class BackupCodeError extends VaultCryptoError {
  final Uint8List? updatedFile;

  BackupCodeError({this.updatedFile, String? message}) : super(message);

  @override
  String toString() {
    final base = super.toString();
    if (updatedFile != null) {
      return '$base (updatedFile: ${updatedFile!.length} bytes)';
    }
    return base;
  }
}
