import 'dart:typed_data';
import '../vault/vault_data.dart';

abstract class LockState {}

// v5: a vault.blob exists but is NOT a valid GEN4 payload — e.g. leftover from
// an old build or truncated/corrupted. The user must either try the MP (it may
// be a user-created blob the header parser rejects) or reset by deleting it.
class BlobCorrupt implements LockState {
  final Uint8List blob;
  const BlobCorrupt({required this.blob});
}

class Initial implements LockState {}

class SetupRequired implements LockState {}

class Locked implements LockState {
  final int failCount;
  final DateTime? rateLimitedUntil;
  final Uint8List blob;

  Locked({this.failCount = 0, this.rateLimitedUntil, required this.blob});

  bool get isRateLimited {
    if (rateLimitedUntil == null) return false;
    return DateTime.now().isBefore(rateLimitedUntil!);
  }
}

class Authenticating implements LockState {}

class Unlocked implements LockState {
  final int failCount;
  final VaultData vaultData;
  final bool revealAuthed;
  final DateTime? revealAuthTime;
  final Uint8List blob; // ADDED: Keep blob for re-locking

  Unlocked({
    this.failCount = 0,
    required this.vaultData,
    this.revealAuthed = false,
    this.revealAuthTime,
    required this.blob, // ADDED
  });
}
