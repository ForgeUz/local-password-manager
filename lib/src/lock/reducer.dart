import 'state.dart';
import 'intent.dart';
import 'backoff.dart';
import '../vault/vault_data.dart';

LockState reduce(LockState state, LockIntent intent) {
  if (state is Initial && intent is VaultLoaded) {
    return Locked(failCount: 0, blob: intent.blob);
  }

  if (state is Initial && intent is VaultMissing) {
    return SetupRequired();
  }

  // A vault.blob exists but is not a valid GEN4 payload -> surface the
  // "corrupted/unreadable" prompt (try MP or delete + create new).
  if (state is Initial && intent is BlobCorruptDetected) {
    return BlobCorrupt(blob: intent.blob);
  }

  // The user chose "Delete and Create New Vault": the file is securely deleted,
  // route to setup.
  if (state is BlobCorrupt && intent is BlobResetComplete) {
    return SetupRequired();
  }

  if (state is SetupRequired && intent is VaultCreated) {
    return Unlocked(vaultData: intent.vaultData, blob: intent.blob);
  }

  if (state is Locked) {
    if (intent is UnlockFail) {
      final nextFail = state.failCount + 1;
      final delay = BackoffCalculator.nextDelay(nextFail);
      return Locked(
        failCount: nextFail,
        rateLimitedUntil: DateTime.now().add(delay),
        blob: state.blob,
      );
    }
    if (intent is UnlockSuccess) {
      return Unlocked(
        vaultData: intent.vaultData,
        blob: state.blob, // Pass blob to Unlocked state
      );
    }
  }

  if (state is Unlocked) {
    if (intent is AddEntry) {
      final newEntries = List.of(state.vaultData.entries)..add(intent.entry);
      return Unlocked(
        failCount: state.failCount,
        vaultData: VaultData(entries: newEntries),
        revealAuthed: state.revealAuthed,
        revealAuthTime: state.revealAuthTime,
        blob: state.blob,
      );
    }
    if (intent is AutoLock) {
      // BUG FIX: Transition back to Locked, retaining the blob
      return Locked(failCount: 0, blob: state.blob);
    }
  }

  return state;
}
