import 'dart:typed_data';
import '../crypto/native/secure_buffer.dart';
import '../vault/vault_data.dart';

abstract class LockIntent {}

class CheckVault implements LockIntent {}

class VaultLoaded implements LockIntent {
  final Uint8List blob;
  VaultLoaded({required this.blob});
}

class VaultMissing implements LockIntent {}

class CreateVault implements LockIntent {
  final SecureBuffer mp;
  CreateVault({required this.mp});
}

class VaultCreated implements LockIntent {
  final VaultData vaultData;
  final Uint8List blob; // ADDED
  VaultCreated({required this.vaultData, required this.blob});
}

class UnlockAttempt implements LockIntent {
  final SecureBuffer mp;
  UnlockAttempt({required this.mp});
}

class UnlockSuccess implements LockIntent {
  final VaultData vaultData;
  UnlockSuccess({required this.vaultData});
}

class UnlockFail implements LockIntent {}

class BlobCorruptDetected implements LockIntent {
  final Uint8List blob;
  BlobCorruptDetected({required this.blob});
}

class BlobResetRequested implements LockIntent {}
class BlobResetComplete implements LockIntent {}
class RequestReveal implements LockIntent {}
class RevealAuthSuccess implements LockIntent {}
class AutoLock implements LockIntent {}

class AddEntry implements LockIntent {
  final VaultEntry entry;
  AddEntry({required this.entry});
}