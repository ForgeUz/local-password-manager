import 'dart:typed_data';

sealed class SyncState {}
class SyncIdle implements SyncState {}
class SyncAdvertising implements SyncState {}
class SyncScanning implements SyncState {
  final Map<String, String> peers;
  SyncScanning(this.peers);
}
class SyncPairing implements SyncState {
  final String passphrase;
  final bool isHost;
  SyncPairing({required this.passphrase, required this.isHost});
}
class SyncConnected implements SyncState {
  final String peerId;
  SyncConnected(this.peerId);
}
class SyncTransferring implements SyncState {
  final String message;
  SyncTransferring(this.message);
}
class SyncVerify implements SyncState {
  final Uint8List bytes;
  SyncVerify(this.bytes);
}
class SyncError implements SyncState {
  final String message;
  SyncError(this.message);
}

sealed class SyncIntent {}
class HostPressed implements SyncIntent {}
class JoinPressed implements SyncIntent {}
class PeerDiscovered implements SyncIntent {
  final String id;
  final String name;
  PeerDiscovered(this.id, this.name);
}
class PeerLost implements SyncIntent {
  final String id;
  PeerLost(this.id);
}
class ConnectPressed implements SyncIntent {
  final String id;
  ConnectPressed(this.id);
}
class Connected implements SyncIntent {}
class Disconnected implements SyncIntent {}
class PairingInitiated implements SyncIntent {
  final String passphrase;
  final bool isHost;
  PairingInitiated({required this.passphrase, required this.isHost});
}
class SendVaultPressed implements SyncIntent {}
class BlobReceived implements SyncIntent {
  final Uint8List bytes;
  BlobReceived(this.bytes);
}
class VerifySuccess implements SyncIntent {}
class VerifyFailed implements SyncIntent {
  final String message;
  VerifyFailed(this.message);
}
class ResetPressed implements SyncIntent {}
class ErrorOccurred implements SyncIntent {
  final String message;
  ErrorOccurred(this.message);
}
