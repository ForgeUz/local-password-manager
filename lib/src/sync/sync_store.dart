import 'dart:async';
import 'sync_state.dart';

SyncState syncReduce(SyncState state, SyncIntent intent) {
  if (intent is ResetPressed) return SyncIdle();
  if (intent is ErrorOccurred) return SyncError(intent.message);
  if (intent is Disconnected) return SyncIdle();

  if (state is SyncIdle) {
    if (intent is HostPressed) return SyncAdvertising();
    if (intent is JoinPressed) return SyncScanning({});
  }

  if (state is SyncAdvertising) {
    if (intent is Connected) return SyncConnected('');
    if (intent is PairingInitiated) {
      return SyncPairing(passphrase: intent.passphrase, isHost: intent.isHost);
    }
  }

  if (state is SyncScanning) {
    if (intent is PeerDiscovered) {
      final newPeers = Map<String, String>.from(state.peers);
      newPeers[intent.id] = intent.name;
      return SyncScanning(newPeers);
    }
    if (intent is PeerLost) {
      final newPeers = Map<String, String>.from(state.peers);
      newPeers.remove(intent.id);
      return SyncScanning(newPeers);
    }
    if (intent is ConnectPressed) {
      return SyncTransferring('Connecting to ${intent.id}...');
    }
  }

  if (state is SyncTransferring) {
    if (intent is Connected) return SyncConnected('');
  }

  if (state is SyncConnected) {
    if (intent is SendVaultPressed) return SyncTransferring('Sending vault...');
    if (intent is BlobReceived) return SyncVerify(intent.bytes);
  }

  if (state is SyncPairing) {
    if (intent is Connected) return SyncConnected('');
  }

  if (state is SyncVerify) {
    if (intent is VerifySuccess) return SyncIdle();
    if (intent is VerifyFailed) return SyncError(intent.message);
  }

  return state;
}

class SyncStore {
  SyncState _state = SyncIdle();
  final _controller = StreamController<SyncState>.broadcast();

  SyncState get currentState => _state;
  Stream<SyncState> get stateStream => _controller.stream;

  void dispatch(SyncIntent intent) {
    final newState = syncReduce(_state, intent);
    if (newState != _state) {
      _state = newState;
      _controller.add(_state);
    }
  }

  void dispose() => _controller.close();
}
