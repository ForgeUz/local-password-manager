import 'replay_counter.dart';

// Intent: P2P sync session state machine (Phase G.7-G.9) as pure logic.
// Transitions: Idle -> Discovering -> Pairing -> Syncing -> Resolved -> Done.
// On error/fail: back to Idle. Uses per-session ReplayCounter for replay
// protection and Ranges for per-entry conflict resolution.
// Sync is strictly optional: the app core never depends on this module.

enum SyncPhase { idle, discovering, pairing, syncing, resolved, done }

class SyncSession {
  SyncPhase _phase = SyncPhase.idle;
  final ReplayCounter _replayCounter = ReplayCounter();
  final List<String> _resolvedEntries = [];

  SyncPhase get phase => _phase;
  List<String> get resolvedEntries => List.unmodifiable(_resolvedEntries);

  void discover() {
    if (_phase != SyncPhase.idle && _phase != SyncPhase.done) return;
    _phase = SyncPhase.discovering;
  }

  void beginPairing() {
    if (_phase != SyncPhase.discovering) return;
    _phase = SyncPhase.pairing;
  }

  void startSyncing(String peerId) {
    if (_phase != SyncPhase.pairing) return;
    _phase = SyncPhase.syncing;
  }

  // Validate an inbound message's counter (replay protection). Rejects
  // non-increasing values -> returns false and drops the message.
  bool acceptFrame(int counter) => _replayCounter.validate(counter);

  void resolveEntry(String entryId) {
    if (_phase != SyncPhase.syncing) return;
    if (!_resolvedEntries.contains(entryId)) _resolvedEntries.add(entryId);
  }

  void resolveAll() {
    if (_phase != SyncPhase.syncing) return;
    _phase = SyncPhase.resolved;
  }

  void done() {
    if (_phase == SyncPhase.resolved) _phase = SyncPhase.done;
  }

  void fail() {
    _phase = SyncPhase.idle;
    _resolvedEntries.clear();
  }
}

// Device registry: list paired, revoke, staleness (6 months).
class PairedDevice {
  final String deviceId;
  final String staticKey;
  final DateTime lastSynced;
  PairedDevice({required this.deviceId, required this.staticKey, required this.lastSynced});

  bool isStale({int staleMonths = 6, DateTime? now}) {
    final nowT = now ?? DateTime.now();
    return nowT.difference(lastSynced).inDays > staleMonths * 30;
  }
}

class DeviceRegistry {
  final List<PairedDevice> _devices = [];

  List<PairedDevice> get devices => List.unmodifiable(_devices);

  void add(PairedDevice d) => _devices.add(d);
  void revoke(String deviceId) => _devices.removeWhere((d) => d.deviceId == deviceId);
  List<PairedDevice> stale({DateTime Function()? now}) {
      final nowT = now ?? DateTime.now;
      return _devices.where((d) => d.isStale(now: nowT())).toList();
  }
}

// Sync-optional invariant: the vault core never depends on this module.
// The app core (VaultService) is fully functional without it.
class SyncOptionalMarker {
  static const bool enabled = true; // presence of this module is optional
}