import 'dart:convert';
import 'dart:typed_data';

// Intent: Per-entry vector clock (v3 §20.2 / Phase G.4). Each entry carries its
// own clock (device_id -> counter). Compare clocks per entry on sync:
//   A dominates B -> A.newer (B is stale, A wins)
//   B dominates A -> B.newer
//   concurrent (neither dominates) -> conflict
// Prevent rollback via clock-skew (monotonic per device).
// Dependencies: dart:convert, dart:typed_data.

enum SyncFlag { localWins, remoteWins, conflict, same }

class VectorClock {
  final Map<String, int> map;

  VectorClock(this.map);

  VectorClock increment(String deviceId) {
    final c = (map[deviceId] ?? 0) + 1;
    final newMap = Map<String, int>.from(map)..[deviceId] = c;
    return VectorClock(newMap);
  }

  // True if this clock is strictly ahead of other (dominates): >= on every
  // device and > on at least one; other must not beat us anywhere.
  bool dominates(VectorClock other) {
    bool strictlyNewer = false;
    final allKeys = {...map.keys, ...other.map.keys};
    for (final k in allKeys) {
      final l = map[k] ?? 0;
      final r = other.map[k] ?? 0;
      if (l < r) return false; // other is ahead somewhere -> we don't dominate
      if (l > r) strictlyNewer = true;
    }
    return strictlyNewer;
  }

  // Per-entry sync decision between this (local) and remote.
  SyncFlag decideAgainst(VectorClock remote) {
    if (identical(this, remote)) return SyncFlag.same;
    final d2r = dominates(remote);
    final r2d = remote.dominates(this);
    if (d2r && !r2d) return SyncFlag.localWins;
    if (r2d && !d2r) return SyncFlag.remoteWins;
    if (d2r && r2d) return SyncFlag.same;
    return SyncFlag.conflict;
  }

  /// Legacy whole-vault conflict check (kept for compatibility).
  bool hasConflict(VectorClock remote) {
    return decideAgainst(remote) == SyncFlag.conflict;
  }

  // --- Serialization (the v4 header stores the clock as a byte blob) ---

  Uint8List toBytes() {
    // JSON: [[key, value], ...]
    final rows = map.entries.map((e) => [e.key, e.value]).toList();
    return Uint8List.fromList(utf8.encode(jsonEncode(rows)));
  }

  factory VectorClock.fromBytes(Uint8List bytes) {
    final rows = (jsonDecode(utf8.decode(bytes)) as List)
        .map((r) => (r as List).cast<dynamic>())
        .toList();
    final m = <String, int>{};
    for (final r in rows) {
      m[r[0] as String] = r[1] as int;
    }
    return VectorClock(m);
  }
}
