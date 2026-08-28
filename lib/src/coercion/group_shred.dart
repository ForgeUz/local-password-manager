import '../security/shamir_kit.dart';

// Intent: v5 E5 — group shred for Shamir-split Critical DEKs.
// Critical DEKs are Shamir-split across paired devices (default 2-of-3). Duress
// shred is a GROUP OPERATION: SHRED_SCHEDULED broadcasts to all share holders;
// each device destroys its local share at the deadline. Critical becomes
// unrecoverable when surviving shares < K. Under default 2-of-3, two destroyed
// shares suffice; all are scheduled.
// Invariants: shred is scheduled on ALL holders; a device destroys only its own
// share; unrecoverable iff surviving shares < K.
// State Transition: schedule(deviceId) -> SHRED_SCHEDULED; destroyShare(deviceId)
// -> share removed; isUnrecoverable(surviving, k) -> bool.
// Dependencies: ShamirKit (Share model), dart:typed_data.

// A shred order for one device: destroy its local share at the deadline.
class ShredOrder {
  final String deviceId;
  final int deadlineEpochMillis;
  const ShredOrder({required this.deviceId, required this.deadlineEpochMillis});
}

class GroupShred {
  // Broadcast SHRED_SCHEDULED to all share holders. Returns one ShredOrder per
  // device, each with the same deadline (delay resolves toward preservation).
  static List<ShredOrder> schedule({
    required List<String> deviceIds,
    required int deadlineEpochMillis,
  }) {
    return deviceIds
        .map((id) =>
            ShredOrder(deviceId: id, deadlineEpochMillis: deadlineEpochMillis))
        .toList();
  }

  // A device destroys its local share. Returns the surviving share count.
  static int destroyShare({
    required List<Share> shares,
    required String deviceId,
    required Map<String, Share> deviceShares,
  }) {
    final share = deviceShares[deviceId];
    if (share == null) return shares.length;
    shares.removeWhere((s) => s.x == share.x);
    deviceShares.remove(deviceId);
    return shares.length;
  }

  // Critical is unrecoverable when surviving shares < K.
  static bool isUnrecoverable({required int survivingShares, required int k}) {
    return survivingShares < k;
  }
}
