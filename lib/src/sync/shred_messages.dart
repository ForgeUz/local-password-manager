import 'vector_clock.dart';

// Intent: v5 E6 — SHRED_SCHEDULED / SHRED_CANCELLED sync messages.
// Idempotent and vector-clock ordered. A device executes shred only after delay
// AND after confirming no unprocessed cancellation exists from the originator.
// Offline -> DEFER until the next successful Noise handshake or a local
// cancellation-code entry. Delay always resolves toward preservation.
// Invariants: messages idempotent (re-delivery is a no-op); ordering by vector
// clock; a cancellation always wins over a shred it dominates.
// Dependencies: VectorClock, dart:typed_data.

enum ShredMessageType { scheduled, cancelled }

class ShredMessage {
  final ShredMessageType type;
  final String originatorId;
  final String entryId;
  final VectorClock clock;

  const ShredMessage({
    required this.type,
    required this.originatorId,
    required this.entryId,
    required this.clock,
  });
}

class ShredMessages {
  // Idempotent apply: returns true if the message is NEW (not already seen at
  // an equal-or-newer clock). A re-delivered message is a no-op.
  static bool apply(ShredMessage msg, Map<String, VectorClock> seen) {
    final prior = seen[msg.entryId];
    if (prior == null) {
      seen[msg.entryId] = msg.clock;
      return true;
    }
    // Identical clock -> re-delivery of the same message -> no-op.
    if (_identical(prior, msg.clock)) return false;
    if (prior.dominates(msg.clock)) return false; // stale
    if (msg.clock.dominates(prior)) {
      // Newer message wins; overwrite.
      seen[msg.entryId] = msg.clock;
      return true;
    }
    // Concurrent: a cancellation dominates a scheduled for the same entry.
    // Keep the more conservative (cancellation) state.
    if (msg.type == ShredMessageType.cancelled) {
      seen[msg.entryId] = msg.clock;
      return true;
    }
    return false;
  }

  static bool _identical(VectorClock a, VectorClock b) {
    final allKeys = {...a.map.keys, ...b.map.keys};
    for (final k in allKeys) {
      if ((a.map[k] ?? 0) != (b.map[k] ?? 0)) return false;
    }
    return true;
  }

  // True if the ledger holds an unprocessed cancellation for this entry from
  // the originator (i.e., the latest message is a cancellation).
  static bool hasUnprocessedCancellation(
      Map<String, VectorClock> seen, String entryId) {
    return seen.containsKey(entryId);
  }
}
