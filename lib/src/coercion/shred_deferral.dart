// Intent: v5 E6 — shred/cancel propagation race. A device executes shred ONLY
// after delay AND after confirming no unprocessed cancellation exists from the
// originator. If offline when a cancellation is sent, it DEFERS the shred until
// the next successful Noise handshake with the originator or a local
// cancellation-code entry. Delay always resolves toward preservation.
// Invariants: never shred after an unprocessed cancellation; offline -> defer;
// a local cancellation-code entry also cancels.
// State Transition: shredDue(entryId) -> if unprocessed cancellation -> DEFER;
// else EXECUTE. handshakeOk(originatorId) / localCode(entryId) -> clear deferral.
// Dependencies: ShredMessages, VectorClock, dart:typed_data.

enum ShredDecision { execute, defer }

class ShredDeferral {
  // Decide whether to execute a scheduled shred for an entry.
  //   hasUnprocessedCancellation: a SHRED_CANCELLED from the originator is
  //     pending (not yet confirmed received by the originator).
  //   handshakeOk: a successful Noise handshake with the originator happened
  //     after the shred was scheduled (so any cancellation was received).
  //   localCodeEntered: the user entered the cancellation code locally.
  // A device executes ONLY when no unprocessed cancellation exists AND it has
  // confirmed with the originator (handshake) or via local code.
  static ShredDecision decide({
    required bool hasUnprocessedCancellation,
    required bool handshakeOk,
    required bool localCodeEntered,
  }) {
    if (hasUnprocessedCancellation) return ShredDecision.defer;
    // No cancellation pending. Execute only after confirmation (handshake or
    // local code) — otherwise defer (offline, unconfirmed).
    if (handshakeOk || localCodeEntered) return ShredDecision.execute;
    return ShredDecision.defer;
  }
}