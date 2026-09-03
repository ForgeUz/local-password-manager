// ignore_for_file: constant_identifier_names
// VALID_TRANSITIONS is a domain-named constant (not a C mirror); kept for clarity.

// File: test/security/statemachine/vault_state_model.dart
// Intent: security2.md gate 21.1 — Formal model of the vault state machine.
// A pure, deterministic model of valid/invalid state transitions. Used by
// test_vault_states.dart for property-based transition-sequence testing.
//
// STATES (from security2.md §21.1):
//   LOCKED → UNLOCKING → UNLOCKED → LOCKING → LOCKED
//   UNLOCKED → SAVING → UNLOCKED
//   UNLOCKED → ENTRY_DECRYPTING → UNLOCKED
//   LOCKED → RECOVERY_MODE → UNLOCKED
//   UNLOCKED → DURESS_TRIGGERED → DECOY_UNLOCKED
//
// Invariants:
// - Every transition is atomic (no partial states).
// - Recovery mode cannot be entered from UNLOCKED.
// - Duress trigger only from UNLOCKED, not from LOCKED.
// - After DECOY_UNLOCKED, primary vault keys are not in memory.
// Dependencies: none (pure model).

/// The vault state machine states.
enum VaultState {
  locked,
  unlocking,
  unlocked,
  locking,
  saving,
  entryDecrypting,
  recoveryMode,
  duressTriggered,
  decoyUnlocked,
}

/// The events that trigger transitions.
enum VaultEvent {
  beginUnlock,
  unlockSuccess,
  unlockFail,
  beginLock,
  lockComplete,
  beginSave,
  saveComplete,
  beginEntryDecrypt,
  entryDecryptComplete,
  enterRecovery,
  recoveryComplete,
  triggerDuress,
  duressComplete,
}

/// A single transition rule: from state + event -> to state (or null if invalid).
class Transition {
  final VaultState from;
  final VaultEvent event;
  final VaultState to;
  const Transition(this.from, this.event, this.to);
}

/// The complete valid transition table.
const List<Transition> VALID_TRANSITIONS = [
  // LOCKED → UNLOCKING → UNLOCKED → LOCKING → LOCKED
  Transition(VaultState.locked, VaultEvent.beginUnlock, VaultState.unlocking),
  Transition(
      VaultState.unlocking, VaultEvent.unlockSuccess, VaultState.unlocked),
  Transition(VaultState.unlocking, VaultEvent.unlockFail, VaultState.locked),
  Transition(VaultState.unlocked, VaultEvent.beginLock, VaultState.locking),
  Transition(VaultState.locking, VaultEvent.lockComplete, VaultState.locked),
  // UNLOCKED → SAVING → UNLOCKED
  Transition(VaultState.unlocked, VaultEvent.beginSave, VaultState.saving),
  Transition(VaultState.saving, VaultEvent.saveComplete, VaultState.unlocked),
  // UNLOCKED → ENTRY_DECRYPTING → UNLOCKED
  Transition(VaultState.unlocked, VaultEvent.beginEntryDecrypt,
      VaultState.entryDecrypting),
  Transition(VaultState.entryDecrypting, VaultEvent.entryDecryptComplete,
      VaultState.unlocked),
  // LOCKED → RECOVERY_MODE → UNLOCKED
  Transition(
      VaultState.locked, VaultEvent.enterRecovery, VaultState.recoveryMode),
  Transition(VaultState.recoveryMode, VaultEvent.recoveryComplete,
      VaultState.unlocked),
  // UNLOCKED → DURESS_TRIGGERED → DECOY_UNLOCKED
  Transition(VaultState.unlocked, VaultEvent.triggerDuress,
      VaultState.duressTriggered),
  Transition(VaultState.duressTriggered, VaultEvent.duressComplete,
      VaultState.decoyUnlocked),
];

/// The state machine model. Applies events and tracks whether a transition is
/// valid. Invalid transitions are rejected (return false) and leave state
/// unchanged — this models atomicity (no partial states).
class VaultStateMachine {
  VaultState _state;
  VaultStateMachine([this._state = VaultState.locked]);

  VaultState get state => _state;

  /// Apply an event. Returns true if the transition was valid and applied,
  /// false if it was invalid (state unchanged — atomic).
  bool apply(VaultEvent event) {
    for (final t in VALID_TRANSITIONS) {
      if (t.from == _state && t.event == event) {
        _state = t.to;
        return true;
      }
    }
    return false;
  }

  /// Whether the current state is a "key material in memory" state.
  /// After DECOY_UNLOCKED, primary keys must NOT be in memory.
  bool get primaryKeysInMemory {
    switch (_state) {
      case VaultState.unlocked:
      case VaultState.saving:
      case VaultState.entryDecrypting:
      case VaultState.locking:
        return true;
      case VaultState.decoyUnlocked:
        // Decoy unlocked: primary keys must be wiped.
        return false;
      default:
        return false;
    }
  }
}
