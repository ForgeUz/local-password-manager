// File: test/security/statemachine/test_vault_states.dart
// Intent: security2.md gate 21.1 — Vault state transitions verification.
// Invariants:
// - Every state transition is atomic (no partial states).
// - Lock during UNLOCKING: rolls back cleanly, no key material in memory.
// - Recovery mode cannot be entered from UNLOCKED state.
// - Duress trigger only from UNLOCKED state, not from LOCKED.
// - After DECOY_UNLOCKED, primary vault keys are not in memory.
// - Property-based: 10,000 random transition sequences never reach invalid state.
// Dependencies: vault_state_model.dart.

import 'dart:math';

import 'package:flutter_test/flutter_test.dart';
import 'vault_state_model.dart';

void main() {
  group('Gate 21.1 Vault State Transitions', () {
    test('valid lifecycle: LOCKED → UNLOCKING → UNLOCKED → LOCKING → LOCKED', () {
      final m = VaultStateMachine(VaultState.locked);
      expect(m.apply(VaultEvent.beginUnlock), isTrue);
      expect(m.state, VaultState.unlocking);
      expect(m.apply(VaultEvent.unlockSuccess), isTrue);
      expect(m.state, VaultState.unlocked);
      expect(m.apply(VaultEvent.beginLock), isTrue);
      expect(m.state, VaultState.locking);
      expect(m.apply(VaultEvent.lockComplete), isTrue);
      expect(m.state, VaultState.locked);
    });

    test('UNLOCKED → SAVING → UNLOCKED round-trip', () {
      final m = VaultStateMachine(VaultState.unlocked);
      expect(m.apply(VaultEvent.beginSave), isTrue);
      expect(m.state, VaultState.saving);
      expect(m.apply(VaultEvent.saveComplete), isTrue);
      expect(m.state, VaultState.unlocked);
    });

    test('UNLOCKED → ENTRY_DECRYPTING → UNLOCKED round-trip', () {
      final m = VaultStateMachine(VaultState.unlocked);
      expect(m.apply(VaultEvent.beginEntryDecrypt), isTrue);
      expect(m.state, VaultState.entryDecrypting);
      expect(m.apply(VaultEvent.entryDecryptComplete), isTrue);
      expect(m.state, VaultState.unlocked);
    });

    test('LOCKED → RECOVERY_MODE → UNLOCKED', () {
      final m = VaultStateMachine(VaultState.locked);
      expect(m.apply(VaultEvent.enterRecovery), isTrue);
      expect(m.state, VaultState.recoveryMode);
      expect(m.apply(VaultEvent.recoveryComplete), isTrue);
      expect(m.state, VaultState.unlocked);
    });

    test('UNLOCKED → DURESS_TRIGGERED → DECOY_UNLOCKED', () {
      final m = VaultStateMachine(VaultState.unlocked);
      expect(m.apply(VaultEvent.triggerDuress), isTrue);
      expect(m.state, VaultState.duressTriggered);
      expect(m.apply(VaultEvent.duressComplete), isTrue);
      expect(m.state, VaultState.decoyUnlocked);
    });

    test('recovery mode cannot be entered from UNLOCKED state', () {
      final m = VaultStateMachine(VaultState.unlocked);
      // enterRecovery is only valid from LOCKED.
      expect(m.apply(VaultEvent.enterRecovery), isFalse);
      expect(m.state, VaultState.unlocked); // atomic: unchanged
    });

    test('duress trigger only from UNLOCKED, not from LOCKED', () {
      // From LOCKED: invalid.
      final locked = VaultStateMachine(VaultState.locked);
      expect(locked.apply(VaultEvent.triggerDuress), isFalse);
      expect(locked.state, VaultState.locked);
      // From UNLOCKED: valid.
      final unlocked = VaultStateMachine(VaultState.unlocked);
      expect(unlocked.apply(VaultEvent.triggerDuress), isTrue);
      expect(unlocked.state, VaultState.duressTriggered);
    });

    test('after DECOY_UNLOCKED, primary vault keys are not in memory', () {
      final m = VaultStateMachine(VaultState.unlocked);
      m.apply(VaultEvent.triggerDuress);
      m.apply(VaultEvent.duressComplete);
      expect(m.state, VaultState.decoyUnlocked);
      expect(m.primaryKeysInMemory, isFalse);
    });

    test('invalid transitions are atomic (state unchanged)', () {
      final m = VaultStateMachine(VaultState.locked);
      // beginSave is invalid from LOCKED.
      expect(m.apply(VaultEvent.beginSave), isFalse);
      expect(m.state, VaultState.locked);
      // unlockSuccess is invalid from LOCKED (must go through UNLOCKING).
      expect(m.apply(VaultEvent.unlockSuccess), isFalse);
      expect(m.state, VaultState.locked);
    });

    test('property-based: 10,000 random sequences never reach invalid state', () {
      final rng = Random(42);
      final events = VaultEvent.values;
      for (var i = 0; i < 10000; i++) {
        final m = VaultStateMachine(VaultState.locked);
        // Random sequence of events.
        for (var j = 0; j < 20; j++) {
          final event = events[rng.nextInt(events.length)];
          final before = m.state;
          final applied = m.apply(event);
          if (applied) {
            // The transition must be in the valid table.
            expect(
              VALID_TRANSITIONS.any((t) => t.from == before && t.event == event && t.to == m.state),
              isTrue,
              reason: 'invalid transition $before --$event--> ${m.state}',
            );
          } else {
            // Rejected: state unchanged (atomic).
            expect(m.state, before);
          }
        }
      }
    });
  });
}
