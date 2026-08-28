import '../crypto/native/secure_buffer.dart';

// Intent: Zero-wipe a secret SecureBuffer on lock/auto-lock/background/termination.
// This is the v4 §8 Phase B "explicit zero-wipe" trigger. Idempotent.
// Invariants: after wipe, the buffer is disposed (zeroed); double-wipe is safe.
// State Transition: unlocked -> lock trigger -> wipe(secret) -> zeroed.
// Dependencies: SecureBuffer.

class SecretWiper {
  static void wipe(SecureBuffer secret) {
    secret.dispose();
  }
}
