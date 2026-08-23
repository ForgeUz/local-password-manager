import 'dart:math';
import 'dart:typed_data';
import '../crypto/native/argon2id.dart';

// Intent: State machine for P2P pairing lifecycle (v5 E18).
// Enforces 60s window and attempt lockout. Pairing secret is a >=8-char
// alphanumeric passphrase (not a short PIN); PSK = Argon2id(passphrase, salt)
// raises offline dictionary cost on captured handshakes.
class PairingState {
  final PairingStatus status;
  final String pin;
  final int attempts;

  PairingState({
    required this.status,
    required this.pin,
    required this.attempts,
  });
}

enum PairingStatus { idle, waitingForPeer, paired, cooldown, failed }

class PairingSession {
  static const int _maxAttempts = 3;
  static const int _passphraseLength = 8;
  static const String _alnum = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

  PairingState startPairing() {
    final random = Random.secure();
    // >=8-char alphanumeric passphrase (E18: not a short numeric PIN).
    final pin = List.generate(_passphraseLength, (_) =>
        _alnum[random.nextInt(_alnum.length)]).join();
    return PairingState(
      status: PairingStatus.waitingForPeer,
      pin: pin,
      attempts: 0,
    );
  }

  // PSK = Argon2id(passphrase, pairing salt) — raises offline dictionary cost
  // on captured handshakes (E18).
  Uint8List derivePsk(String passphrase, Uint8List salt) {
    return Argon2id.derive(
      Uint8List.fromList(passphrase.codeUnits),
      salt,
      memory: 65536,
      iterations: 3,
      parallelism: 1,
    );
  }

  PairingState handleHandshakeFail(PairingState current) {
    if (current.status != PairingStatus.waitingForPeer) return current;
    
    final nextAttempts = current.attempts + 1;
    if (nextAttempts >= _maxAttempts) {
      return PairingState(
        status: PairingStatus.cooldown,
        pin: '',
        attempts: nextAttempts,
      );
    }
    
    return PairingState(
      status: PairingStatus.waitingForPeer,
      pin: current.pin,
      attempts: nextAttempts,
    );
  }

  PairingState handleHandshakeSuccess(PairingState current) {
    if (current.status != PairingStatus.waitingForPeer) return current;
    return PairingState(
      status: PairingStatus.paired,
      pin: '',
      attempts: current.attempts,
    );
  }

  PairingState handleTimeout(PairingState current) {
    if (current.status != PairingStatus.waitingForPeer) return current;
    return PairingState(
      status: PairingStatus.failed,
      pin: '',
      attempts: current.attempts,
    );
  }
}