import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/crypto/native/constant_time.dart';
import 'package:vault_crypto/src/sync/pairing_session.dart';

void main() {
  test('StartPairing generates >=8-char alphanumeric passphrase (E18)', () {
    final session = PairingSession();
    final state = session.startPairing();
    
    expect(state.status, PairingStatus.waitingForPeer);
    expect(state.pin.length, greaterThanOrEqualTo(8));
    // Alphanumeric only (no short numeric PIN).
    expect(RegExp(r'^[A-Za-z0-9]{8,}$').hasMatch(state.pin), isTrue);
  });

  test('derivePsk uses Argon2id(passphrase, salt) -> 32-byte PSK (E18)', () {
    final session = PairingSession();
    final salt = Uint8List.fromList(List.generate(16, (i) => i));
    final psk = session.derivePsk('correct-horse-battery', salt);
    expect(psk.length, 32);
    // Deterministic: same passphrase + salt -> same PSK.
    final psk2 = session.derivePsk('correct-horse-battery', salt);
    expect(ConstantTime.equals(psk, psk2), isTrue);
  });

  test('HandshakeFail increments attempts, enforces cooldown after 3', () {
    var session = PairingSession();
    var state = session.startPairing();
    
    state = session.handleHandshakeFail(state);
    expect(state.status, PairingStatus.waitingForPeer);
    expect(state.attempts, 1);
    
    state = session.handleHandshakeFail(state);
    state = session.handleHandshakeFail(state);
    
    expect(state.status, PairingStatus.cooldown);
    expect(state.attempts, 3);
  });

  test('HandshakeSuccess sets Paired', () {
    var session = PairingSession();
    var state = session.startPairing();
    
    state = session.handleHandshakeSuccess(state);
    expect(state.status, PairingStatus.paired);
  });

  test('Timeout sets Failed', () {
    var session = PairingSession();
    var state = session.startPairing();
    
    state = session.handleTimeout(state);
    expect(state.status, PairingStatus.failed);
  });
}