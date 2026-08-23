import 'dart:typed_data';
import '../native/hkdf.dart';
import 'constants.dart';

// Intent: v5 H.6 — FIDO2 hardware key as an unlock factor. A P-256 signature
// (64 bytes: 32-byte R + 32-byte S) is folded into the HKDF input alongside
// the MK, so the derived VRK depends on the hardware key. Keylogger-immune:
// the signature is produced by the authenticator, never typed.
//   VRK = HKDF(MK || sig, "GENESIS-VRK-v4")
// Wrong/absent signature -> different VRK -> GCM fails (math, not a check).
// Invariants: signature folded into KDF; wrong sig -> wrong VRK -> GCM fail.
// Dependencies: Hkdf, dart:typed_data.

class Fido2Factor {
  static const int _sigSize = 64; // P-256 signature: R(32) || S(32)

  // Fold a P-256 signature into the VRK derivation. Returns the VRK.
  static Uint8List deriveVrkWithFido2(Uint8List mk, Uint8List p256Signature) {
    if (p256Signature.length != _sigSize) {
      throw StateError('P-256 signature must be 64 bytes');
    }
    final salt = Uint8List(32);
    final ikm = Uint8List(mk.length + p256Signature.length);
    ikm.setRange(0, mk.length, mk);
    ikm.setRange(mk.length, ikm.length, p256Signature);
    return Hkdf.derive(ikm, salt, 'GENESIS-VRK-v4', V4Constants.keySize);
  }
}