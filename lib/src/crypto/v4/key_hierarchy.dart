import 'dart:math';
import 'dart:typed_data';
import '../native/aes_gcm.dart';
import '../native/hkdf.dart';
import 'constants.dart';

// Intent: Per-entry key hierarchy (v3 §19 / v4 §8 A.4-A.7).
//   MK -> HKDF("GENESIS-VRK-v4") -> VRK (wraps DEKs, never encrypts directly)
//   DEK_i = CSPRNG(32) -> AES-GCM(VRK, DEK_i) -> wrapped DEK
// The "wrapped DEK" field carries its own nonce: nonce(12) || ciphertext+tag.
// This makes unwrap self-contained (the nonce travels with the wrapped key).
// Invariants: VRK deterministic; DEK wrap/unwrap round-trips; wrong VRK fails.
// Dependencies: Hkdf, AesGcm, ConstantTime, dart:math, dart:typed_data.

class KeyHierarchy {
  static const String _vrkInfo = 'GENESIS-VRK-v4';
  static const int _nonceSize = 12;

  // Derive VRK from MK. If TOTP-bound 2FA is enabled, the TOTP code is folded
  // into the HKDF input so the VRK (and thus the vault key) depends on it:
  //   VRK = HKDF(MK || totpBytes, "GENESIS-VRK-v4")
  // Wrong TOTP -> different VRK -> GCM tag fails (math, not a check).
  static Uint8List deriveVrk(Uint8List mk, {Uint8List? totpBytes}) {
    final salt = Uint8List(32); // empty salt -> zeros (HKDF extract)
    if (totpBytes == null || totpBytes.isEmpty) {
      return Hkdf.derive(mk, salt, _vrkInfo, V4Constants.keySize);
    }
    // Prepend TOTP bytes to MK for the HKDF IKM input.
    final ikm = Uint8List(mk.length + totpBytes.length);
    ikm.setRange(0, mk.length, mk);
    ikm.setRange(mk.length, ikm.length, totpBytes);
    return Hkdf.derive(ikm, salt, _vrkInfo, V4Constants.keySize);
  }

  static Uint8List generateDek() {
    final random = Random.secure();
    return Uint8List.fromList(List.generate(V4Constants.keySize, (_) => random.nextInt(256)));
  }

  // Returns nonce(12) || AES-GCM(VRK, DEK).
  static Uint8List wrapDek(Uint8List vrk, Uint8List dek) {
    final nonce = _freshNonce();
    final ct = AesGcm.encrypt(vrk, nonce, Uint8List(0), dek);
    final out = Uint8List(_nonceSize + ct.length);
    out.setRange(0, _nonceSize, nonce);
    out.setRange(_nonceSize, _nonceSize + ct.length, ct);
    return out;
  }

  static Uint8List unwrapDek(Uint8List vrk, Uint8List wrapped) {
    if (wrapped.length < _nonceSize + 16) throw StateError('wrapped DEK too short');
    final nonce = wrapped.sublist(0, _nonceSize);
    final ct = wrapped.sublist(_nonceSize);
    return AesGcm.decrypt(vrk, nonce, Uint8List(0), ct);
  }

  static Uint8List _freshNonce() {
    final random = Random.secure();
    return Uint8List.fromList(List.generate(_nonceSize, (_) => random.nextInt(256)));
  }
}