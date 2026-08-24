import 'dart:typed_data';
import '../native/hkdf.dart';
import 'constants.dart';

// Intent: Duress key derivation (v4 §5.3). MK_duress from Argon2id of the
// duress MP; VRK_duress = HKDF(MK_duress, "GENESIS-VRK-DURESS"). Decrypts the
// decoy vault only; independent of the primary VRK.
//
// SECURITY CRITICAL: MK_duress parameter MUST be zeroed by caller after this
// function returns. The returned VRK_duress also MUST be zeroed by caller.
//
// Invariants: different MK -> different VRK_duress.
// Dependencies: Hkdf, dart:typed_data.

class Duress {
  static const String _vrkDuressInfo = 'GENESIS-VRK-DURESS';

  /// Derive VRK_duress from MK_duress using HKDF.
  ///
  /// SECURITY:
  /// - mkDuress parameter is NOT zeroed here (caller's responsibility).
  /// - Returned VRK_duress MUST be zeroed by caller after use.
  static Uint8List deriveVrkDuress(Uint8List mkDuress) {
    final salt = Uint8List(32);
    return Hkdf.derive(mkDuress, salt, _vrkDuressInfo, V4Constants.keySize);
  }
}