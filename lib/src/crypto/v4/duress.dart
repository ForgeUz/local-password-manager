import 'dart:typed_data';
import '../native/hkdf.dart';
import 'constants.dart';

// Intent: Duress key derivation (v4 §5.3). MK_duress from Argon2id of the
// duress MP; VRK_duress = HKDF(MK_duress, "GENESIS-VRK-DURESS"). Decrypts the
// decoy vault only; independent of the primary VRK.
// Invariants: different MK -> different VRK_duress.
// Dependencies: Hkdf, dart:typed_data.

class Duress {
  static const String _vrkDuressInfo = 'GENESIS-VRK-DURESS';

  static Uint8List deriveVrkDuress(Uint8List mkDuress) {
    final salt = Uint8List(32);
    return Hkdf.derive(mkDuress, salt, _vrkDuressInfo, V4Constants.keySize);
  }
}