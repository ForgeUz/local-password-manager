import 'dart:convert';
import 'dart:typed_data';

import '../crypto/v4/vault_crypto_v4.dart';

// Intent: Decoy-vault setup (Phase J.4, v5 E4). Pure logic, no state.
// Extracted from VaultService (god-class split, Part IV item 7) so the decoy
// security boundary (slot-2 embedding, cancellation code) has its own module +
// test file.
// Invariants:
// - Decoy blob is locked under VRK_duress with the SAME salt as the primary.
// - Cancellation code is 8 digits, CSPRNG-derived, shown exactly once.
// Dependencies: VaultCryptoV4, DecoyVault, dart:convert, dart:typed_data.
class DecoyService {
  const DecoyService._();

  // Build the decoy vault JSON payload from a list of decoy entries.
  static Uint8List buildDecoyJson(List<V4VaultEntry> entries) {
    return Uint8List.fromList(
      jsonEncode({'entries': entries.map((e) => e.toJson()).toList()})
          .codeUnits,
    );
  }
}