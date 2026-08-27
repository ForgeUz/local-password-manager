// Intent: Pure core for WebAuthn/FIDO2 passkey management (Phase P3).
// Invariants:
// - Private keys NEVER live in Dart heap (stored in hardware Keystore).
// - Credential ID is opaque bytes (stored in encrypted vault).
// - Domain isolation: rpId MUST match requesting domain exactly.
// State Transition:
//   ChallengeReceived -> CredentialLookup(rpId) -> KeystoreSign -> Signature
// Dependencies: dart:typed_data.

import 'dart:typed_data';

/// Represents a FIDO2 passkey bound to a specific Relying Party (domain).
/// The actual private key lives in the device's hardware-backed Keystore.
/// This entry only holds the opaque credentialId needed to retrieve it.
class PasskeyEntry {
  final String id;
  final String rpId; // Relying Party ID (e.g., "github.com")
  final Uint8List credentialId; // Opaque handle to the key in Keystore
  final DateTime createdAt;

  const PasskeyEntry({
    required this.id,
    required this.rpId,
    required this.credentialId,
    required this.createdAt,
  });

  Map<String, dynamic> toJson() => {
        'id': id,
        'rpId': rpId,
        'credentialId': credentialId,
        'createdAt': createdAt.millisecondsSinceEpoch,
      };

  factory PasskeyEntry.fromJson(Map<String, dynamic> json) {
    return PasskeyEntry(
      id: json['id'] as String,
      rpId: json['rpId'] as String,
      credentialId: Uint8List.fromList(List<int>.from(json['credentialId'] as List)),
      createdAt: DateTime.fromMillisecondsSinceEpoch(json['createdAt'] as int),
    );
  }
}

/// Pure logic for passkey operations. No I/O.
class PasskeyManager {
  const PasskeyManager._();

  /// Verify requesting domain matches stored rpId.
  /// FIDO2 strictly binds credentials to the rpId. Core MUST enforce
  /// exact match to prevent cross-domain replay/phishing.
  static bool verifyRpId({
    required String storedRpId,
    required String requestedRpId,
  }) {
    return storedRpId == requestedRpId;
  }
}
