// File: test/passkey/passkey_core_test.dart
// Intent: Kill-tests for PasskeyManager FIDO2 invariants (M126).
// Invariants:
// - rpId MUST match exactly. Subdomains or different domains MUST fail.
import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/passkey/passkey_core.dart';

void main() {
  group('M126: verifyRpId enforces FIDO2 domain isolation', () {
    test('exact match -> true', () {
      expect(PasskeyManager.verifyRpId(storedRpId: 'github.com', requestedRpId: 'github.com'), isTrue);
    });

    test('subdomain mismatch -> false', () {
      expect(PasskeyManager.verifyRpId(storedRpId: 'github.com', requestedRpId: 'evil.github.com'), isFalse);
    });

    test('different domain -> false', () {
      expect(PasskeyManager.verifyRpId(storedRpId: 'github.com', requestedRpId: 'gitlab.com'), isFalse);
    });
  });
}
