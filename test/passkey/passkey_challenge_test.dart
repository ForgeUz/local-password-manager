// Intent: Kill-tests for WebAuthn challenge generation.
// Invariants:
// - Output is base64url (no '+', '/', or '=').
// - Entropy length >= 32 bytes.
import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/passkey/passkey_challenge.dart';

void main() {
  test('generates 32-byte base64url challenge without padding', () {
    final c = PasskeyChallenge.generate();
    
    // 32 bytes -> 43 chars in base64url (ceil(32/3)*4 = 44, minus 1 padding = 43)
    expect(c.length, greaterThanOrEqualTo(43));
    
    // Strict WebAuthn compliance: no standard base64 chars, no padding
    expect(c.contains('='), isFalse);
    expect(c.contains('+'), isFalse);
    expect(c.contains('/'), isFalse);
    
    // Verify it decodes back to 32 bytes
    final padded = c.padRight((c.length / 4).ceil() * 4, '=');
    final decoded = base64Url.decode(padded);
    expect(decoded.length, equals(32));
  });
}