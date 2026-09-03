import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/security/breach_rotation.dart';
import 'package:vault_crypto/src/security/integrity_heartbeat.dart';

// Intent: Verify integrity heartbeat (Phase P) + one-tap breach rotation (K.3).
void main() {
  group('IntegrityHeartbeat', () {
    test('chain verifies when intact', () {
      final hb = IntegrityHeartbeat();
      hb.append(t: 1, version: '1.0', binaryHash: 'h1');
      hb.append(t: 2, version: '1.0', binaryHash: 'h2');
      hb.append(t: 3, version: '1.0', binaryHash: 'h3');
      expect(hb.verify(), isTrue);
    });

    test('broken chain detected (tamper evidence)', () {
      final hb = IntegrityHeartbeat();
      hb.append(t: 1, version: '1.0', binaryHash: 'h1');
      hb.append(t: 2, version: '1.0', binaryHash: 'h2');
      // Serialize, then tamper the first entry's timestamp in the JSON.
      final json = hb.serialize();
      final tamperedJson = json.replaceFirst('"t":1', '"t":999');
      final tampered = IntegrityHeartbeat()..load(tamperedJson);
      // The second entry's prevHash no longer matches the (modified) first.
      expect(tampered.verify(), isFalse);
    });

    test('serialize/load round-trips and still verifies', () {
      final hb = IntegrityHeartbeat();
      hb.append(t: 1, version: '1.0', binaryHash: 'h1');
      hb.append(t: 2, version: '1.0', binaryHash: 'h2');
      final json = hb.serialize();
      final loaded = IntegrityHeartbeat()..load(json);
      expect(loaded.log.length, 2);
      expect(loaded.verify(), isTrue);
    });
  });

  group('BreachRotation', () {
    test('rotates password, preserves old, TOTP untouched', () {
      final r = BreachRotation.rotate(
        oldPassword: 'oldpass',
        isCritical: false,
        isAuthed: true,
      );
      expect(r.newPassword, isNot('oldpass'));
      expect(r.newPassword.length, 20);
      expect(r.oldPassword, 'oldpass'); // preserved, marked compromised
      expect(r.totpSeedUntouched, isTrue);
    });

    test('Critical-tier requires fresh re-auth', () {
      expect(
        () => BreachRotation.rotate(
          oldPassword: 'x',
          isCritical: true,
          isAuthed: false,
        ),
        throwsStateError,
      );
      // With re-auth it succeeds.
      final r = BreachRotation.rotate(
        oldPassword: 'x',
        isCritical: true,
        isAuthed: true,
      );
      expect(r.newPassword, isNotEmpty);
    });
  });
}
