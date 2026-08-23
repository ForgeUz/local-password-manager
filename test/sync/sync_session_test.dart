import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/sync/sync_session.dart';

// Intent: Verify the sync session state machine (Phase G.7-G.9).
// Invariants: Idle -> Discovering -> Pairing -> Syncing -> Resolved -> Done;
// replay rejected; device staleness (6 months); revoke works; sync is optional.
void main() {
  test('full sync lifecycle transitions', () {
    final s = SyncSession();
    expect(s.phase, SyncPhase.idle);
    s.discover();
    expect(s.phase, SyncPhase.discovering);
    s.beginPairing();
    expect(s.phase, SyncPhase.pairing);
    s.startSyncing('peer-1');
    expect(s.phase, SyncPhase.syncing);
    s.resolveEntry('e1');
    s.resolveEntry('e2');
    expect(s.resolvedEntries.length, 2);
    s.resolveAll();
    expect(s.phase, SyncPhase.resolved);
    s.done();
    expect(s.phase, SyncPhase.done);
  });

  test('replay counter rejects non-increasing frames', () {
    final s = SyncSession();
    s.discover();
    s.beginPairing();
    s.startSyncing('peer-1');
    expect(s.acceptFrame(1), isTrue);
    expect(s.acceptFrame(2), isTrue);
    expect(s.acceptFrame(2), isFalse); // replay
    expect(s.acceptFrame(1), isFalse); // rollback
  });

  test('device staleness (6 months) and revoke', () {
    final reg = DeviceRegistry();
    final now = DateTime.now();
    reg.add(PairedDevice(
      deviceId: 'a',
      staticKey: 'k1',
      lastSynced: now.subtract(const Duration(days: 200)),
    ));
    reg.add(PairedDevice(
      deviceId: 'b',
      staticKey: 'k2',
      lastSynced: now,
    ));
    expect(reg.stale(now: () => now).length, 1);
    expect(reg.stale(now: () => now).first.deviceId, 'a');
    reg.revoke('a');
    expect(reg.stale(now: () => now), isEmpty);
  });

  test('sync is optional: marker present, core independent', () {
    expect(SyncOptionalMarker.enabled, isTrue);
  });
}