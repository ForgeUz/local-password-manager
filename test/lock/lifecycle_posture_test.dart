import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/lock/lifecycle_controller.dart';
import 'package:vault_crypto/src/lock/lockable.dart';
import 'package:vault_crypto/src/lock/posture_timer.dart';

// Intent: Verify lifecycle lock-on-pause and posture-driven idle auto-lock.
// Invariants: paused/inactive -> lock(); posture timeout -> lock(); interaction
// resets the timer.

// Minimal fake implementing Lockable.
class FakeService implements Lockable {
  int lockCount = 0;
  @override
  Future<void> lock() async {
    lockCount++;
  }
}

void main() {
  group('LifecycleController', () {
    test('paused triggers lock', () {
      final service = FakeService();
      final controller = LifecycleController(service);
      controller.didChangeAppLifecycleState(AppLifecycleState.paused);
      expect(service.lockCount, 1);
      expect(controller.lockedOnPause, isTrue);
    });

    test('inactive triggers lock', () {
      final service = FakeService();
      final controller = LifecycleController(service);
      controller.didChangeAppLifecycleState(AppLifecycleState.inactive);
      expect(service.lockCount, 1);
    });

    test('resumed does not lock', () {
      final service = FakeService();
      final controller = LifecycleController(service);
      controller.didChangeAppLifecycleState(AppLifecycleState.resumed);
      expect(service.lockCount, 0);
    });
  });

  group('PostureTimer', () {
    test('zero timeout locks immediately (lockdown posture)', () {
      final service = FakeService();
      final timer = PostureTimer(service);
      timer.onUnlock(
          canaryTriggered: true, networkRecognized: true, recentFailures: 0);
      expect(service.lockCount, 1);
      timer.dispose();
    });

    test('non-zero timeout does not lock immediately', () async {
      final service = FakeService();
      final timer = PostureTimer(service);
      // high posture -> 30s timeout; no immediate lock.
      timer.onUnlock(
          canaryTriggered: false, networkRecognized: false, recentFailures: 0);
      expect(service.lockCount, 0);
      timer.dispose();
      expect(service.lockCount, 0);
    });
  });
}
