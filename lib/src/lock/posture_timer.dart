import 'dart:async';
import 'lockable.dart';
import '../security/adaptive_posture.dart';

// Intent: Idle auto-lock timer driven by the adaptive PosturePolicy. On unlock,
// evaluate posture -> start idle timer with the policy's auto-lock timeout.
// Any user interaction resets the timer; timeout triggers Lockable.lock().
// Invariants: timeout fires lock(); interaction resets; zero timeout locks
// immediately.
// State Transition: unlock -> start(timeout) -> interaction resets -> timeout -> lock()
// Dependencies: Lockable, AdaptivePosture, dart:async.

class PostureTimer {
  final Lockable _service;
  Timer? _timer;

  PostureTimer(this._service);

  // Evaluate posture and start the idle timer with its auto-lock timeout.
  // v5 E16: strictRoamingEnabled gates unknown-network escalation (opt-in, off
  // by default) so a roaming laptop does not live in permanent high posture.
  void onUnlock({
    required bool canaryTriggered,
    required bool networkRecognized,
    required int recentFailures,
    bool strictRoamingEnabled = false,
  }) {
    final policy = AdaptivePosture.evaluate(
      canaryTriggered: canaryTriggered,
      networkRecognized: networkRecognized,
      recentFailures: recentFailures,
      strictRoamingEnabled: strictRoamingEnabled,
    );
    _start(policy.autoLockTimeout);
  }

  void registerActivity() {
    // Reset the timer; the current timeout is preserved by re-reading it.
    // Caller re-invokes onUnlock with the same inputs to keep it simple, or
    // we store the last policy. Store the last timeout for reset.
    if (_lastTimeout != null) _start(_lastTimeout!);
  }

  Duration? _lastTimeout;

  void _start(Duration timeout) {
    _lastTimeout = timeout;
    _timer?.cancel();
    if (timeout == Duration.zero) {
      _service.lock();
      return;
    }
    _timer = Timer(timeout, () {
      _service.lock();
    });
  }

  void dispose() {
    _timer?.cancel();
    _timer = null;
  }
}