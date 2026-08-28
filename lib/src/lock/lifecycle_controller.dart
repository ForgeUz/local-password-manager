import 'package:flutter/widgets.dart';
import 'lockable.dart';

// Intent: OS lifecycle observer. On AppLifecycleState.paused/inactive, lock
// the vault (wipe VRK). This is the v4 §8 Phase D.5 / v2 §5.1 background-wipe
// trigger, applied on both Android and Linux.
//
// FIX: Added explicit timer-based lock after 1 second of background time.
// Some Android versions do NOT call paused/inactive on recent-apps swipe,
// so we use a timer as a fallback.
//
// Invariants: paused/inactive -> lock() OR timer fires after 1s.
// State Transition: active -> paused/inactive -> Lockable.lock()
// Dependencies: Lockable, flutter/widgets (WidgetsBindingObserver).

class LifecycleController with WidgetsBindingObserver {
  final Lockable _service;
  bool _lockedOnPause = false;
  bool _isBackgrounded = false;

  LifecycleController(this._service);

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.paused ||
        state == AppLifecycleState.inactive) {
      _lockedOnPause = true;
      _isBackgrounded = true;
      // FIX: Force lock immediately, then schedule a backup lock after 1s
      _service.lock();
      Future.delayed(const Duration(seconds: 1), () {
        if (_isBackgrounded) {
          _service.lock(); // Backup lock if the first one didn't work
        }
      });
    } else if (state == AppLifecycleState.resumed) {
      _isBackgrounded = false;
    }
  }

  bool get lockedOnPause => _lockedOnPause;
}
