import 'package:flutter/widgets.dart';
import 'lockable.dart';

// Intent: OS lifecycle observer. On AppLifecycleState.paused/inactive, lock
// the vault (wipe VRK). This is the v4 §8 Phase D.5 / v2 §5.1 background-wipe
// trigger, applied on both Android and Linux.
// Invariants: paused/inactive -> lock(); resumed does not lock.
// State Transition: active -> paused/inactive -> Lockable.lock()
// Dependencies: Lockable, flutter/widgets (WidgetsBindingObserver).

class LifecycleController with WidgetsBindingObserver {
  final Lockable _service;
  bool _lockedOnPause = false;

  LifecycleController(this._service);

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.paused || state == AppLifecycleState.inactive) {
      _lockedOnPause = true;
      _service.lock();
    }
  }

  bool get lockedOnPause => _lockedOnPause;
}