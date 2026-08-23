import 'dart:async';
import 'intent.dart';

// Intent: Wraps Timer. Emits AutoLock intent on idle timeout.
// State Transition: Activity -> Timer Reset -> Timeout -> AutoLock Intent
class AutoLockController {
  final void Function(LockIntent) _dispatch;
  final Duration _timeout;
  Timer? _timer;

  AutoLockController({required void Function(LockIntent) dispatch, required Duration timeout}) 
      : _dispatch = dispatch, _timeout = timeout;

  void start() {
    _cancel();
    _timer = Timer(_timeout, () {
      _dispatch(AutoLock());
    });
  }

  void registerActivity() {
    start(); // Reset timer
  }

  void _cancel() {
    _timer?.cancel();
    _timer = null;
  }

  void dispose() {
    _cancel();
  }
}