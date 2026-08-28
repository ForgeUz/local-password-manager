import 'dart:async';
import '../lock/state.dart';
import '../lock/intent.dart';
import '../lock/reducer.dart';

class AppStore {
  LockState _state = Initial();
  final _stateController = StreamController<LockState>.broadcast();

  LockState get currentState => _state;
  Stream<LockState> get stateStream => _stateController.stream;

  void dispatch(LockIntent intent) {
    final newState = reduce(_state, intent);

    if (newState != _state) {
      _state = newState;
      _stateController.add(_state);
    }
  }

  void dispose() {
    _stateController.close();
  }
}
