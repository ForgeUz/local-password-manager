// Intent: Pure core for onboarding wizard state machine.
// Invariants:
// - Invalid transitions unrepresentable (sealed classes).
// - SecureBuffer lifecycle explicitly managed by Store.
// State Transition: Welcome -> Doctrine -> CreateMP -> DecoyOptIn -> Done.

import 'dart:async';
import '../crypto/native/secure_buffer.dart';

sealed class OnboardingState {}
class OnboardingWelcome implements OnboardingState {}
class OnboardingDoctrine implements OnboardingState {}
class OnboardingCreateMP implements OnboardingState {}
class OnboardingDecoyOptIn implements OnboardingState {}
class OnboardingDone implements OnboardingState {
  final bool createDecoy;
  OnboardingDone({required this.createDecoy});
}

sealed class OnboardingIntent {}
class BeginOnboarding implements OnboardingIntent {}
class AcceptDoctrine implements OnboardingIntent {}
class SubmitMP implements OnboardingIntent {
  final SecureBuffer mp;
  SubmitMP(this.mp);
}
class SkipDecoy implements OnboardingIntent {}
class CreateDecoy implements OnboardingIntent {}
class GoBack implements OnboardingIntent {}

OnboardingState _reduce(OnboardingState state, OnboardingIntent intent) {
  if (intent is GoBack) {
    if (state is OnboardingDoctrine) return OnboardingWelcome();
    if (state is OnboardingCreateMP) return OnboardingDoctrine();
    if (state is OnboardingDecoyOptIn) return OnboardingCreateMP();
  }
  if (state is OnboardingWelcome && intent is BeginOnboarding) return OnboardingDoctrine();
  if (state is OnboardingDoctrine && intent is AcceptDoctrine) return OnboardingCreateMP();
  if (state is OnboardingCreateMP && intent is SubmitMP) return OnboardingDecoyOptIn();
  if (state is OnboardingDecoyOptIn) {
    if (intent is SkipDecoy) return OnboardingDone(createDecoy: false);
    if (intent is CreateDecoy) return OnboardingDone(createDecoy: true);
  }
  return state;
}

class OnboardingStore {
  OnboardingState _state = OnboardingWelcome();
  SecureBuffer? _mp;
  final _controller = StreamController<OnboardingState>.broadcast();

  Stream<OnboardingState> get stream => _controller.stream;
  OnboardingState get currentState => _state;
  SecureBuffer? get masterPassword => _mp;

  void dispatch(OnboardingIntent intent) {
    if (intent is SubmitMP) {
      _mp?.dispose();
      _mp = intent.mp;
    }
    if (intent is GoBack && _state is OnboardingCreateMP) {
      // Wipe MP if user goes back to Doctrine
      _mp?.dispose();
      _mp = null;
    }
    final newState = _reduce(_state, intent);
    if (newState != _state) {
      _state = newState;
      _controller.add(_state);
    }
  }

  void dispose() {
    _mp?.dispose();
    _controller.close();
  }
}
