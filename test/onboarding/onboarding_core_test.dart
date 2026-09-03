// File: test/onboarding/onboarding_core_test.dart
// Intent: Kill-tests for OnboardingStore state machine (M127-M129).
// Invariants:
// - Cannot skip Doctrine (Zero-Knowledge warning).
// - SubmitMP stores the SecureBuffer.
// - GoBack from CreateMP wipes the SecureBuffer reference.

import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/crypto/native/secure_buffer.dart';
import 'package:vault_crypto/src/onboarding/onboarding_core.dart';

void main() {
  group('M127: Cannot bypass Doctrine', () {
    test('Doctrine -> AcceptDoctrine -> CreateMP (not Done)', () {
      final store = OnboardingStore();
      store.dispatch(BeginOnboarding());
      store.dispatch(AcceptDoctrine());
      expect(store.currentState, isA<OnboardingCreateMP>());
      expect(store.currentState, isNot(isA<OnboardingDone>()));
    });
  });

  group('M128: SubmitMP stores the SecureBuffer', () {
    test('CreateMP -> SubmitMP -> DecoyOptIn (MP retained)', () {
      final store = OnboardingStore();
      store.dispatch(BeginOnboarding());
      store.dispatch(AcceptDoctrine());

      final mp = SecureBuffer.fromList(Uint8List.fromList([1, 2, 3]));
      store.dispatch(SubmitMP(mp));

      expect(store.currentState, isA<OnboardingDecoyOptIn>());
      expect(store.masterPassword, isNotNull);
    });
  });

  group('M129: GoBack from CreateMP wipes MP reference', () {
    test('GoBack from CreateMP -> Doctrine (MP cleared)', () {
      final store = OnboardingStore();
      store.dispatch(BeginOnboarding());
      store.dispatch(AcceptDoctrine());
      // To get to CreateMP WITH an MP stored, we must go forward to DecoyOptIn,
      // then go back to CreateMP.
      store.dispatch(
          SubmitMP(SecureBuffer.fromList(Uint8List.fromList([1, 2, 3]))));
      store.dispatch(GoBack()); // Back to CreateMP. MP is still stored.

      // Now go back again to Doctrine. This should trigger the wipe.
      store.dispatch(GoBack());

      expect(store.currentState, isA<OnboardingDoctrine>());
      expect(store.masterPassword, isNull);
    });

    test('GoBack from DecoyOptIn -> CreateMP (MP preserved)', () {
      final store = OnboardingStore();
      store.dispatch(BeginOnboarding());
      store.dispatch(AcceptDoctrine());
      store.dispatch(SubmitMP(SecureBuffer.fromList(Uint8List.fromList([1]))));
      // Now in DecoyOptIn. MP is stored.

      store.dispatch(GoBack());
      // Now in CreateMP. MP should STILL be stored.
      expect(store.currentState, isA<OnboardingCreateMP>());
      expect(store.masterPassword, isNotNull);
    });
  });
}
