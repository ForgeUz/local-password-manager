import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/app/app_store.dart';
import 'package:vault_crypto/src/lock/state.dart';
import 'package:vault_crypto/src/lock/intent.dart';
import 'package:vault_crypto/src/vault/vault_data.dart';

// Intent: Verify the AppStore reducer transitions (v4 lock state machine).
// Flow: VaultLoaded -> Locked; UnlockSuccess -> Unlocked; UnlockFail -> Locked+1.
void main() {
  late AppStore store;

  setUp(() {
    store = AppStore();
  });

  test('VaultLoaded transitions Initial to Locked', () {
    store.dispatch(VaultLoaded(blob: Uint8List(0)));
    expect(store.currentState, isA<Locked>());
  });

  test('UnlockSuccess transitions Locked to Unlocked', () async {
    store.dispatch(VaultLoaded(blob: Uint8List(0)));
    final states = <LockState>[];
    final sub = store.stateStream.listen(states.add);

    store.dispatch(UnlockSuccess(vaultData: VaultData(entries: [])));
    await Future.delayed(Duration.zero);

    expect(states.last, isA<Unlocked>());
    sub.cancel();
  });

  test('UnlockFail increments fail count', () async {
    store.dispatch(VaultLoaded(blob: Uint8List(0)));
    expect((store.currentState as Locked).failCount, 0);

    store.dispatch(UnlockFail());
    await Future.delayed(Duration.zero);

    expect((store.currentState as Locked).failCount, 1);
    expect((store.currentState as Locked).isRateLimited, isTrue);
  });
}
