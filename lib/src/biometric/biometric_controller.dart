import 'dart:async';
import 'biometric_platform.dart';
import '../lock/intent.dart';
import '../vault/vault_data.dart';

// Intent: Bridges native biometric result to pure lock state machine.
// State Transition: authenticate() -> Platform Bool -> Dispatch Intent
class BiometricController {
  final BiometricPlatform _platform;
  final void Function(LockIntent) _dispatch;

  BiometricController({
    required BiometricPlatform platform,
    required void Function(LockIntent) dispatch,
  })  : _platform = platform,
        _dispatch = dispatch;

  Future<void> authenticate() async {
    try {
      final success = await _platform.authenticate();
      if (success) {
        _dispatch(UnlockSuccess(vaultData: VaultData(entries: [])));
      } else {
        _dispatch(UnlockFail());
      }
    } catch (_) {
      _dispatch(UnlockFail());
    }
  }
}
