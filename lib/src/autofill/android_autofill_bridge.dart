import 'package:flutter/services.dart';
import '../app/app_store.dart';
import '../app/vault_service.dart';
import '../lock/state.dart';
import '../security/security_tier.dart';
import 'tier_autofill_enforcer.dart';

class AndroidAutofillBridge {
  static const _channel = MethodChannel('vault_crypto/autofill_bridge');
  final AppStore _store;
  final VaultService _service;
  String? _pendingDomain;

  AndroidAutofillBridge({required AppStore store, required VaultService service})
      : _store = store, _service = service {
    _channel.setMethodCallHandler(_handleMethod);
    _store.stateStream.listen(_onStateChange);
  }

  Future<dynamic> _handleMethod(MethodCall call) async {
    if (call.method == 'onAutofillRequested') {
      final domain = call.arguments['domain'] as String? ?? '';
      if (domain.isEmpty) return;
      
      if (_store.currentState is Unlocked) {
        await _processAutofill(domain);
      } else {
        _pendingDomain = domain;
      }
    }
  }

  void _onStateChange(LockState state) {
    if (state is Unlocked && _pendingDomain != null) {
      final domain = _pendingDomain!;
      _pendingDomain = null;
      _processAutofill(domain);
    }
  }

  Future<void> _processAutofill(String requestedDomain) async {
    final ids = _service.search(requestedDomain);
    if (ids.isEmpty) {
      await _channel.invokeMethod('cancelAutofill');
      return;
    }

    final entry = _service.getVaultEntry(ids.first);
    final tierInt = _service.getEntryTier(ids.first);
    if (entry == null || tierInt == null) {
      await _channel.invokeMethod('cancelAutofill');
      return;
    }

    final tier = SecurityTier.values[tierInt];
    
    final decision = TierAutofillEnforcer.decide(AutofillRequest(
      entryDomain: entry.url,
      requestedDomain: requestedDomain,
      tier: tier,
    ));

    switch (decision) {
      case FillImmediately():
      case FillAfterReauth():
        await _channel.invokeMethod('completeAutofill', {
          'username': entry.username,
          'password': entry.password,
        });
        break;
      case BlockManualOnly():
      case BlockDomainMismatch():
      case HardStopLookalike():
        await _channel.invokeMethod('cancelAutofill');
        break;
    }
  }
}
