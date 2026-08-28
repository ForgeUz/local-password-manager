import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:path_provider/path_provider.dart';
import 'package:vault_crypto/src/app/vault_service.dart';
import 'package:vault_crypto/src/crypto/native/secure_buffer.dart';
import 'package:vault_crypto/src/sync/sync_state.dart';
import 'package:vault_crypto/src/sync/sync_store.dart';

bool get _bleSyncSupported => Platform.isAndroid;

class SyncScreen extends StatefulWidget {
  final VaultService service;
  const SyncScreen({super.key, required this.service});

  @override
  State<SyncScreen> createState() => _SyncScreenState();
}

class _SyncScreenState extends State<SyncScreen> {
  static const _method =
      MethodChannel('com.example.vault_crypto/ble_transport');
  static const _peers = EventChannel('com.example.vault_crypto/ble_peers');
  static const _data = EventChannel('com.example.vault_crypto/ble_data');

  late final SyncStore _store;

  @override
  void initState() {
    super.initState();
    _store = SyncStore();

    _method.setMethodCallHandler((call) async {
      switch (call.method) {
        case 'onConnected':
          _store.dispatch(Connected());
          break;
        case 'onDisconnected':
          _store.dispatch(Disconnected());
          break;
        case 'onConnectionFailed':
        case 'onConnectionRejected':
          _store.dispatch(ErrorOccurred('Connection failed/rejected'));
          break;
      }
    });

    _peers.receiveBroadcastStream().listen((event) {
      final map = Map<String, dynamic>.from(event as Map);
      final id = map['peerId'] as String;
      if (map['type'] == 'found') {
        _store.dispatch(
            PeerDiscovered(id, (map['deviceName'] ?? 'peer') as String));
      } else if (map['type'] == 'lost') {
        _store.dispatch(PeerLost(id));
      }
    });

    _data.receiveBroadcastStream().listen((event) async {
      final bytes = (event as Uint8List);
      _store.dispatch(BlobReceived(bytes));
    });
  }

  @override
  void dispose() {
    _store.dispose();
    super.dispose();
  }

  Future<void> _host() async {
    try {
      await _method
          .invokeMethod('startAdvertising', {'deviceName': 'Vault Host'});
      _store.dispatch(HostPressed());
    } catch (e) {
      _store.dispatch(ErrorOccurred('Advertise failed: $e'));
    }
  }

  Future<void> _sendBlob() async {
    _store.dispatch(SendVaultPressed());
    String? path;
    try {
      final tmp = await getTemporaryDirectory();
      path = '${tmp.path}/sync_export.vault';
      await widget.service.exportVaultFile(path);
      final bytes = await File(path).readAsBytes();
      await _method.invokeMethod('sendData', {'data': bytes});
      _store.dispatch(ResetPressed());
    } catch (e) {
      _store.dispatch(ErrorOccurred('Send failed: $e'));
    } finally {
      if (path != null) {
        final f = File(path);
        if (f.existsSync()) f.deleteSync();
      }
    }
  }

  Future<void> _join() async {
    try {
      await _method.invokeMethod('startScanning');
      _store.dispatch(JoinPressed());
    } catch (e) {
      _store.dispatch(ErrorOccurred('Scan failed: $e'));
    }
  }

  Future<void> _connect(String peerId) async {
    _store.dispatch(ConnectPressed(peerId));
    await _method.invokeMethod('connect', {'peerId': peerId});
  }

  Future<void> _reset() async {
    try {
      await _method.invokeMethod('stopScanning');
    } catch (_) {}
    try {
      await _method.invokeMethod('stopAdvertising');
    } catch (_) {}
    try {
      await _method.invokeMethod('disconnect');
    } catch (_) {}
    _store.dispatch(ResetPressed());
  }

  Future<void> _onBlobReceived(Uint8List bytes) async {
    final tmp = await getTemporaryDirectory();
    final path = '${tmp.path}/sync_incoming.vault';
    await File(path).writeAsBytes(bytes, flush: true);

    final mpController = TextEditingController();

    final ok = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Verify Master Password'),
        content: TextField(
          controller: mpController,
          obscureText: true,
          decoration: const InputDecoration(
              hintText: 'Enter master password to decrypt vault'),
        ),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(context, false),
              child: const Text('Cancel')),
          TextButton(
              onPressed: () => Navigator.pop(context, true),
              child: const Text('Verify')),
        ],
      ),
    );

    if (ok != true) {
      mpController.dispose();
      final f = File(path);
      if (f.existsSync()) f.deleteSync();
      _store.dispatch(ResetPressed());
      return;
    }

    SecureBuffer? mp;
    try {
      mp = SecureBuffer.alloc(mpController.text.codeUnits.length);
      mp.writeBytes(Uint8List.fromList(mpController.text.codeUnits));
      await widget.service.importVaultFile(path, mp);
      await widget.service.lock();
      if (mounted) {
        Navigator.pop(context);
      }
      _store.dispatch(VerifySuccess());
    } catch (_) {
      _store.dispatch(VerifyFailed('Wrong master password.'));
    } finally {
      mp?.dispose();
      mpController.dispose();
      final f = File(path);
      if (f.existsSync()) f.deleteSync();
    }
  }

  @override
  Widget build(BuildContext context) {
    if (!_bleSyncSupported) {
      return Scaffold(
        appBar: AppBar(title: const Text('P2P Sync (BLE)')),
        body: const Center(
          child: Padding(
            padding: EdgeInsets.all(24),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(Icons.bluetooth_disabled, size: 64, color: Colors.grey),
                SizedBox(height: 16),
                Text(
                  'P2P BLE sync is only available on Android.',
                  style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                  textAlign: TextAlign.center,
                ),
                SizedBox(height: 8),
                Text(
                  'On this device (Linux/desktop) the Bluetooth transport is not '
                  'implemented. Use the Android app to host or join a sync session.',
                  textAlign: TextAlign.center,
                ),
              ],
            ),
          ),
        ),
      );
    }

    return StreamBuilder<SyncState>(
        stream: _store.stateStream,
        initialData: _store.currentState,
        builder: (context, snapshot) {
          final state = snapshot.data ?? SyncIdle();
          return _buildBody(context, state);
        });
  }

  Widget _buildBody(BuildContext context, SyncState state) {
    return Scaffold(
      appBar: AppBar(title: const Text('P2P Sync (BLE)')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: Colors.blueGrey.withValues(alpha: 0.15),
              borderRadius: BorderRadius.circular(12),
            ),
            child: const Text(
              'Both devices: enable Bluetooth and grant Bluetooth + '
              'Nearby Wi-Fi permissions to Vault Crypto. Host sends the '
              'encrypted vault; receiver verifies it with the master password.',
              style: TextStyle(fontSize: 13),
            ),
          ),
          const SizedBox(height: 16),
          _buildActions(state),
          const SizedBox(height: 8),
          Align(
            alignment: Alignment.centerLeft,
            child: TextButton.icon(
              onPressed: _reset,
              icon: const Icon(Icons.refresh),
              label: const Text('Reset / Disconnect'),
            ),
          ),
          const SizedBox(height: 16),
          Text('Status: ${_statusText(state)}',
              style: const TextStyle(fontSize: 14)),
          const SizedBox(height: 24),
          _buildPeers(state),
        ],
      ),
    );
  }

  Widget _buildActions(SyncState state) {
    if (state is SyncConnected) {
      return ElevatedButton.icon(
        onPressed: _sendBlob,
        icon: const Icon(Icons.send),
        label: const Text('Send Vault'),
      );
    }
    return Row(
      children: [
        Expanded(
          child: ElevatedButton.icon(
            onPressed: state is SyncIdle ? _host : null,
            icon: const Icon(Icons.cast),
            label: const Text('Host (send)'),
          ),
        ),
        const SizedBox(width: 8),
        Expanded(
          child: ElevatedButton.icon(
            onPressed: state is SyncIdle ? _join : null,
            icon: const Icon(Icons.radar),
            label: const Text('Join (receive)'),
          ),
        ),
      ],
    );
  }

  Widget _buildPeers(SyncState state) {
    if (state is! SyncScanning) {
      return const Padding(
        padding: EdgeInsets.all(8),
        child: Text(
            'No peers yet. Press "Join" on this device and "Host" on the other.'),
      );
    }
    if (state.peers.isEmpty) {
      return const Padding(
        padding: EdgeInsets.all(8),
        child: Text('Scanning for peers...'),
      );
    }
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text('Discovered peers:', style: TextStyle(fontSize: 16)),
        ...state.peers.entries.map(
          (e) => ListTile(
            leading: const Icon(Icons.phone_android),
            title: Text(e.value),
            subtitle: Text(e.key),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => _connect(e.key),
          ),
        ),
      ],
    );
  }

  String _statusText(SyncState state) {
    if (state is SyncIdle) return 'Idle';
    if (state is SyncAdvertising) return 'Advertising...';
    if (state is SyncScanning) return 'Scanning...';
    if (state is SyncConnected) return 'Connected to peer';
    if (state is SyncTransferring) return state.message;
    if (state is SyncVerify) {
      WidgetsBinding.instance
          .addPostFrameCallback((_) => _onBlobReceived(state.bytes));
      return 'Received ${state.bytes.length} bytes, verifying...';
    }
    if (state is SyncError) return 'Error: ${state.message}';
    return 'Unknown';
  }
}
