import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:path_provider/path_provider.dart';
import 'package:vault_crypto/src/app/vault_service.dart';
import 'package:vault_crypto/src/crypto/native/secure_buffer.dart';

// Intent: P2P BLE sync is Android-only (Nearby Connections). On Linux/desktop
// there is no ble_transport channel implementation, so invoking it throws
// MissingPluginException. Gate the whole screen to Android and show a clear
// message elsewhere instead of a crash.
bool get _bleSyncSupported => Platform.isAndroid;

// Typestate: explicit UI state machine. Invalid transitions unrepresentable.
// State Transition: idle -> advertising/scanning -> connected -> sending -> idle.
// On fail/disconnect -> idle (Host button always recoverable).
enum SyncUiState { idle, advertising, scanning, connected, sending }

// Intent: Minimal P2P BLE sync screen bridging the Kotlin BleTransportPlugin
// (Nearby Connections) to the vault service. Host advertises and SENDS the
// encrypted blob; client discovers, connects and RECEIVES it, then verifies
// it with the master password via importVaultFile (proof of possession).
//
// SECURITY NOTE: the transferred blob is already AES-256-GCM encrypted at
// rest, so the BLE transport never sees plaintext. The full Noise NNpsk0
// pairing layer (lib/src/sync) will be wired on top in a later iteration.
//
// REQUIREMENTS: both devices need Bluetooth + Nearby Wi-Fi devices runtime
// permissions granted (Settings -> Apps -> Vault Crypto -> Permissions) and
// Google Play Services present.
class SyncScreen extends StatefulWidget {
  final VaultService service;
  const SyncScreen({super.key, required this.service});

  @override
  State<SyncScreen> createState() => _SyncScreenState();
}

class _SyncScreenState extends State<SyncScreen> {
  // Channel names MUST match BleTransportPlugin.kt
  static const _method = MethodChannel('com.example.vault_crypto/ble_transport');
  static const _peers = EventChannel('com.example.vault_crypto/ble_peers');
  static const _data = EventChannel('com.example.vault_crypto/ble_data');

  SyncUiState _state = SyncUiState.idle;
  String _status = 'Idle';
  final Map<String, String> _foundPeers = {}; // peerId -> deviceName

  // State Transition: any -> newState; single write point for state+status.
  void _set(SyncUiState s, String msg) => setState(() { _state = s; _status = msg; });

  @override
  void initState() {
    super.initState();
    // Kotlin -> Dart: connection lifecycle callbacks
    _method.setMethodCallHandler((call) async {
      switch (call.method) {
        case 'onConnected':
          _set(SyncUiState.connected, 'Connected to peer');
          break;
        case 'onDisconnected':
          _set(SyncUiState.idle, 'Disconnected'); // reset -> Host returns
          break;
        case 'onConnectionFailed':
        case 'onConnectionRejected':
          _set(SyncUiState.idle, 'Connection failed/rejected');
          break;
      }
    });

    // Kotlin -> Dart: discovered peers stream
    _peers.receiveBroadcastStream().listen((event) {
      final map = Map<String, dynamic>.from(event as Map);
      final id = map['peerId'] as String;
      if (map['type'] == 'found') {
        setState(() => _foundPeers[id] = (map['deviceName'] ?? 'peer') as String);
      } else if (map['type'] == 'lost') {
        setState(() => _foundPeers.remove(id));
      }
    });

    // Kotlin -> Dart: incoming encrypted blob bytes
    _data.receiveBroadcastStream().listen((event) async {
      final bytes = (event as Uint8List);
      _set(SyncUiState.sending, 'Received ${bytes.length} bytes, verifying...');
      await _onBlobReceived(bytes);
    });
  }

  // HOST: export current encrypted blob to temp file and send it over BLE.
  Future<void> _host() async {
    if (_state != SyncUiState.idle) return; // re-entrancy guard
    _set(SyncUiState.advertising, 'Advertising...');
    try {
      await _method.invokeMethod('startAdvertising', {'deviceName': 'Vault Host'});
    } catch (e) {
      _set(SyncUiState.idle, 'Advertise failed: $e (grant Bluetooth permissions!)');
    }
  }

  Future<void> _sendBlob() async {
    if (_state != SyncUiState.connected) return; // only send when connected
    _set(SyncUiState.sending, 'Sending vault...');
    String? path;
    try {
      final tmp = await getTemporaryDirectory();
      path = '${tmp.path}/sync_export.vault';
      await widget.service.exportVaultFile(path);
      final bytes = await File(path).readAsBytes();
      await _method.invokeMethod('sendData', {'data': bytes});
      _set(SyncUiState.idle, 'Vault sent (${bytes.length} bytes).'); // reset -> Host returns
    } catch (e) {
      _set(SyncUiState.idle, 'Send failed: $e'); // reset on failure too
    } finally {
      if (path != null) {
        final f = File(path);
        if (f.existsSync()) f.deleteSync(); // wipe exported blob from disk
      }
    }
  }

  // CLIENT: scan for hosts.
  Future<void> _join() async {
    if (_state != SyncUiState.idle) return; // re-entrancy guard -> avoids 8002
    _set(SyncUiState.scanning, 'Scanning...');
    try {
      await _method.invokeMethod('startScanning');
    } catch (e) {
      _set(SyncUiState.idle, 'Scan failed: $e (grant Bluetooth permissions!)');
    }
  }

  Future<void> _connect(String peerId) async {
    _set(SyncUiState.scanning, 'Connecting to $peerId...');
    await _method.invokeMethod('connect', {'peerId': peerId});
  }

  // Explicit reset: always return to a hostable state, even mid-session.
  Future<void> _reset() async {
    try { await _method.invokeMethod('stopScanning'); } catch (_) {}
    try { await _method.invokeMethod('stopAdvertising'); } catch (_) {}
    try { await _method.invokeMethod('disconnect'); } catch (_) {}
    _foundPeers.clear();
    _set(SyncUiState.idle, 'Idle');
  }

  // CLIENT: persist received blob to temp file, verify with MP, replace live
  // vault, then force re-lock so the user re-unlocks the fresh vault.
  // Invariants: mp SecureBuffer is zeroed (disposed) and temp file deleted on
  // every exit path -> master password never lingers in native memory or disk.
  Future<void> _onBlobReceived(Uint8List bytes) async {
    final tmp = await getTemporaryDirectory();
    final path = '${tmp.path}/sync_incoming.vault';
    await File(path).writeAsBytes(bytes, flush: true);

    final mpController = TextEditingController();
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Verify received vault'),
        content: TextField(
          controller: mpController,
          obscureText: true,
          autocorrect: false,
          enableSuggestions: false,
          decoration: const InputDecoration(labelText: 'Master Password'),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
          ElevatedButton(onPressed: () => Navigator.pop(ctx, true), child: const Text('Verify')),
        ],
      ),
    );

    if (ok != true) {
      mpController.dispose();
      final f = File(path);
      if (f.existsSync()) f.deleteSync();
      _set(SyncUiState.idle, 'Import cancelled.');
      return;
    }

    SecureBuffer? mp;
    try {
      mp = SecureBuffer.alloc(mpController.text.codeUnits.length);
      mp.writeBytes(Uint8List.fromList(mpController.text.codeUnits));
      await widget.service.importVaultFile(path, mp);
      await widget.service.lock(); // force re-unlock with the new blob
      if (mounted) {
        Navigator.pop(context); // back to lock screen of the fresh vault
      }
    } catch (_) {
      _set(SyncUiState.idle, 'Verify failed: wrong master password.');
    } finally {
      mp?.dispose(); // zero master password from native memory
      mpController.dispose();
      final f = File(path);
      if (f.existsSync()) f.deleteSync();
    }
  }

  @override
  Widget build(BuildContext context) {
    if (!_bleSyncSupported) {
      // BLE P2P sync requires the Android Nearby Connections plugin. On
      // Linux/desktop there is no channel implementation -> show guidance.
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
              'encrypted vault; receiver verifies it with the master password.\n\n'
              'Master password: enter the SAME master password that unlocks the '
              'vault you are receiving. If the two devices use different master '
              'passwords, the transfer will fail verification (the vault is '
              'encrypted with the sender\'s password). The password is never '
              'transmitted over BLE — it only unlocks the already-encrypted file.',
              style: TextStyle(fontSize: 13),
            ),
          ),
          const SizedBox(height: 16),
          Row(
            children: [
              Expanded(
                child: ElevatedButton.icon(
                  onPressed: _state == SyncUiState.connected ? _sendBlob : _host,
                  icon: const Icon(Icons.cast),
                  label: Text(_state == SyncUiState.connected ? 'Send Vault' : 'Host (send)'),
                ),
              ),
              const SizedBox(width: 8),
              Expanded(
                child: ElevatedButton.icon(
                  onPressed: _join,
                  icon: const Icon(Icons.radar),
                  label: const Text('Join (receive)'),
                ),
              ),
            ],
          ),
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
          Text('Status: $_status', style: const TextStyle(fontSize: 14)),
          const SizedBox(height: 24),
          const Text('Discovered peers:', style: TextStyle(fontSize: 16)),
          if (_foundPeers.isEmpty)
            const Padding(
              padding: EdgeInsets.all(8),
              child: Text('No peers yet. Press "Join" on this device and "Host" on the other.'),
            ),
          ..._foundPeers.entries.map(
            (e) => ListTile(
              leading: const Icon(Icons.phone_android),
              title: Text(e.value),
              subtitle: Text(e.key),
              trailing: const Icon(Icons.chevron_right),
              onTap: () => _connect(e.key),
            ),
          ),
        ],
      ),
    );
  }
}
