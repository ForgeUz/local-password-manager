import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:vault_crypto/src/app/app_store.dart';
import 'package:vault_crypto/src/app/vault_service.dart';
import 'package:vault_crypto/src/crypto/native/secure_buffer.dart';
import 'package:vault_crypto/src/lock/state.dart';
import 'package:vault_crypto/src/security/root_detection.dart';
import 'recover_from_shares_screen.dart';

class LockScreen extends StatefulWidget {
  final AppStore store;
  final VaultService service;
  final Uint8List blob;

  const LockScreen({super.key, required this.store, required this.service, required this.blob});

  @override
  State<LockScreen> createState() => _LockScreenState();
}

class _LockScreenState extends State<LockScreen> {
  final _controller = TextEditingController();

  void _attemptUnlock() {
    final mpStr = _controller.text;
    if (mpStr.isEmpty) return;

    final mpBytes = Uint8List.fromList(mpStr.codeUnits);
    final mp = SecureBuffer.alloc(mpBytes.length);
    mp.writeBytes(mpBytes);

    widget.service.unlock(mp);
    _controller.clear();
  }

  @override
  Widget build(BuildContext context) {
    final state = widget.store.currentState as Locked;
    bool isRateLimited = state.isRateLimited;
    String errorText = isRateLimited ? 'Too many attempts. Try again later.' : '';

    final rooted = RootDetection.isRooted(RootDetection.defaultMarkers);
    return Scaffold(
      appBar: AppBar(title: const Text('Vault Locked')),
      body: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            if (rooted) ...[
              Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: Colors.orange.shade100,
                  borderRadius: BorderRadius.circular(8),
                ),
                child: const Row(
                  children: [
                    Icon(Icons.warning_amber, color: Colors.orange),
                    SizedBox(width: 8),
                    Expanded(
                      child: Text(
                        'Rooted device detected. Keystore guarantees are weakened. Advisory only.',
                        style: TextStyle(color: Colors.black87),
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 16),
            ],
            const Icon(Icons.lock, size: 64, color: Colors.blueGrey),
            const SizedBox(height: 24),
            TextField(
              controller: _controller,
              obscureText: true,
              decoration: InputDecoration(
                labelText: 'Master Password',
                errorText: errorText.isNotEmpty ? errorText : null,
              ),
              onSubmitted: (_) => _attemptUnlock(),
            ),
            const SizedBox(height: 24),
            SizedBox(
              width: double.infinity,
              child: ElevatedButton(
                onPressed: isRateLimited ? null : _attemptUnlock,
                child: const Text('Unlock'),
              ),
            ),
            const SizedBox(height: 12),
            TextButton(
              onPressed: () {
                Navigator.push(
                  context,
                  MaterialPageRoute(
                    builder: (_) =>
                        RecoverFromSharesScreen(service: widget.service),
                  ),
                );
              },
              child: const Text('Recover from Shares'),
            ),
          ],
        ),
      ),
    );
  }
}