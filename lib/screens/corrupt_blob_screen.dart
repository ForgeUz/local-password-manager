import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:vault_crypto/src/app/vault_service.dart';
import 'package:vault_crypto/src/crypto/native/secure_buffer.dart';

// Intent: the vault.blob exists but is corrupt / unreadable / an
// old-build leftover. The user may try the MP once (a corrupt write may
// still be partially decodable) or securely delete + start fresh.
// The reset path calls VaultService.resetVault (secure delete + route to
// SetupRequired).
class CorruptBlobScreen extends StatefulWidget {
  final VaultService service;
  const CorruptBlobScreen({super.key, required this.service});

  @override
  State<CorruptBlobScreen> createState() => _CorruptBlobScreenState();
}

class _CorruptBlobScreenState extends State<CorruptBlobScreen> {
  final _controller = TextEditingController();

  void _tryUnlock() {
    final mpStr = _controller.text;
    if (mpStr.isEmpty) return;
    // Best-effort real unlock — the crypto layer is paranoid; a wrong MP or
    // corrupt ciphertext will throw DecryptionFailedError.
    final mpBytes = Uint8List.fromList(mpStr.codeUnits);
    final mp = SecureBuffer.alloc(mpBytes.length);
    mp.writeBytes(mpBytes);
    widget.service.unlock(mp);
    _controller.clear();
  }

  void _reset() {
    widget.service.resetVault();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Vault Unreadable')),
      body: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Icon(Icons.error_outline, size: 64, color: Colors.orange),
            const SizedBox(height: 24),
            const Text(
              'An existing vault file was found but it is corrupted or '
              'unreadable (e.g. leftover from an older version).',
              textAlign: TextAlign.center,
              style: TextStyle(fontSize: 16),
            ),
            const SizedBox(height: 24),
            TextField(
              controller: _controller,
              obscureText: true,
              decoration: const InputDecoration(
                labelText: 'Master Password (try existing)',
              ),
              onSubmitted: (_) => _tryUnlock(),
            ),
            const SizedBox(height: 16),
            SizedBox(
              width: double.infinity,
              child: ElevatedButton(
                onPressed: _tryUnlock,
                child: const Text('Try Master Password'),
              ),
            ),
            const SizedBox(height: 12),
            SizedBox(
              width: double.infinity,
              child: OutlinedButton(
                onPressed: _reset,
                style: OutlinedButton.styleFrom(
                  foregroundColor: Colors.redAccent,
                ),
                child: const Text('Delete and Create New Vault'),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
