import 'package:flutter/material.dart';
import 'package:vault_crypto/src/app/vault_service.dart';
import 'package:vault_crypto/src/crypto/native/secure_buffer.dart';
import 'dart:typed_data';

// Intent: Settings screen with manual vault export/import (Phase F.4).
// Export copies the raw V4 encrypted blob to a user path; import replaces the
// live blob after MP verification. Enables offline USB transfer.
// Dependencies: VaultService.exportVaultFile/importVaultFile, SecureBuffer.
class SettingsScreen extends StatefulWidget {
  final VaultService service;
  const SettingsScreen({super.key, required this.service});

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  final _exportPathController = TextEditingController();
  final _importPathController = TextEditingController();
  final _importMpController = TextEditingController();
  final _shamirMpController = TextEditingController();
  int _shamirN = 5;
  int _shamirK = 3;
  List<String>? _shares;

  @override
  void dispose() {
    _exportPathController.dispose();
    _importPathController.dispose();
    _importMpController.dispose();
    _shamirMpController.dispose();
    super.dispose();
  }

  // Generate N Shamir shares from the MK (derived from MP + vault salt).
  // Displays them as QR-ready base64 strings with the physical-separation
  // warning. Anyone with K shares can reconstruct the MK and unlock.
  Future<void> _generateShares(BuildContext context) async {
    final mpBytes = Uint8List.fromList(_shamirMpController.text.codeUnits);
    final mp = SecureBuffer.alloc(mpBytes.length);
    mp.writeBytes(mpBytes);
    try {
      final shares = await widget.service.generateShares(
        mp,
        n: _shamirN,
        k: _shamirK,
      );
      setState(() => _shares = shares);
    } catch (_) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Share generation failed: wrong MP.')),
      );
    }
  }

  void _export(BuildContext context) {
    final path = _exportPathController.text.trim();
    if (path.isEmpty) return;
    widget.service.exportVaultFile(path);
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('Vault exported (encrypted blob).')),
    );
  }

  void _import(BuildContext context) {
    final path = _importPathController.text.trim();
    if (path.isEmpty) return;
    final mpBytes = Uint8List.fromList(_importMpController.text.codeUnits);
    final mp = SecureBuffer.alloc(mpBytes.length);
    mp.writeBytes(mpBytes);
    try {
      widget.service.importVaultFile(path, mp);
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Vault imported and verified.')),
      );
    } catch (_) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Import failed: wrong MP or corrupt blob.')),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Settings')),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text('Export Vault', style: TextStyle(fontSize: 18)),
            const SizedBox(height: 8),
            TextField(
              controller: _exportPathController,
              decoration: const InputDecoration(labelText: 'Target path (.vault)'),
            ),
            const SizedBox(height: 8),
            ElevatedButton(
              onPressed: () => _export(context),
              child: const Text('Export Encrypted Vault'),
            ),
            const SizedBox(height: 24),
            const Text('Import Vault', style: TextStyle(fontSize: 18)),
            const SizedBox(height: 8),
            TextField(
              controller: _importPathController,
              decoration: const InputDecoration(labelText: 'Source path (.vault)'),
            ),
            const SizedBox(height: 8),
            TextField(
              controller: _importMpController,
              obscureText: true,
              decoration: const InputDecoration(labelText: 'Master Password'),
            ),
            const SizedBox(height: 8),
            ElevatedButton(
              onPressed: () => _import(context),
              child: const Text('Import + Verify'),
            ),
            const SizedBox(height: 32),
            const Text('Disaster Recovery (Shamir)',
                style: TextStyle(fontSize: 18)),
            const SizedBox(height: 8),
            const Text(
              'Split your Master Key into N shares; any K reconstruct it. '
              'Opt-in, off by default.',
              style: TextStyle(fontSize: 13),
            ),
            const SizedBox(height: 8),
            Row(
              children: [
                Expanded(
                  child: TextField(
                    keyboardType: TextInputType.number,
                    decoration: const InputDecoration(labelText: 'N (total shares)'),
                    onChanged: (v) =>
                        _shamirN = int.tryParse(v) ?? _shamirN,
                  ),
                ),
                const SizedBox(width: 8),
                Expanded(
                  child: TextField(
                    keyboardType: TextInputType.number,
                    decoration: const InputDecoration(labelText: 'K (required)'),
                    onChanged: (v) =>
                        _shamirK = int.tryParse(v) ?? _shamirK,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 8),
            TextField(
              controller: _shamirMpController,
              obscureText: true,
              decoration: const InputDecoration(labelText: 'Master Password'),
            ),
            const SizedBox(height: 8),
            ElevatedButton(
              onPressed: () => _generateShares(context),
              child: const Text('Generate Shares'),
            ),
            if (_shares != null) ...[
              const SizedBox(height: 16),
              const Text(
                'WARNING: Store these in separate physical locations. '
                'Anyone with K shares can access your vault.',
                style: TextStyle(color: Colors.orange, fontSize: 13),
              ),
              const SizedBox(height: 8),
              ..._shares!.asMap().entries.map((e) => Padding(
                    padding: const EdgeInsets.only(bottom: 4),
                    child: SelectableText(
                      'Share ${e.key + 1}: ${e.value}',
                      style: const TextStyle(fontSize: 12),
                    ),
                  )),
            ],
          ],
        ),
      ),
    );
  }
}