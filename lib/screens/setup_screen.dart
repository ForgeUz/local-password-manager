import 'package:flutter/material.dart';
import 'package:vault_crypto/src/app/vault_service.dart';
import 'package:vault_crypto/src/crypto/native/secure_buffer.dart';
import 'dart:typed_data';
import 'decoy_setup_screen.dart';

class SetupScreen extends StatefulWidget {
  final VaultService service;
  const SetupScreen({super.key, required this.service});

  @override
  State<SetupScreen> createState() => _SetupScreenState();
}

class _SetupScreenState extends State<SetupScreen> {
  final _mpController = TextEditingController();
  final _confirmController = TextEditingController();
  bool _created = false;

  Future<void> _createVault() async {
    if (_mpController.text != _confirmController.text) {
      ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Passwords do not match')));
      return;
    }
    if (_mpController.text.isEmpty) return;

    final mpBytes = Uint8List.fromList(_mpController.text.codeUnits);
    final mp = SecureBuffer.alloc(mpBytes.length);
    mp.writeBytes(mpBytes);

    // Fail-closed: a crypto failure (Argon2id, disk write) surfaces as a
    // SnackBar instead of an unhandled async crash ("Lost connection").
    try {
      await widget.service.createVault(mp);
      if (mounted) setState(() => _created = true);
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Vault creation failed: $e')),
        );
      }
    }
  }

  // v5 Two-Bunker: after the Primary Vault is created, offer the isolated
  // Decoy Vault (Bunker 2). The DecoySetupScreen wizard handles the duress MP
  // + decoy entries + one-time cancellation code.
  void _openDecoyWizard(BuildContext context) {
    Navigator.push(
      context,
      MaterialPageRoute(
        builder: (_) => DecoySetupScreen(service: widget.service),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Create Vault')),
      body: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Text('No vault found. Create a new one.', style: TextStyle(fontSize: 18)),
            const SizedBox(height: 24),
            TextField(
              controller: _mpController,
              obscureText: true,
              decoration: const InputDecoration(labelText: 'Master Password'),
            ),
            const SizedBox(height: 16),
            TextField(
              controller: _confirmController,
              obscureText: true,
              decoration: const InputDecoration(labelText: 'Confirm Password'),
            ),
            const SizedBox(height: 24),
            ElevatedButton(
              onPressed: _createVault,
              child: const Text('Create Vault'),
            ),
            if (_created) ...[
              const SizedBox(height: 16),
              const Text(
                'Vault created. Do you want to create an additional, '
                'isolated vault?',
                style: TextStyle(fontSize: 14),
              ),
              const SizedBox(height: 12),
              ElevatedButton(
                onPressed: () => _openDecoyWizard(context),
                child: const Text('Create Secondary Vault'),
              ),
            ],
          ],
        ),
      ),
    );
  }
}