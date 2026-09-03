import 'package:flutter/material.dart';
import 'package:vault_crypto/src/app/vault_service.dart';
import 'package:vault_crypto/src/security/shamir_kit.dart';

// Intent: Disaster-recovery unlock via Shamir shares (Phase I.8 UI). The user
// pastes K share strings; the MK is reconstructed and the vault unlocks.
// Anyone with K shares can access the vault — stated plainly.
// State Transition: input K shares -> parse -> unlockWithShares -> Unlocked.
// Dependencies: VaultService.unlockWithShares, ShamirKit.parseShare.
class RecoverFromSharesScreen extends StatefulWidget {
  final VaultService service;
  const RecoverFromSharesScreen({super.key, required this.service});

  @override
  State<RecoverFromSharesScreen> createState() =>
      _RecoverFromSharesScreenState();
}

class _RecoverFromSharesScreenState extends State<RecoverFromSharesScreen> {
  final _shareControllers = <TextEditingController>[
    TextEditingController(),
    TextEditingController(),
    TextEditingController(),
  ];

  @override
  void dispose() {
    for (final c in _shareControllers) {
      c.dispose();
    }
    super.dispose();
  }

  Future<void> _recover() async {
    final shares = <Share>[];
    for (final c in _shareControllers) {
      final text = c.text.trim();
      if (text.isEmpty) continue;
      try {
        shares.add(ShamirKit.parseShare(text));
      } catch (_) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Invalid share format.')),
        );
        return;
      }
    }
    if (shares.length < 3) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Enter at least 3 shares.')),
      );
      return;
    }
    final ok = await widget.service.unlockWithShares(shares);
    if (!mounted) return;
    if (!ok) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Recovery failed: shares do not match.')),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Recover from Shares')),
      body: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Enter K share strings to reconstruct the Master Key and unlock. '
              'Anyone with K shares can access your vault.',
              style: TextStyle(fontSize: 13),
            ),
            const SizedBox(height: 16),
            ..._shareControllers.asMap().entries.map((e) => Padding(
                  padding: const EdgeInsets.only(bottom: 8),
                  child: TextField(
                    controller: e.value,
                    decoration: InputDecoration(
                      labelText: 'Share ${e.key + 1}',
                      border: const OutlineInputBorder(),
                    ),
                  ),
                )),
            const SizedBox(height: 16),
            SizedBox(
              width: double.infinity,
              child: ElevatedButton(
                onPressed: _recover,
                child: const Text('Recover and Unlock'),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
