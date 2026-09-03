import 'package:flutter/material.dart';
import 'package:vault_crypto/src/app/vault_service.dart';
import 'package:vault_crypto/src/clipboard/clipboard_controller.dart';
import 'package:vault_crypto/src/passkey/passkey_challenge.dart';
import 'package:vault_crypto/src/passkey/passkey_platform.dart';

// Intent: View a single entry. Reveal Password calls VaultService.getEntry()
// (which applies random-subset decoy obfuscation + wipes decoys). Copy uses the
// clipboard controller (30s sensitive wipe).
class EntryDetailScreen extends StatefulWidget {
  final VaultService service;
  final ClipboardController clipboard;
  final String entryId;
  final String title;

  const EntryDetailScreen({
    super.key,
    required this.service,
    required this.clipboard,
    required this.entryId,
    required this.title,
  });

  @override
  State<EntryDetailScreen> createState() => _EntryDetailScreenState();
}

class _EntryDetailScreenState extends State<EntryDetailScreen> {
  bool _revealed = false;
  bool _creatingPasskey = false;
  bool _passkeyAttached = false;

  @override
  void initState() {
    super.initState();
    _passkeyAttached = widget.service.hasPasskey(widget.entryId);
  }

  Future<void> _createPasskey() async {
    if (_creatingPasskey || _passkeyAttached) return;
    setState(() => _creatingPasskey = true);

    final entry = widget.service.getEntry(widget.entryId);
    if (entry == null) {
      setState(() => _creatingPasskey = false);
      return;
    }

    final challenge = PasskeyChallenge.generate();
    final credId = await PasskeyPlatform.create(
      rpId: entry.url,
      rpName: entry.title,
      userId: widget.entryId,
      userName: entry.username,
      challenge: challenge,
    );

    if (credId != null) {
      await widget.service.attachPasskey(widget.entryId, credId);
      if (!mounted) return;
      setState(() {
        _passkeyAttached = true;
        _creatingPasskey = false;
      });
      ScaffoldMessenger.of(context)
          .showSnackBar(const SnackBar(content: Text('Passkey attached.')));
    } else {
      if (!mounted) return;
      setState(() => _creatingPasskey = false);
      ScaffoldMessenger.of(context).showSnackBar(const SnackBar(
          content: Text('Passkey creation cancelled or unsupported.')));
    }
  }

  void _reveal() {
    final entry = widget.service.getEntry(widget.entryId);
    if (entry == null) return;
    setState(() => _revealed = true);
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('Revealed via secure memory.')),
    );
  }

  void _copy() {
    final entry = widget.service.getEntry(widget.entryId);
    if (entry == null) return;
    widget.clipboard.copy(entry.password);
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('Copied. Wipes in 30s.')),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text(widget.title)),
      body: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Entry: ${widget.title}',
                style: const TextStyle(fontSize: 20)),
            const SizedBox(height: 16),
            Row(
              children: [
                Expanded(
                  child: ElevatedButton(
                    onPressed: _reveal,
                    child: const Text('Reveal Password'),
                  ),
                ),
                const SizedBox(width: 8),
                Expanded(
                  child: ElevatedButton.icon(
                    onPressed: _copy,
                    icon: const Icon(Icons.copy),
                    label: const Text('Copy'),
                  ),
                ),
              ], // <--- Здесь заканчивается список children у Row
            ), // <--- Здесь закрывается сам виджет Row
            // Теперь следующие виджеты относятся к списку children главного Column:
            const SizedBox(height: 12),
            ElevatedButton.icon(
              onPressed: (_creatingPasskey || _passkeyAttached)
                  ? null
                  : _createPasskey,
              icon: _creatingPasskey
                  ? const SizedBox(
                      width: 16,
                      height: 16,
                      child: CircularProgressIndicator(strokeWidth: 2))
                  : const Icon(Icons.key),
              label: Text(
                  _passkeyAttached ? 'Passkey Attached' : 'Create Passkey'),
              style: ElevatedButton.styleFrom(
                minimumSize: const Size(double.infinity, 40),
              ),
            ),

            if (_revealed) ...[
              const SizedBox(height: 24),
              const Text(
                  'Password reveal is gated by secure memory. Password is available for copy.'),
            ],
          ],
        ),
      ),
    );
  }
}
