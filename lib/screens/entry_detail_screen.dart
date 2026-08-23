import 'package:flutter/material.dart';
import 'package:vault_crypto/src/app/vault_service.dart';
import 'package:vault_crypto/src/clipboard/clipboard_controller.dart';

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
            Text('Entry: ${widget.title}', style: const TextStyle(fontSize: 20)),
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
              ],
            ),
            if (_revealed) ...[
              const SizedBox(height: 24),
              const Text('Password reveal is gated by secure memory. Password is available for copy.'),
            ],
          ],
        ),
      ),
    );
  }
}