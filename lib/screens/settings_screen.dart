import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:vault_crypto/src/app/vault_service.dart';
import 'package:vault_crypto/src/crypto/native/secure_buffer.dart';
import 'dart:io';
import 'package:flutter/foundation.dart';

// Intent: Settings screen with user-friendly vault export/import via the
// native Android file picker (Storage Access Framework). No manual path
// typing: the user visually chooses the destination/source file.
class SettingsScreen extends StatefulWidget {
  final VaultService service;
  const SettingsScreen({super.key, required this.service});

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  static const _filePicker = MethodChannel('vault_crypto/file_picker');
  final _shamirMpController = TextEditingController();
  int _shamirN = 5;
  int _shamirK = 3;
  List<String>? _shares;
  String? _exportStatus;
  String? _importStatus;
  bool _busy = false;

  @override
  void dispose() {
    _shamirMpController.dispose();
    super.dispose();
  }

  // Export: write blob to a temp file, then open the native "Save as"
  // dialog; Kotlin streams the temp file into the user-chosen URI.
  Future<void> _exportVault() async {
    if (_busy) return;
    setState(() {
      _busy = true;
      _exportStatus = 'Preparing encrypted file...';
    });

    try {
      final tmp = await Directory.systemTemp.createTemp('vault_export');
      final tmpPath = '${tmp.path}/vault_export.vault';

      debugPrint('Export: calling exportVaultFile...');
      await widget.service.exportVaultFile(tmpPath);

      final tmpFile = File(tmpPath);
      final tmpSize = await tmpFile.length();
      debugPrint('Export: temp file size=$tmpSize');

      if (tmpSize == 0) {
        setState(() => _exportStatus = 'Export failed: vault is empty');
        await tmp.delete(recursive: true);
        return;
      }

      setState(() => _exportStatus = 'Choose where to save...');
      final uri = await _filePicker.invokeMethod<String>(
        'pickExportPath',
        {'tmpPath': tmpPath},
      );

      debugPrint('Export: URI=$uri');
      setState(() => _exportStatus = '✓ Saved. Location: $uri');
      await tmp.delete(recursive: true);
    } on PlatformException catch (e) {
      debugPrint('Export PlatformException: ${e.code} - ${e.message}');
      setState(() => _exportStatus = e.code == 'cancelled'
          ? 'Export cancelled.'
          : 'Export failed: ${e.message}');
    } catch (e, stack) {
      debugPrint('Export exception: $e');
      debugPrint('Stack: $stack');
      setState(() => _exportStatus = 'Export failed: $e');
    } finally {
      setState(() => _busy = false);
    }
  }

  // Import: native "Open" dialog -> bytes -> MP verification -> replace vault.
  Future<void> _importVault() async {
    if (_busy) return;
    setState(() {
      _busy = true;
      _importStatus = 'Choose a .vault file...';
    });

    try {
      final bytes = await _filePicker.invokeMethod<Uint8List>('pickImportPath');
      if (bytes == null) {
        setState(() => _importStatus = 'Import cancelled.');
        return;
      }

      debugPrint('Import: received ${bytes.length} bytes');
      debugPrint(
          'Import: first 16 bytes: ${bytes.sublist(0, bytes.length > 16 ? 16 : bytes.length)}');

      final mpController = TextEditingController();
      final ok = await showDialog<bool>(
        context: context,
        builder: (ctx) => AlertDialog(
          title: const Text('Verify imported vault'),
          content: TextField(
            controller: mpController,
            obscureText: true,
            autocorrect: false,
            enableSuggestions: false,
            decoration: const InputDecoration(labelText: 'Master Password'),
          ),
          actions: [
            TextButton(
                onPressed: () => Navigator.pop(ctx, false),
                child: const Text('Cancel')),
            ElevatedButton(
                onPressed: () => Navigator.pop(ctx, true),
                child: const Text('Verify')),
          ],
        ),
      );

      if (ok != true) {
        setState(() => _importStatus = 'Import cancelled.');
        return;
      }

      debugPrint(
          'Import: password entered, length=${mpController.text.length}');

      final tmp = await Directory.systemTemp.createTemp('vault_import');
      final tmpPath = '${tmp.path}/vault_import.vault';
      await File(tmpPath).writeAsBytes(bytes, flush: true);
      debugPrint(
          'Import: wrote to $tmpPath, size=${await File(tmpPath).length()}');

      final mp = SecureBuffer.alloc(mpController.text.codeUnits.length);
      mp.writeBytes(Uint8List.fromList(mpController.text.codeUnits));

      debugPrint('Import: calling importVaultFile...');
      await widget.service.importVaultFile(tmpPath, mp);
      debugPrint('Import: success, calling lock()...');

      await widget.service.lock();
      await tmp.delete(recursive: true);

      if (mounted) {
        setState(() => _importStatus =
            '✓ Vault imported. Unlock with its master password.');
        Navigator.pop(context);
      }
    } on PlatformException catch (e) {
      debugPrint('Import PlatformException: ${e.code} - ${e.message}');
      setState(() => _importStatus = e.code == 'cancelled'
          ? 'Import cancelled.'
          : 'Import failed: ${e.message}');
    } catch (e, stack) {
      debugPrint('Import exception: $e');
      debugPrint('Stack: $stack');
      setState(() => _importStatus = 'Import failed: $e');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _generateShares(BuildContext context) async {
    final mpBytes = Uint8List.fromList(_shamirMpController.text.codeUnits);
    final mp = SecureBuffer.alloc(mpBytes.length);
    mp.writeBytes(mpBytes);
    try {
      final shares =
          await widget.service.generateShares(mp, n: _shamirN, k: _shamirK);
      setState(() => _shares = shares);
    } catch (_) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Share generation failed: wrong MP.')),
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
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            const Text('Backup',
                style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold)),
            const SizedBox(height: 8),
            const Text(
              'The exported file is fully encrypted (AES-256-GCM). '
              'It is safe to keep it in Downloads, on a USB stick or in cloud storage.',
              style:
                  TextStyle(fontSize: 13, color: Colors.white70, height: 1.5),
            ),
            const SizedBox(height: 16),
            ElevatedButton.icon(
              onPressed: _busy ? null : _exportVault,
              icon: const Icon(Icons.upload_file),
              label: const Text('Export encrypted vault'),
              style: ElevatedButton.styleFrom(
                padding: const EdgeInsets.symmetric(vertical: 16),
                shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(12)),
              ),
            ),
            if (_exportStatus != null)
              Padding(
                padding: const EdgeInsets.only(top: 8),
                child: Text(_exportStatus!,
                    style:
                        const TextStyle(fontSize: 12, color: Colors.white70)),
              ),
            const SizedBox(height: 24),
            ElevatedButton.icon(
              onPressed: _busy ? null : _importVault,
              icon: const Icon(Icons.download),
              label: const Text('Import vault from file'),
              style: ElevatedButton.styleFrom(
                padding: const EdgeInsets.symmetric(vertical: 16),
                shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(12)),
              ),
            ),
            if (_importStatus != null)
              Padding(
                padding: const EdgeInsets.only(top: 8),
                child: Text(_importStatus!,
                    style:
                        const TextStyle(fontSize: 12, color: Colors.white70)),
              ),
            const SizedBox(height: 40),
            const Text('Disaster Recovery (Shamir)',
                style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold)),
            const SizedBox(height: 8),
            const Text(
              'Split your Master Key into N shares; any K of them reconstruct it. '
              'Store shares in separate physical locations.',
              style:
                  TextStyle(fontSize: 13, color: Colors.white70, height: 1.5),
            ),
            const SizedBox(height: 16),
            Row(
              children: [
                Expanded(
                  child: TextField(
                    keyboardType: TextInputType.number,
                    decoration:
                        const InputDecoration(labelText: 'N (total shares)'),
                    onChanged: (v) => _shamirN = int.tryParse(v) ?? _shamirN,
                  ),
                ),
                const SizedBox(width: 8),
                Expanded(
                  child: TextField(
                    keyboardType: TextInputType.number,
                    decoration:
                        const InputDecoration(labelText: 'K (required)'),
                    onChanged: (v) => _shamirK = int.tryParse(v) ?? _shamirK,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 8),
            TextField(
              controller: _shamirMpController,
              obscureText: true,
              autocorrect: false,
              enableSuggestions: false,
              decoration: const InputDecoration(labelText: 'Master Password'),
            ),
            const SizedBox(height: 12),
            ElevatedButton(
              onPressed: () => _generateShares(context),
              child: const Text('Generate Shares'),
            ),
            if (_shares != null) ...[
              const SizedBox(height: 16),
              const Text(
                'WARNING: Anyone with K shares can access your vault.',
                style: TextStyle(color: Colors.orange, fontSize: 13),
              ),
              const SizedBox(height: 8),
              ..._shares!.asMap().entries.map((e) => Padding(
                    padding: const EdgeInsets.only(bottom: 4),
                    child: SelectableText('Share ${e.key + 1}: ${e.value}',
                        style: const TextStyle(fontSize: 12)),
                  )),
            ],
          ],
        ),
      ),
    );
  }
}
