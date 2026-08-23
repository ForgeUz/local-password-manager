import 'package:flutter/material.dart';
import 'package:vault_crypto/src/app/app_store.dart';
import 'package:vault_crypto/src/app/vault_service.dart';
import 'package:vault_crypto/src/clipboard/clipboard_controller.dart';
import 'package:vault_crypto/src/lock/intent.dart';
import 'package:vault_crypto/src/lock/state.dart';
import 'package:vault_crypto/src/vault/vault_data.dart';
import 'dashboard_screen.dart';
import 'decoy_setup_screen.dart';
import 'entry_detail_screen.dart';
import 'settings_screen.dart';

class UnlockedScreen extends StatefulWidget {
  final AppStore store;
  final VaultService service;
  final ClipboardController clipboard;

  const UnlockedScreen({
    super.key,
    required this.store,
    required this.service,
    required this.clipboard,
  });

  @override
  State<UnlockedScreen> createState() => _UnlockedScreenState();
}

class _UnlockedScreenState extends State<UnlockedScreen> {
  final _searchController = TextEditingController();
  String _query = '';

  @override
  void dispose() {
    _searchController.dispose();
    super.dispose();
  }

  void _addEntryDialog(BuildContext context) {
    final titleCtrl = TextEditingController();
    final userCtrl = TextEditingController();
    final passCtrl = TextEditingController();

    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Add Entry'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            TextField(controller: titleCtrl, decoration: const InputDecoration(labelText: 'Title')),
            TextField(controller: userCtrl, decoration: const InputDecoration(labelText: 'Username')),
            TextField(controller: passCtrl, decoration: const InputDecoration(labelText: 'Password')),
          ],
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx), child: const Text('Cancel')),
          ElevatedButton(
            onPressed: () {
              if (titleCtrl.text.isNotEmpty) {
                // Await the async save so a crypto/disk failure surfaces as a
                // SnackBar instead of an unhandled async crash. The entry is
                // persisted to disk (writeBlob) + dispatched to the store.
                widget.service.addEntry(VaultEntry(
                  id: DateTime.now().millisecondsSinceEpoch.toString(),
                  title: titleCtrl.text,
                  username: userCtrl.text,
                  password: passCtrl.text,
                  url: titleCtrl.text.toLowerCase(),
                )).then((_) {
                  Navigator.pop(ctx);
                }).catchError((e) {
                  ScaffoldMessenger.of(ctx).showSnackBar(
                    SnackBar(content: Text('Save failed: $e')),
                  );
                });
              }
            },
            child: const Text('Save'),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final state = widget.store.currentState as Unlocked;
    final all = state.vaultData.entries;
    // Filter by service.search(query) if non-empty, else show all.
    final query = _query.trim();
    final ids = query.isEmpty ? null : widget.service.search(query);
    final shown = query.isEmpty
        ? all
        : all.where((e) => ids!.contains(e.id)).toList();

    // v5 deniability: when the secondary (duress) vault is open, the UI must
    // look EXACTLY like the primary vault — same title, same actions. The
    // service's isDuress flag is never surfaced to the user.
    return Scaffold(
      appBar: AppBar(
        title: const Text('Vault Unlocked'),
        actions: [
          IconButton(
            icon: const Icon(Icons.security),
            tooltip: 'Security Dashboard',
            onPressed: () {
              Navigator.push(
                context,
                MaterialPageRoute(
                  builder: (_) => DashboardScreen(service: widget.service),
                ),
              );
            },
          ),
          IconButton(
            icon: const Icon(Icons.lock_clock),
            onPressed: () => widget.store.dispatch(AutoLock()),
          ),
          IconButton(
            icon: const Icon(Icons.visibility_off),
            tooltip: 'Add Secondary Vault',
            onPressed: () {
              Navigator.push(
                context,
                MaterialPageRoute(
                  builder: (_) => DecoySetupScreen(service: widget.service),
                ),
              );
            },
          ),
          IconButton(
            icon: const Icon(Icons.settings),
            tooltip: 'Settings',
            onPressed: () {
              Navigator.push(
                context,
                MaterialPageRoute(
                  builder: (_) => SettingsScreen(service: widget.service),
                ),
              );
            },
          ),
        ],
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: () => _addEntryDialog(context),
        child: const Icon(Icons.add),
      ),
      body: Column(
        children: [
          Padding(
            padding: const EdgeInsets.all(8.0),
            child: TextField(
              controller: _searchController,
              decoration: const InputDecoration(
                labelText: 'Search',
                prefixIcon: Icon(Icons.search),
              ),
              onChanged: (v) => setState(() => _query = v),
            ),
          ),
          Expanded(
            child: shown.isEmpty
                ? const Center(child: Text('No entries yet. Add one!'))
                : ListView.builder(
                    itemCount: shown.length,
                    itemBuilder: (ctx, i) {
                      final entry = shown[i];
                      return ListTile(
                        title: Text(entry.title),
                        subtitle: Text(entry.username),
                        onTap: () {
                          Navigator.push(
                            context,
                            MaterialPageRoute(
                              builder: (_) => EntryDetailScreen(
                                service: widget.service,
                                clipboard: widget.clipboard,
                                entryId: entry.id,
                                title: entry.title,
                              ),
                            ),
                          );
                        },
                      );
                    },
                  ),
          ),
        ],
      ),
    );
  }
}