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
import 'sync_screen.dart';
import 'totp_screen.dart';

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
        content: SizedBox(
          width: double.maxFinite,
          child: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                TextField(
                  controller: titleCtrl,
                  autocorrect: false,
                  decoration: const InputDecoration(labelText: 'Title'),
                ),
                const SizedBox(height: 8),
                TextField(
                  controller: userCtrl,
                  autocorrect: false,
                  enableSuggestions: false,
                  decoration: const InputDecoration(labelText: 'Username'),
                ),
                const SizedBox(height: 8),
                TextField(
                  controller: passCtrl,
                  obscureText: true,
                  autocorrect: false,
                  enableSuggestions: false,
                  keyboardType: TextInputType.visiblePassword,
                  decoration: const InputDecoration(labelText: 'Password'),
                ),
              ],
            ),
          ),
        ),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(ctx), child: const Text('Cancel')),
          ElevatedButton(
            onPressed: () {
              if (titleCtrl.text.isNotEmpty) {
                widget.service
                    .addEntry(VaultEntry(
                  id: DateTime.now().millisecondsSinceEpoch.toString(),
                  title: titleCtrl.text,
                  username: userCtrl.text,
                  password: passCtrl.text,
                  url: titleCtrl.text.toLowerCase(),
                ))
                    .then((_) {
                  if (!ctx.mounted) return;
                  Navigator.pop(ctx);
                }).catchError((e) {
                  if (!ctx.mounted) return;
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
    final query = _query.trim();
    final ids = query.isEmpty ? null : widget.service.search(query);
    final shown =
        query.isEmpty ? all : all.where((e) => ids!.contains(e.id)).toList();

    return Scaffold(
      appBar: AppBar(
        title: const Text('Vault Unlocked'),
        // Keep the AppBar lean so the title is not truncated on narrow phones.
        // Secondary actions live in the overflow menu (PopupMenuButton).
        actions: [
          IconButton(
            icon: const Icon(Icons.lock_clock),
            tooltip: 'Lock now',
            onPressed: () => widget.store.dispatch(AutoLock()),
          ),
          PopupMenuButton<String>(
            tooltip: 'More',
            onSelected: (v) {
              switch (v) {
                case 'totp':
                  Navigator.push(
                      context, MaterialPageRoute(builder: (_) => TotpScreen()));
                  break;
                case 'sync':
                  Navigator.push(
                      context,
                      MaterialPageRoute(
                          builder: (_) => SyncScreen(service: widget.service)));
                  break;
                case 'dashboard':
                  Navigator.push(
                      context,
                      MaterialPageRoute(
                          builder: (_) =>
                              DashboardScreen(service: widget.service)));
                  break;
                case 'decoy':
                  Navigator.push(
                      context,
                      MaterialPageRoute(
                          builder: (_) =>
                              DecoySetupScreen(service: widget.service)));
                  break;
                case 'settings':
                  Navigator.push(
                      context,
                      MaterialPageRoute(
                          builder: (_) =>
                              SettingsScreen(service: widget.service)));
                  break;
              }
            },
            itemBuilder: (ctx) => const [
              PopupMenuItem(
                  value: 'totp',
                  child: ListTile(
                      leading: Icon(Icons.timer),
                      title: Text('TOTP Generator'))),
              PopupMenuItem(
                  value: 'sync',
                  child: ListTile(
                      leading: Icon(Icons.sync), title: Text('P2P Sync'))),
              PopupMenuItem(
                  value: 'dashboard',
                  child: ListTile(
                      leading: Icon(Icons.security),
                      title: Text('Security Dashboard'))),
              PopupMenuItem(
                  value: 'decoy',
                  child: ListTile(
                      leading: Icon(Icons.visibility_off),
                      title: Text('Secondary Vault'))),
              PopupMenuItem(
                  value: 'settings',
                  child: ListTile(
                      leading: Icon(Icons.settings), title: Text('Settings'))),
            ],
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
                      return Card(
                        margin: const EdgeInsets.symmetric(
                            horizontal: 8, vertical: 4),
                        child: ListTile(
                          contentPadding: const EdgeInsets.symmetric(
                              horizontal: 16, vertical: 8),
                          title: Text(
                            entry.title,
                            style: const TextStyle(
                                fontSize: 17, fontWeight: FontWeight.w600),
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                          ),
                          subtitle: Text(
                            entry.username,
                            style: const TextStyle(fontSize: 14),
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                          ),
                          trailing: const Icon(Icons.chevron_right),
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
                        ),
                      );
                    },
                  ),
          ),
        ],
      ),
    );
  }
}
