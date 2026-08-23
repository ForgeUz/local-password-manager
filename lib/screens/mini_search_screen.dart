import 'package:flutter/material.dart';
import 'package:vault_crypto/src/app/app_store.dart';
import 'package:vault_crypto/src/app/vault_service.dart';
import 'package:vault_crypto/src/clipboard/clipboard_controller.dart';
import 'package:vault_crypto/src/lock/state.dart';
import 'package:vault_crypto/src/vault/vault_data.dart';

// Intent: Quick floating mini-search window opened by the global hotkey
// (Ctrl+Shift+Space). Lists entries by SSE search; tapping an entry copies its
// password via ClipboardController (30s sensitive auto-wipe). Never renders
// passwords in the list — only titles/usernames.
// State Transition: hotkey -> open -> type query -> tap entry -> copy + wipe.
// Dependencies: VaultService.search, ClipboardController, AppStore.
class MiniSearchScreen extends StatefulWidget {
  final AppStore store;
  final VaultService service;
  final ClipboardController clipboard;

  const MiniSearchScreen({
    super.key,
    required this.store,
    required this.service,
    required this.clipboard,
  });

  @override
  State<MiniSearchScreen> createState() => _MiniSearchScreenState();
}

class _MiniSearchScreenState extends State<MiniSearchScreen> {
  final _searchController = TextEditingController();
  String _query = '';

  @override
  void dispose() {
    _searchController.dispose();
    super.dispose();
  }

  void _copy(String id) {
    final entry = widget.service.getEntry(id);
    if (entry == null) return;
    widget.clipboard.copy(entry.password);
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('Copied. Wipes in 30s.')),
    );
    Navigator.pop(context);
  }

  @override
  Widget build(BuildContext context) {
    final state = widget.store.currentState;
    final List<VaultEntry> all;
    if (state is Unlocked) {
      all = state.vaultData.entries;
    } else {
      all = const <VaultEntry>[];
    }
    final query = _query.trim();
    final ids = query.isEmpty ? null : widget.service.search(query);
    final shown = query.isEmpty
        ? all
        : all.where((e) => ids!.contains(e.id)).toList();

    return Scaffold(
      appBar: AppBar(title: const Text('Quick Search (Ctrl+Shift+Space)')),
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
                ? const Center(child: Text('No matches. Tap an entry to copy.'))
                : ListView.builder(
                    itemCount: shown.length,
                    itemBuilder: (ctx, i) {
                      final entry = shown[i];
                      return ListTile(
                        title: Text(entry.title),
                        subtitle: Text(entry.username),
                        trailing: const Icon(Icons.copy),
                        onTap: () => _copy(entry.id),
                      );
                    },
                  ),
          ),
        ],
      ),
    );
  }
}