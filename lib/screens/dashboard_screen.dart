import 'package:flutter/material.dart';
import 'package:vault_crypto/src/app/vault_service.dart';

// Intent: Local Security Dashboard (Phase K.1). Shows duplicate/weak/old
// password warnings, fully local, zero network.
class DashboardScreen extends StatelessWidget {
  final VaultService service;
  const DashboardScreen({super.key, required this.service});

  @override
  Widget build(BuildContext context) {
    final warnings = service.dashboardWarnings();
    return Scaffold(
      appBar: AppBar(title: const Text('Security Dashboard')),
      body: warnings.isEmpty
          ? const Center(
              child: Text('No security warnings. Your vault looks healthy.'))
          : ListView.builder(
              itemCount: warnings.length,
              itemBuilder: (ctx, i) {
                final w = warnings[i];
                final icon = switch (w.type) {
                  'duplicate' => Icons.content_copy,
                  'weak' => Icons.warning_amber,
                  _ => Icons.schedule,
                };
                final color = w.severity == 'high' ? Colors.red : Colors.orange;
                return ListTile(
                  leading: Icon(icon, color: color),
                  title: Text(w.detail),
                  subtitle: Text('${w.type} • ${w.entryId}'),
                );
              },
            ),
    );
  }
}
