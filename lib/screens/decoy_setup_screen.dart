import 'dart:math';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:vault_crypto/src/app/vault_service.dart';
import 'package:vault_crypto/src/crypto/native/secure_buffer.dart';
import 'package:vault_crypto/src/crypto/v4/vault_crypto_v4.dart';

// Intent: Secondary Vault setup wizard (Phase J.4, v5 sanitized).
// The UI NEVER reveals the deniability mechanism. All user-facing strings are
// neutral ("Secondary Vault", "Additional Vault"). The secondary vault is
// cryptographically indistinguishable from the primary; a coerced user opens
// it with the secondary password and sees only low-value entries.
// State Transition: intro -> secondary MP -> entries -> confirmation code.
// Dependencies: VaultService.setupDecoy, SecureBuffer, dart:typed_data.

class DecoySetupScreen extends StatefulWidget {
  final VaultService service;
  const DecoySetupScreen({super.key, required this.service});

  // Test hook: expose the secondary-entry generator for the decoy-data
  // sanitization test (asserts no forbidden words leak into user-visible data).
  static List<V4VaultEntry> secondaryEntriesForTest() => _secondaryEntries();

  // Plausible low-value entries (5-10). Real-looking but harmless, so a
  // coerced user can hand them over without real credential loss. The data
  // MUST look like real accounts — realistic domains, usernames, strong
  // passwords. NO words like "decoy/fake/dummy/test/example/bunker" in any
  // user-visible field (a coercer seeing them destroys plausible deniability).
  static List<V4VaultEntry> _secondaryEntries() {
    final seed = DateTime.now().millisecondsSinceEpoch;
    final titles = [
      'Old Forum Account',
      'Free Newsletter',
      'Guest Wi-Fi Portal',
      'Throwaway Email',
      'Public Library Card',
      'Demo App Login',
      'Coupon Site',
      'Old Game Account',
    ];
    final domains = [
      'some-forum.com',
      'newsletter.io',
      'guestwifi.net',
      'mailbox.org',
      'library.gov',
      'apphub.io',
      'coupons.com',
      'oldgames.net',
    ];
    final users = [
      'john.doe',
      'sarah.lee',
      'm.kowalski',
      'user1990',
      'a.martin',
      'dev.user',
      'c.brown',
      'gamer.one',
    ];
    return List.generate(titles.length, (i) {
      final n = seed + i;
      return V4VaultEntry(
        id: 's_$n',
        title: titles[i],
        username: users[i],
        password: _strongPassword(n),
        url: domains[i],
        domain: domains[i],
        tier: 0,
      );
    });
  }

  // CSPRNG strong password (12 chars, mixed classes).
  static String _strongPassword(int seed) {
    final r = Random.secure();
    const lower = 'abcdefghijklmnopqrstuvwxyz';
    const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const digits = '0123456789';
    const syms = '!@#\$%^&*';
    final all = lower + upper + digits + syms;
    final sb = StringBuffer();
    for (var i = 0; i < 12; i++) {
      sb.write(all[r.nextInt(all.length)]);
    }
    return sb.toString();
  }

  @override
  State<DecoySetupScreen> createState() => _DecoySetupScreenState();
}

class _DecoySetupScreenState extends State<DecoySetupScreen> {
  final _primaryController = TextEditingController();
  final _secondaryController = TextEditingController();
  final _confirmController = TextEditingController();
  bool _enabled = false;
  bool _codeShown = false;
  String? _confirmationCode;

  @override
  void dispose() {
    _primaryController.dispose();
    _secondaryController.dispose();
    _confirmController.dispose();
    super.dispose();
  }

  Future<void> _finish(BuildContext context) async {
    if (!_enabled) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Enable the secondary vault first')),
      );
      return;
    }
    if (_secondaryController.text != _confirmController.text) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Passwords do not match')),
      );
      return;
    }
    if (_secondaryController.text.isEmpty) return;
    if (_primaryController.text.isEmpty) return;

    final primaryBytes = Uint8List.fromList(_primaryController.text.codeUnits);
    final primaryMp = SecureBuffer.alloc(primaryBytes.length);
    primaryMp.writeBytes(primaryBytes);
    final mpBytes = Uint8List.fromList(_secondaryController.text.codeUnits);
    final mp = SecureBuffer.alloc(mpBytes.length);
    mp.writeBytes(mpBytes);

    // Fail-closed: any error surfaces as a SnackBar, never a crash.
    try {
      _confirmationCode =
          await widget.service.setupDecoy(primaryMp, mp, DecoySetupScreen._secondaryEntries());
      if (mounted) setState(() => _codeShown = true);
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Setup failed: $e')),
        );
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    if (_codeShown) {
      // Confirmation code shown exactly once. Neutral copy — no deniability
      // vocabulary.
      return Scaffold(
        appBar: AppBar(title: const Text('Secondary Vault Ready')),
        body: Padding(
          padding: const EdgeInsets.all(16.0),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              const Text(
                'Confirmation code (shown once — write it down):',
                style: TextStyle(fontSize: 16),
              ),
              const SizedBox(height: 12),
              Text(
                _confirmationCode ?? '',
                style: const TextStyle(fontSize: 28, fontWeight: FontWeight.bold),
              ),
              const SizedBox(height: 24),
              ElevatedButton(
                onPressed: () => Navigator.pop(context),
                child: const Text('Done'),
              ),
            ],
          ),
        ),
      );
    }

    return Scaffold(
      appBar: AppBar(title: const Text('Create Secondary Vault')),
      body: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Text(
              'Create an additional, isolated vault. It is opened with a '
              'separate password and holds only low-value entries.',
              style: TextStyle(fontSize: 14),
            ),
            const SizedBox(height: 16),
            CheckboxListTile(
              value: _enabled,
              onChanged: (v) => setState(() => _enabled = v ?? false),
              title: const Text('Enable secondary vault'),
            ),
            const SizedBox(height: 16),
            TextField(
              controller: _primaryController,
              obscureText: true,
              decoration: const InputDecoration(labelText: 'Primary Master Password'),
            ),
            const SizedBox(height: 16),
            TextField(
              controller: _secondaryController,
              obscureText: true,
              decoration: const InputDecoration(labelText: 'Secondary Master Password'),
            ),
            const SizedBox(height: 16),
            TextField(
              controller: _confirmController,
              obscureText: true,
              decoration: const InputDecoration(labelText: 'Confirm Secondary Password'),
            ),
            const SizedBox(height: 16),
            const Text(
              'The secondary vault will be populated with 8 low-value entries.',
              style: TextStyle(fontSize: 13),
            ),
            const SizedBox(height: 24),
            ElevatedButton(
              onPressed: () => _finish(context),
              child: const Text('Create Secondary Vault'),
            ),
          ],
        ),
      ),
    );
  }
}