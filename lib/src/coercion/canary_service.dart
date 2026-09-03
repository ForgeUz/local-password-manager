import 'dart:math';

import '../crypto/v4/vault_crypto_v4.dart';

// Intent: Canary (honeypot) entry generation (v4 §6.1). Pure logic, no state.
// Extracted from VaultService (god-class split, Part IV item 7) so the canary
// security boundary has its own module + test file.
// Invariants:
// - Exactly 3 canaries, marked isCanary, hidden from the UI.
// - Fake data MUST look real: no "canary/decoy/fake/dummy/test/example/bunker"
//   in any user-visible field (a coercer seeing them destroys deniability).
// - CSPRNG-derived strong passwords (12 chars, mixed classes).
// Dependencies: V4VaultEntry, dart:math.
class CanaryService {
  const CanaryService._();

  // Generate 3 realistic-looking honeypot canaries (v4 §6.1). Marked isCanary
  // so the UI filters them and access triggers the alarm.
  static List<V4VaultEntry> generate() {
    final seed = DateTime.now().millisecondsSinceEpoch;
    final titles = ['Netflix', 'Reddit', 'Steam'];
    final domains = ['netflix.com', 'reddit.com', 'steam.com'];
    final users = ['john.doe', 'user1990', 'm.kowalski'];
    return List.generate(3, (i) {
      final n = seed + i;
      return V4VaultEntry(
        id: 'c_$n',
        title: titles[i],
        username: users[i],
        password: _randomStrongPassword(n),
        url: domains[i],
        domain: domains[i],
        tier: 0,
        isCanary: true,
      );
    });
  }

  // CSPRNG strong password (12 chars, mixed classes).
  static String _randomStrongPassword(int seed) {
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
}