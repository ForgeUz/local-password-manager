import 'dart:math';

// Intent: v5 H.8 — companion-device push approval. A login attempt on the
// primary device generates a 2-digit challenge; the companion device shows the
// challenge + 3 options (Approve / Deny / Ignore). The user must pick the
// option matching the challenge (number-matching defeats relay/phishing).
// Rate-limited: excess attempts are silently dropped.
// Invariants: challenge is 2 digits; exactly 3 options; rate-limited; the
// correct option is the one matching the challenge.
// Dependencies: dart:math (CSPRNG).

class PushApproval {
  static const int _maxAttempts = 5;

  // Generate a 2-digit challenge (00-99) + 3 options, one of which matches.
  static PushChallenge generate() {
    final r = Random.secure();
    final challenge = r.nextInt(100);
    // 3 options: the correct one + 2 decoys.
    final options = <int>[challenge];
    while (options.length < 3) {
      final d = r.nextInt(100);
      if (!options.contains(d)) options.add(d);
    }
    options.shuffle();
    return PushChallenge(challenge: challenge, options: options);
  }

  // Verify a submitted option against the challenge. Returns true if the
  // option matches. Rate-limited: after _maxAttempts wrong tries, returns false
  // and drops further attempts (silently).
  static bool verify(PushChallenge c, int option, {required int attempts}) {
    if (attempts >= _maxAttempts) return false; // rate-limited, silent drop
    return option == c.challenge;
  }
}

class PushChallenge {
  final int challenge; // 2-digit number shown on the primary device
  final List<int> options; // 3 options shown on the companion device
  const PushChallenge({required this.challenge, required this.options});
}