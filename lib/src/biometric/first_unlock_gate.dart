// Intent: v5 E20 — optional "require MP on first unlock of the day" so the
// duress path (which requires typing) stays reachable despite the biometric
// fast path. Biometric cannot signal duress — documented honestly. This gate is
// pure logic: the store/UI persists the flag; the gate decides whether the
// biometric fast path may unlock RIGHT NOW.
// Invariants: if armed and today has no unlock yet -> biometric denied (MP
// required); after the first MP unlock of the day -> biometric allowed for the
// rest of the day; if not armed -> biometric always allowed.
// State Transition: (armed, lastUnlockDay) + now -> requiresMp | recordUnlock.
// Dependencies: none (pure logic).

class FirstUnlockGate {
  // Optional setting, off by default.
  final bool requireMpOnFirstUnlock;
  // Day (YYYYMMDD string) of the last successful unlock, or null if none yet.
  String? _lastUnlockDay;

  FirstUnlockGate({this.requireMpOnFirstUnlock = false});

  // True when the biometric fast path is DENIED (the user must type the MP).
  // Biometric cannot signal duress; typing the MP keeps the duress path
  // reachable. Honest limitation: biometric never emits a duress signal.
  bool requiresMp(String day) {
    if (!requireMpOnFirstUnlock) return false;
    return _lastUnlockDay != day;
  }

  // Record a successful unlock (MP or biometric) for today.
  void recordUnlock(String day) {
    _lastUnlockDay = day;
  }
}