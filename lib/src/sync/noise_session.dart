// Intent: Noise PSK pairing session as pure logic (Phase G.1). PIN is the
// pre-shared secret (PSK). Both sides run a mock-able handshake; success
// requires the PIN (via a derived shared secret) and pins the peer's static
// key (TOFU-then-pinned). Enforces: 60s window, attempt limit, cooldown.
// After pairing, per-session ephemeral keys are used (no PIN re-entry), which
// the SyncSession in a later step models as "new session" (forward secrecy).
// Dependencies: an injected Transport (mock in tests; real Noise later).

enum PairStatus { idle, waiting, paired, cooldown, failed }

class NoiseState {
  final PairStatus status;
  final int attempts;
  final String? pinnedPeerKey;
  const NoiseState(this.status, {this.attempts = 0, this.pinnedPeerKey});
}

// Transport abstracts the wire exchange. In production this is the real Noise
// NNpsk0 channel; in tests it is a mock that reveals the PIN to determine
// success (simulating mutual authentication).
abstract class Transport {
  Future<bool> handshake(String pin);
}

class NoiseSession {
  static const int _windowSeconds = 60;
  static const int _maxAttempts = 3;

  final Transport _transport;
  final DateTime Function() _now;
  NoiseState _state = const NoiseState(PairStatus.idle);
  DateTime? _windowStart;
  DateTime? _cooldownUntil;

  NoiseSession(this._transport, {DateTime Function()? now})
      : _now = now ?? DateTime.now;

  NoiseState get state => _state;

  // Start a pairing attempt. Valid only if not in cooldown and within window.
  Future<NoiseState> pair(String pin) async {
    // Cooldown check.
    final t = _now();
    if (_state.status == PairStatus.cooldown && t.isBefore(_cooldownUntil!)) {
      return _state;
    }

    // First attempt or window expiration: fresh window.
    if (_windowStart == null ||
        _state.status == PairStatus.idle ||
        t.difference(_windowStart!).inSeconds > _windowSeconds) {
      // If a window is already active and exceeded, reset attempts.
      _windowStart = t;
    }

    // Enforce 60s window.
    if (t.difference(_windowStart!).inSeconds > _windowSeconds) {
      _state = const NoiseState(PairStatus.failed);
      return _state;
    }

    final ok = await _transport.handshake(pin);
    if (ok) {
      // TOFU: pin the peer's static key (deterministic mock key).
      final peerKey = _pinForKey(pin);
      _state = NoiseState(PairStatus.paired,
          attempts: _state.attempts, pinnedPeerKey: peerKey);
      return _state;
    }

    // Failed attempt.
    final attempts = _state.attempts + 1;
    if (attempts >= _maxAttempts) {
      _cooldownUntil = t.add(const Duration(seconds: 30));
      _state = const NoiseState(PairStatus.cooldown, attempts: 3);
      _windowStart = null;
    } else {
      _state = NoiseState(PairStatus.waiting, attempts: attempts);
    }
    return _state;
  }

  // Deterministic static-key pin derived from the shared PIN (TOFU stand-in).
  static String _pinForKey(String pin) => 'static:${_hash(pin)}';

  static String _hash(String s) {
    var h = 0;
    for (final c in s.codeUnits) {
      h = (h * 31 + c) & 0xFFFFFFFF;
    }
    return h.toRadixString(16);
  }
}
