// Intent: Tracks per-session monotonic counter to drop replayed sync messages.
class ReplayCounter {
  int _lastSeen = 0;

  bool validate(int counter) {
    if (counter <= _lastSeen) return false;
    _lastSeen = counter;
    return true;
  }
}
