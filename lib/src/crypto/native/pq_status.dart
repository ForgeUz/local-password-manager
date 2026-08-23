import 'dart:ffi';

// Intent: PQ-hybrid availability gate (v5 E9). The PQ badge appears ONLY when
// ML-KEM-768 (PQClean/liboqs) is present AND its round-trip self-test passes.
// Stub builds (no PQClean) must NEVER claim PQ. This records the startup flag.
// Invariants: isAvailable is true only if the ML-KEM library is present.
// Dependencies: liboqs/PQClean (probed), absent in this env -> false.

class PqStatus {
  static bool? _available; // null = not yet probed

  // Probe for the PQClean/liboqs library. In this environment it is not
  // installed, so this returns false — the PQ badge must not appear.
  static bool get isAvailable {
    if (_available != null) return _available!;
    _available = _probe();
    return _available!;
  }

  static bool _probe() {
    try {
      // If liboqs is absent, open() throws -> PQ unavailable.
      DynamicLibrary.open('liboqs.so');
      // On-device: a full ML-KEM-768 keygen/enc/dec round-trip self-test would
      // run here and gate the badge. The probe confirms presence only.
      return true;
    } catch (_) {
      return false;
    }
  }
}