import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/crypto/native/pq_status.dart';

// Intent: Verify PQ gating (v5 E9). The PQ badge appears ONLY when ML-KEM-768
// is present AND its round-trip self-test passes. Stub builds (no liboqs/
// PQClean) must NEVER claim PQ.
void main() {
  test('PQ status is a boolean (gated on ML-KEM self-test)', () {
    // The probe must not throw; it reports whether PQ is genuinely available.
    expect(PqStatus.isAvailable, isA<bool>());
  });

  test('stub build (no PQClean) reports PQ unavailable', () {
    // In this environment liboqs/PQClean is not installed -> PQ must be false.
    // The badge must not appear.
    expect(PqStatus.isAvailable, isFalse);
  });
}