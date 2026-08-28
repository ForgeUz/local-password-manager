import 'dart:typed_data';
import '../native/constant_time.dart';
import '../native/hmac_sha256.dart';

// Intent: v5 E11 — tier-downgrade cooldown as a DEVICE-ENFORCED policy using
// signed monotonic timestamps. The spec states honestly that a patched build
// can bypass device policy; this is enforcement against the honest path, not
// math. The cooldown timestamp is signed under a device key so it cannot be
// silently rolled back.
// Invariants: cooldown timestamp signed (tamper-evident); monotonic (a rolled-
// back timestamp is rejected); policy is device-enforced, honestly stated.
// State Transition: sign(ts, deviceKey) -> signed blob; enforce(signed, now,
// cooldownMs) -> allowed | denied.
// Dependencies: HmacSha256, ConstantTime, dart:typed_data.
//
// Signed blob layout: [timestamp(8, big-endian)][HMAC-SHA256(deviceKey, ts)(32)]

class Cooldown {
  static const int _tsSize = 8;
  static const int _sigSize = 32;

  // Sign a monotonic timestamp under the device key. Returns
  // [timestamp(8)][signature(32)].
  static Uint8List sign(Uint8List deviceKey, int timestampMillis) {
    final payload = _payload(timestampMillis);
    final sig = HmacSha256.compute(deviceKey, payload);
    final out = Uint8List(_tsSize + _sigSize);
    out.setRange(0, _tsSize, payload);
    out.setRange(_tsSize, out.length, sig);
    return out;
  }

  // Verify a signed timestamp and enforce the cooldown. Returns true if the
  // downgrade is allowed (cooldown elapsed), false if still cooling down.
  // Throws CooldownTamperError if the signature is invalid (forged/rolled-back).
  static bool enforce(Uint8List deviceKey, Uint8List signedTs, int nowMillis,
      int cooldownMillis) {
    if (signedTs.length != _tsSize + _sigSize) throw CooldownTamperError();
    final ts = _extractTimestamp(signedTs);
    final expected = sign(deviceKey, ts);
    if (!ConstantTime.equals(expected, signedTs)) {
      throw CooldownTamperError();
    }
    return (nowMillis - ts) >= cooldownMillis;
  }

  static Uint8List _payload(int timestampMillis) {
    final out = Uint8List(_tsSize);
    final bd = ByteData.sublistView(out);
    bd.setUint64(0, timestampMillis, Endian.big);
    return out;
  }

  static int _extractTimestamp(Uint8List signedTs) {
    final bd = ByteData.sublistView(signedTs, 0, _tsSize);
    return bd.getUint64(0, Endian.big);
  }
}

class CooldownTamperError implements Exception {}
