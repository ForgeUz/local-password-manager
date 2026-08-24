import 'dart:typed_data';
import 'hmac_sha256.dart';
import 'dart:io';

// Intent: RFC 6238 TOTP generation (over HMAC-SHA256 with RFC 4226 dynamic
// truncation, 30s step, 6 digits). Uses the available libsodium HMAC-SHA256
// primitive; the 4-byte dynamic-truncation is algorithm-agnostic. The result
// is a 6-digit code used as a KDF input.
// Invariants: deterministic for (seed, timeStep); matches RFC 4226 truncation.
// Dependencies: HmacSha256, dart:convert, dart:typed_data.

class Totp {
  static const int _digits = 6;
  static const int _stepSeconds = 30;

  // Decode a Base32 seed to raw bytes.
  static Uint8List decodeBase32(String s) {
    const alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    var buffer = 0;
    var bitsLeft = 0;
    final out = <int>[];
    for (final c in s.toUpperCase().replaceAll('=', '').codeUnits) {
      final v = alpha.indexOf(String.fromCharCode(c));
      if (v < 0) throw ArgumentError('Invalid Base32 char: $c');
      buffer = (buffer << 5) | v;
      bitsLeft += 5;
      if (bitsLeft >= 8) {
        out.add((buffer >> (bitsLeft - 8)) & 0xFF);
        bitsLeft -= 8;
      }
    }
    return Uint8List.fromList(out);
  }

  // Encode raw bytes to Base32 (RFC 4648).
  static String encodeBase32(Uint8List data) {
    const alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    final sb = StringBuffer();
    var buffer = 0;
    var bitsLeft = 0;
    for (final b in data) {
      buffer = (buffer << 8) | b;
      bitsLeft += 8;
      while (bitsLeft >= 5) {
        sb.write(alpha[(buffer >> (bitsLeft - 5)) & 31]);
        bitsLeft -= 5;
      }
    }
    if (bitsLeft > 0) {
      sb.write(alpha[(buffer << (5 - bitsLeft)) & 31]);
    }
    return sb.toString();
  }

  // Current 6-digit TOTP for the given seed (raw bytes) and Unix time.
  static String generate(Uint8List seed, int unixTimeSeconds) {
    final counter = unixTimeSeconds ~/ _stepSeconds;
    final msg = Uint8List(8);
    final bd = ByteData.sublistView(msg);
    bd.setUint64(0, counter, Endian.big);
    // HMAC-SHA256 over the 8-byte big-endian counter.
    final hmac = HmacSha256.compute(seed.length == 32 ? seed : _padKey(seed), msg);
    // RFC 4226 dynamic truncation: offset = last nibble.
    final offset = hmac[hmac.length - 1] & 0x0f;
    final binCode = ((hmac[offset] & 0x7f) << 24) |
        (hmac[offset + 1] << 16) |
        (hmac[offset + 2] << 8) |
        hmac[offset + 3];
    return (binCode % 1000000).toString().padLeft(_digits, '0');
  }

  // Verify a submitted code against the seed with ±skewSteps tolerance
  // (default 1 step = ±30s clock skew, v3 §12.5). Constant-time compare.
  static bool verify(Uint8List seed, String code, int unixTimeSeconds,
      {int skewSteps = 1}) {
    for (var i = -skewSteps; i <= skewSteps; i++) {
      final t = unixTimeSeconds + i * _stepSeconds;
      if (_constTimeEq(generate(seed, t), code)) return true;
    }
    return false;
  }

  static bool _constTimeEq(String a, String b) {
    if (a.length != b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) {
      diff |= a.codeUnitAt(i) ^ b.codeUnitAt(i);
    }
    return diff == 0;
  }

  static Uint8List _padKey(Uint8List key) {
    // HMAC-SHA256 requires a 32-byte key; pad TOTP seeds (20-byte typical) with
    // zeros to 32 bytes.
    final out = Uint8List(32);
    out.setRange(0, key.length < 32 ? key.length : 32, key.sublist(0, key.length < 32 ? key.length : 32));
    return out;
  }
}