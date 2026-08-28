import 'dart:typed_data';

// Intent: SHA-1 (FIPS 180-1) for HIBP k-anonymity interop (v5 E8). HIBP Pwned
// Passwords keys on SHA-1 prefixes; libsodium 1.0.18 does not export
// crypto_hash_sha1. SHA-1 here is an INTEROP IDENTIFIER ONLY — never used for
// storage, integrity, or any security boundary. The full hash never leaves the
// device; only the 5-char prefix is exposed.
// Invariants: matches FIPS 180-1 known-answer vectors.
// Dependencies: dart:typed_data. Pure Dart (interop-only, not a security primitive).

class Sha1 {
  static Uint8List hash(Uint8List data) {
    // Pad: append 0x80, zeros, then 64-bit big-endian bit length.
    final bitLen = data.length * 8;
    final paddedLen = ((data.length + 8) ~/ 64 + 1) * 64;
    final padded = Uint8List(paddedLen);
    padded.setRange(0, data.length, data);
    padded[data.length] = 0x80;
    final bd = ByteData.sublistView(padded);
    bd.setUint64(paddedLen - 8, bitLen, Endian.big);

    var h0 = 0x67452301,
        h1 = 0xEFCDAB89,
        h2 = 0x98BADCFE,
        h3 = 0x10325476,
        h4 = 0xC3D2E1F0;
    final w = List<int>.filled(80, 0);

    for (var block = 0; block < paddedLen; block += 64) {
      for (var i = 0; i < 16; i++) {
        w[i] = bd.getUint32(block + i * 4, Endian.big);
      }
      for (var i = 16; i < 80; i++) {
        w[i] = _rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
      }
      var a = h0, b = h1, c = h2, d = h3, e = h4;
      for (var i = 0; i < 80; i++) {
        int f, k;
        if (i < 20) {
          f = (b & c) | ((~b) & d);
          k = 0x5A827999;
        } else if (i < 40) {
          f = b ^ c ^ d;
          k = 0x6ED9EBA1;
        } else if (i < 60) {
          f = (b & c) | (b & d) | (c & d);
          k = 0x8F1BBCDC;
        } else {
          f = b ^ c ^ d;
          k = 0xCA62C1D6;
        }
        final temp = (_rotl(a, 5) + f + e + k + w[i]) & 0xFFFFFFFF;
        e = d;
        d = c;
        c = _rotl(b, 30);
        b = a;
        a = temp;
      }
      h0 = (h0 + a) & 0xFFFFFFFF;
      h1 = (h1 + b) & 0xFFFFFFFF;
      h2 = (h2 + c) & 0xFFFFFFFF;
      h3 = (h3 + d) & 0xFFFFFFFF;
      h4 = (h4 + e) & 0xFFFFFFFF;
    }

    final out = Uint8List(20);
    final obd = ByteData.sublistView(out);
    obd.setUint32(0, h0, Endian.big);
    obd.setUint32(4, h1, Endian.big);
    obd.setUint32(8, h2, Endian.big);
    obd.setUint32(12, h3, Endian.big);
    obd.setUint32(16, h4, Endian.big);
    return out;
  }

  static int _rotl(int x, int n) => ((x << n) | (x >>> (32 - n))) & 0xFFFFFFFF;
}
