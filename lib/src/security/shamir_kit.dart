import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

// Intent: Shamir's Secret Sharing over GF(256) (SLIP-39 style) for the
// Master Key recovery kit (v3 §15 / Phase I.8). Splits the MK into N shares;
// any K shares reconstruct it. Opt-in, off by default.
// Invariants: split->reconstruct(all N) == MK; any K of N reconstructs MK;
// fewer than K shares cannot.
// Dependencies: dart:math (CSPRNG), dart:typed_data. Pure math, no I/O.
// State Transition: split(MK, n, k) -> List<Share>; reconstruct(List<Share>) -> MK.

class Share {
  final int x; // x-coordinate (1..255)
  final Uint8List y; // one y per secret byte

  const Share({required this.x, required this.y});
}

class ShamirKit {
  // Encode a share as a QR-ready base64 string: x(1B) || y.
  static String encodeShare(Share s) {
    final bytes = Uint8List(1 + s.y.length);
    bytes[0] = s.x;
    bytes.setRange(1, bytes.length, s.y);
    return base64Encode(bytes);
  }

  // Parse a base64 share string back into a Share.
  static Share parseShare(String encoded) {
    final bytes = base64Decode(encoded);
    if (bytes.length < 2) throw StateError('invalid share');
    return Share(x: bytes[0], y: Uint8List.fromList(bytes.sublist(1)));
  }
  // AES irreducible polynomial x^8+x^4+x^3+x+1 = 0x11b.
  static const int _GF_POLY = 0x11b;

  // Split a secret (byte array) into n shares; any k reconstruct it.
  static List<Share> split(Uint8List secret, {required int n, required int k}) {
    if (k < 1 || k > n || n > 255) throw StateError('invalid (n,k)');
    final r = Random.secure();
    // Distinct x-coordinates 1..255.
    final xs = <int>[];
    while (xs.length < n) {
      final x = 1 + r.nextInt(255);
      if (!xs.contains(x)) xs.add(x);
    }
    // For each secret byte, build ONE random degree-(k-1) polynomial whose
    // constant term is the secret byte. All shares of that byte must come from
    // the same polynomial, so generate coefficients once per byte.
    final polys = List.generate(secret.length, (b) => _randomCoeffs(secret[b], k, r));
    final shares = <Share>[];
    for (final x in xs) {
      final y = Uint8List(secret.length);
      for (var b = 0; b < secret.length; b++) {
        y[b] = _evalPoly(polys[b], x);
      }
      shares.add(Share(x: x, y: y));
    }
    return shares;
  }

  // Reconstruct the secret from any k shares via Lagrange interpolation at x=0.
  static Uint8List reconstruct(List<Share> shares) {
    if (shares.isEmpty) throw StateError('no shares');
    final len = shares.first.y.length;
    final out = Uint8List(len);
    for (var b = 0; b < len; b++) {
      var acc = 0;
      for (var i = 0; i < shares.length; i++) {
        var term = shares[i].y[b];
        for (var j = 0; j < shares.length; j++) {
          if (i == j) continue;
          // Lagrange basis at x=0: x_j / (x_i - x_j). In GF(2), x_i - x_j ==
          // x_i XOR x_j == x_j - x_i, so the sign is irrelevant.
          final denom = _gfSub(shares[i].x, shares[j].x);
          final factor = _gfDiv(shares[j].x, denom);
          term = _gfMul(term, factor);
        }
        acc ^= term;
      }
      out[b] = acc;
    }
    return out;
  }

  // Random degree-(k-1) polynomial coefficients; coeff[0] = secretByte.
  static List<int> _randomCoeffs(int secretByte, int k, Random r) {
    final coeff = List<int>.filled(k, 0);
    coeff[0] = secretByte;
    for (var i = 1; i < k; i++) {
      coeff[i] = r.nextInt(256);
    }
    return coeff;
  }

  // Horner evaluation of the polynomial at x.
  static int _evalPoly(List<int> coeff, int x) {
    var y = 0;
    for (var i = coeff.length - 1; i >= 0; i--) {
      y = _gfMul(y, x) ^ coeff[i];
    }
    return y;
  }

  // GF(256) subtraction == XOR (char 2).
  static int _gfSub(int a, int b) => a ^ b;

  // GF(256) multiply (carryless) then reduce mod 0x11b.
  static int _gfMul(int a, int b) {
    var result = 0;
    while (b > 0) {
      if ((b & 1) != 0) result ^= a;
      a <<= 1;
      if ((a & 0x100) != 0) a ^= _GF_POLY;
      b >>= 1;
    }
    return result & 0xff;
  }

  // GF(256) division via a * inv(b).
  static int _gfDiv(int a, int b) {
    return _gfMul(a, _gfInverse(b));
  }

  static int _gfInverse(int a) {
    if (a == 0) throw StateError('zero has no inverse');
    // In GF(256) the nonzero group has order 255, so a^254 = a^-1.
    var result = 1;
    var base = a;
    var exp = 254;
    while (exp > 0) {
      if ((exp & 1) != 0) result = _gfMul(result, base);
      base = _gfMul(base, base);
      exp >>= 1;
    }
    return result;
  }
}