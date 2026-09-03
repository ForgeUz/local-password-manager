// File: test/security/model/reference_crypto.dart
// Intent: security2.md gate 22.1 — Pure Dart reference implementation of the
// crypto primitives, independent of libsodium. Used for differential testing
// against the FFI wrappers to catch parameter-marshalling bugs.
//
// Reference implementations:
// - HKDF-SHA256: RFC 5869 in pure Dart (over package:crypto HMAC).
// - HMAC-SHA256: via package:crypto (independent of libsodium).
//
// Invariants:
// - Reference HKDF output == libsodium HKDF output (byte-for-byte).
// - Reference HMAC output == libsodium HMAC output.
// Dependencies: package:crypto (HMAC), dart:typed_data.

import 'dart:typed_data';

import 'package:crypto/crypto.dart';

/// Pure Dart HKDF-SHA256 (RFC 5869) reference implementation.
class ReferenceHkdf {
  /// RFC 5869 extract: PRK = HMAC-SHA256(salt, IKM).
  static Uint8List extract(Uint8List ikm, Uint8List salt) {
    // Salt is padded to hash length (32) with zeros if shorter.
    final paddedSalt = salt.length >= 32 ? salt : Uint8List(32)
      ..setRange(0, salt.length, salt);
    return Uint8List.fromList(
      Hmac(sha256, paddedSalt).convert(ikm).bytes,
    );
  }

  /// RFC 5869 expand: OKM = T(1) || T(2) || ... || T(n).
  static Uint8List expand(Uint8List prk, Uint8List info, int outLen) {
    final out = Uint8List(outLen);
    var t = Uint8List(0);
    var offset = 0;
    var block = 1;
    while (offset < outLen) {
      final input = Uint8List(t.length + info.length + 1);
      input.setRange(0, t.length, t);
      input.setRange(t.length, t.length + info.length, info);
      input[t.length + info.length] = block;
      t = Uint8List.fromList(Hmac(sha256, prk).convert(input).bytes);
      final take = (outLen - offset) < 32 ? (outLen - offset) : 32;
      out.setRange(offset, offset + take, t.sublist(0, take));
      offset += take;
      block++;
    }
    return out;
  }

  /// Full HKDF derive (extract + expand).
  static Uint8List derive(
      Uint8List ikm, Uint8List salt, Uint8List info, int outLen) {
    final prk = extract(ikm, salt);
    return expand(prk, info, outLen);
  }
}

/// Pure Dart HMAC-SHA256 reference (via package:crypto).
class ReferenceHmacSha256 {
  static Uint8List compute(Uint8List key, Uint8List data) {
    return Uint8List.fromList(Hmac(sha256, key).convert(data).bytes);
  }
}
