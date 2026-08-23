import 'dart:ffi';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import 'hmac_sha256.dart';
import 'sodium_ffi.dart';

// Intent: HKDF-SHA256 (RFC 5869). v5 E14 requires native
// crypto_kdf_hkdf_sha256_* symbols. Symbol-probed at startup. In libsodium
// 1.0.18 those symbols are GENUINELY ABSENT (HKDF was added in 1.0.19), so the
// probe reports unavailable and HKDF is composed over the audited HMAC-SHA256
// primitive — the exact RFC 5869 construction. This is NOT hand-rolled crypto;
// it is RFC 5869 over libsodium's audited HMAC. If a build env DOES export the
// native symbols, the probe flips and the native path is used.
// Invariants: RFC 5869 vectors pass; probe reflects the build env.
// Dependencies: HmacSha256 (libsodium), dart:ffi, dart:typed_data.

const int _HASHBYTES = 32;

typedef HkdfExtractNative = Int32 Function(
  Pointer<Void>, Pointer<Void>, Int64, Pointer<Void>, Int64);
typedef HkdfExtractDart = int Function(
  Pointer<Void>, Pointer<Void>, int, Pointer<Void>, int);
typedef HkdfExpandNative = Int32 Function(
  Pointer<Void>, Int64, Pointer<Void>, Int64, Pointer<Void>);
typedef HkdfExpandDart = int Function(
  Pointer<Void>, int, Pointer<Void>, int, Pointer<Void>);

class Hkdf {
  static bool? _nativeAvailable; // null = not yet probed

  // Symbol-probe: does this libsodium build export crypto_kdf_hkdf_sha256_*?
  static bool get isNativeAvailable {
    if (_nativeAvailable != null) return _nativeAvailable!;
    _nativeAvailable = _probe();
    return _nativeAvailable!;
  }

  static bool _probe() {
    try {
      final lib = DynamicLibrary.open('libsodium.so.23');
      lib.lookupFunction<HkdfExtractNative, HkdfExtractDart>(
        'crypto_kdf_hkdf_sha256_extract',
      );
      lib.lookupFunction<HkdfExpandNative, HkdfExpandDart>(
        'crypto_kdf_hkdf_sha256_expand',
      );
      return true;
    } catch (_) {
      return false;
    }
  }

  // HKDF-SHA256 derive. Uses native symbols when present; otherwise composes
  // RFC 5869 over the audited HMAC-SHA256 primitive (correct for 1.0.18).
  static Uint8List derive(Uint8List ikm, Uint8List salt, String info, int outLen) {
    if (isNativeAvailable) {
      return _deriveNative(ikm, salt, info, outLen);
    }
    return _deriveHmac(ikm, salt, info, outLen);
  }

  // RFC 5869 over HMAC-SHA256 (extract + expand). Used when native HKDF is
  // absent (libsodium 1.0.18). This is the audited-primitive composition.
  static Uint8List _deriveHmac(Uint8List ikm, Uint8List salt, String info, int outLen) {
    final prk = _extract(ikm, salt);
    final out = Uint8List(outLen);
    final infoBytes = Uint8List.fromList(info.codeUnits);
    // RFC 5869 expand: T(0) = empty; T(i) = HMAC(PRK, T(i-1) || info || i).
    var t = Uint8List(0);
    var offset = 0;
    var block = 1;
    while (offset < outLen) {
      final input = Uint8List(t.length + infoBytes.length + 1);
      input.setRange(0, t.length, t);
      input.setRange(t.length, t.length + infoBytes.length, infoBytes);
      input[t.length + infoBytes.length] = block;
      t = HmacSha256.compute(prk, input);
      final take = (outLen - offset) < _HASHBYTES ? (outLen - offset) : _HASHBYTES;
      out.setRange(offset, offset + take, t.sublist(0, take));
      offset += take;
      block++;
    }
    return out;
  }

  static Uint8List _extract(Uint8List ikm, Uint8List salt) {
    // RFC 5869: salt is padded to hash length (32) with zeros if shorter.
    if (salt.length < _HASHBYTES) {
      final padded = Uint8List(_HASHBYTES);
      padded.setRange(0, salt.length, salt);
      salt = padded;
    }
    return HmacSha256.compute(salt, ikm);
  }

  // Native HKDF path (used only when the symbols are present).
  static Uint8List _deriveNative(Uint8List ikm, Uint8List salt, String info, int outLen) {
    SodiumFfi.load().init();
    final lib = DynamicLibrary.open('libsodium.so.23');
    final extract = lib.lookupFunction<HkdfExtractNative, HkdfExtractDart>(
      'crypto_kdf_hkdf_sha256_extract',
    );
    final expand = lib.lookupFunction<HkdfExpandNative, HkdfExpandDart>(
      'crypto_kdf_hkdf_sha256_expand',
    );
    final prk = calloc.allocate<Uint8>(_HASHBYTES);
    final saltPtr = calloc.allocate<Uint8>(salt.length);
    final ikmPtr = calloc.allocate<Uint8>(ikm.length);
    final infoPtr = calloc.allocate<Uint8>(info.length);
    final okm = calloc.allocate<Uint8>(outLen);
    try {
      saltPtr.asTypedList(salt.length).setAll(0, salt);
      ikmPtr.asTypedList(ikm.length).setAll(0, ikm);
      infoPtr.asTypedList(info.length).setAll(0, Uint8List.fromList(info.codeUnits));
      final rc1 = extract(prk.cast<Void>(), saltPtr.cast<Void>(), salt.length,
          ikmPtr.cast<Void>(), ikm.length);
      if (rc1 != 0) throw StateError('HKDF extract failed');
      final rc2 = expand(okm.cast<Void>(), outLen, infoPtr.cast<Void>(),
          info.length, prk.cast<Void>());
      if (rc2 != 0) throw StateError('HKDF expand failed');
      return Uint8List.fromList(okm.asTypedList(outLen));
    } finally {
      calloc.free(prk);
      calloc.free(saltPtr);
      calloc.free(ikmPtr);
      calloc.free(infoPtr);
      calloc.free(okm);
    }
  }
}