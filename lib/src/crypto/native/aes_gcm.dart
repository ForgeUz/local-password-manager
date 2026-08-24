import 'dart:ffi';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import 'sodium_ffi.dart';

// Intent: AES-256-GCM via libsodium crypto_aead_aes256gcm.
// Used for: entry ciphertext, DEK wrapping, header MAC (v4 §4/§5).
// Dependencies: libsodium.so.23, dart:ffi, dart:typed_data, package:ffi.
//
// SECURITY CRITICAL: 
// 1. Hardware AES-NI support MUST be verified before use (fail-closed).
// 2. All native memory (keys, plaintext, ciphertext) MUST be zeroed before freeing.

const int _KEYBYTES = 32;
const int _NPUBBYTES = 12;
const int _ABYTES = 16; // tag size

// libsodium signatures (9 args, no key length; nsec is a pointer):
// encrypt(c, clen, m, mlen, ad, adlen, nsec, npub, k)
// decrypt(m, mlen, nsec, c, clen, ad, adlen, npub, k)
typedef EncryptNative = Int32 Function(
  Pointer<Void>, Pointer<Void>, Pointer<Void>, Int64, Pointer<Void>, Int64, Pointer<Void>, Pointer<Void>, Pointer<Void>);
typedef EncryptDart = int Function(
  Pointer<Void>, Pointer<Void>, Pointer<Void>, int, Pointer<Void>, int, Pointer<Void>, Pointer<Void>, Pointer<Void>);
typedef DecryptNative = Int32 Function(
  Pointer<Void>, Pointer<Void>, Pointer<Void>, Pointer<Void>, Int64, Pointer<Void>, Int64, Pointer<Void>, Pointer<Void>);
typedef DecryptDart = int Function(
  Pointer<Void>, Pointer<Void>, Pointer<Void>, Pointer<Void>, int, Pointer<Void>, int, Pointer<Void>, Pointer<Void>);
typedef SodiumMemzeroNative = Void Function(Pointer<Void>, Int64);
typedef SodiumMemzeroDart = void Function(Pointer<Void>, int);
typedef AesAvailableNative = Int32 Function();
typedef AesAvailableDart = int Function();

class AesGcm {
  static bool _inited = false;

  /// Encrypt plaintext using AES-256-GCM.
  /// Returns: nonce(12) || ciphertext || tag(16)
  /// 
  /// SECURITY: All native memory zeroed before freeing.
  static Uint8List encrypt(Uint8List key, Uint8List nonce, Uint8List aad, Uint8List pt) {
    _ensureInit();
    final lib = DynamicLibrary.open('libsodium.so.23');
    final enc = lib.lookupFunction<EncryptNative, EncryptDart>('crypto_aead_aes256gcm_encrypt');
    final memzero = lib.lookupFunction<SodiumMemzeroNative, SodiumMemzeroDart>('sodium_memzero');

    final ct = calloc.allocate<Uint8>(pt.length + _ABYTES);
    final clen = calloc.allocate<Int64>(8);
    final keyPtr = calloc.allocate<Uint8>(_KEYBYTES);
    final noncePtr = calloc.allocate<Uint8>(_NPUBBYTES);
    final aadPtr = calloc.allocate<Uint8>(aad.length);
    final ptPtr = calloc.allocate<Uint8>(pt.length);
    
    try {
      // Copy all inputs into native memory
      keyPtr.asTypedList(_KEYBYTES).setAll(0, key);
      noncePtr.asTypedList(_NPUBBYTES).setAll(0, nonce);
      aadPtr.asTypedList(aad.length).setAll(0, aad);
      ptPtr.asTypedList(pt.length).setAll(0, pt);

      final rc = enc(ct.cast<Void>(), clen.cast<Void>(), ptPtr.cast<Void>(), pt.length,
          aadPtr.cast<Void>(), aad.length, nullptr, noncePtr.cast<Void>(), keyPtr.cast<Void>());
      if (rc != 0) throw StateError('AES-GCM encrypt failed');
      
      final len = clen.cast<Int64>().value;
      
      // CRITICAL: Copy result BEFORE zeroing
      final result = Uint8List.fromList(ct.asTypedList(len));
      
      // CRITICAL: Zero ALL secrets before freeing
      memzero(keyPtr.cast<Void>(), _KEYBYTES);
      memzero(ptPtr.cast<Void>(), pt.length);
      memzero(ct.cast<Void>(), len);
      
      return result;
    } catch (e) {
      // On error, still zero memory
      memzero(keyPtr.cast<Void>(), _KEYBYTES);
      memzero(ptPtr.cast<Void>(), pt.length);
      memzero(ct.cast<Void>(), pt.length + _ABYTES);
      rethrow;
    } finally {
      calloc.free(ct);
      calloc.free(clen);
      calloc.free(keyPtr);
      calloc.free(noncePtr);
      calloc.free(aadPtr);
      calloc.free(ptPtr);
    }
  }

  /// Decrypt ciphertext using AES-256-GCM.
  /// Input: nonce(12) || ciphertext || tag(16)
  /// 
  /// SECURITY: All native memory (key, plaintext) zeroed before freeing.
  static Uint8List decrypt(Uint8List key, Uint8List nonce, Uint8List aad, Uint8List ct) {
    _ensureInit();
    final lib = DynamicLibrary.open('libsodium.so.23');
    final dec = lib.lookupFunction<DecryptNative, DecryptDart>('crypto_aead_aes256gcm_decrypt');
    final memzero = lib.lookupFunction<SodiumMemzeroNative, SodiumMemzeroDart>('sodium_memzero');

    final pt = calloc.allocate<Uint8>(ct.length - _ABYTES);
    final mlen = calloc.allocate<Int64>(8);
    final keyPtr = calloc.allocate<Uint8>(_KEYBYTES);
    final noncePtr = calloc.allocate<Uint8>(_NPUBBYTES);
    final aadPtr = calloc.allocate<Uint8>(aad.length);
    final ctPtr = calloc.allocate<Uint8>(ct.length);
    
    try {
      // Copy all inputs into native memory
      keyPtr.asTypedList(_KEYBYTES).setAll(0, key);
      noncePtr.asTypedList(_NPUBBYTES).setAll(0, nonce);
      aadPtr.asTypedList(aad.length).setAll(0, aad);
      ctPtr.asTypedList(ct.length).setAll(0, ct);

      final rc = dec(pt.cast<Void>(), mlen.cast<Void>(), nullptr, ctPtr.cast<Void>(), ct.length,
          aadPtr.cast<Void>(), aad.length, noncePtr.cast<Void>(), keyPtr.cast<Void>());
      if (rc != 0) throw StateError('AES-GCM decrypt failed (tag mismatch)');
      
      final len = mlen.cast<Int64>().value;
      
      // CRITICAL: Copy plaintext BEFORE zeroing
      final result = Uint8List.fromList(pt.asTypedList(len));
      
      // CRITICAL: Zero ALL secrets before freeing
      memzero(keyPtr.cast<Void>(), _KEYBYTES);
      memzero(pt.cast<Void>(), len);          // plaintext output
      memzero(ctPtr.cast<Void>(), ct.length); // ciphertext input

      return result;
    } catch (e) {
      // On error, still zero memory
      memzero(keyPtr.cast<Void>(), _KEYBYTES);
      memzero(pt.cast<Void>(), ct.length - _ABYTES);   // ← pt, not ptPtr
      memzero(ctPtr.cast<Void>(), ct.length);
      rethrow;
    } finally {
      calloc.free(pt);
      calloc.free(mlen);
      calloc.free(keyPtr);
      calloc.free(noncePtr);
      calloc.free(aadPtr);
      calloc.free(ctPtr);
    }
  }

  static void _ensureInit() {
    if (_inited) return;
    SodiumFfi.load().init();
    
    // CRITICAL: Verify hardware AES-NI support (fail-closed)
    final lib = DynamicLibrary.open('libsodium.so.23');
    final isAvailable = lib.lookupFunction<AesAvailableNative, AesAvailableDart>(
        'crypto_aead_aes256gcm_is_available')();
    
    if (isAvailable == 0) {
      throw StateError('AES-GCM hardware acceleration (AES-NI) not available on this CPU. '
          'Failing closed for security. Use ChaCha20-Poly1305 instead.');
    }
    
    _inited = true;
  }
}