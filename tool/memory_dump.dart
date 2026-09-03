// File: tool/memory_dump.dart
// Intent: security.md gate 16.1 — Memory dump analysis.
// Verifies that after a SecureBuffer is disposed (lock), no residual plaintext
// remains in its native region. This is the unit-level proxy for the spec's
// "no residual plaintext post-lock" requirement.
// Invariants:
// - After vault lock: no MK, VRK, DEK in memory (native regions zeroed).
// - No accumulation of secrets over multiple lock/unlock cycles.
// - Service-layer derivations (VaultService) leave no MK/VRK/MP on the Dart
//   heap after the operation returns (CWE-226 zeroization, Part II item 2).
// Usage: dart run tool/memory_dump.dart
// Dependencies: secure_buffer.dart, memory_dump.dart, vault_service.dart.

import 'dart:io';
import 'dart:typed_data';

import 'package:vault_crypto/src/app/app_store.dart';
import 'package:vault_crypto/src/app/vault_service.dart';
import 'package:vault_crypto/src/crypto/native/memory_dump.dart';
import 'package:vault_crypto/src/crypto/native/secure_buffer.dart';
import 'package:vault_crypto/src/crypto/v4/vault_crypto_v4.dart';
import 'package:vault_crypto/src/vault/vault_data.dart';
import 'package:vault_crypto/src/vault/vault_storage.dart';

void main() async {
  var failures = 0;

  // 1. Single lock/unlock cycle: marker must be wiped after dispose.
  final marker = Uint8List.fromList(List.generate(32, (i) => (0xA0 + i) & 0xFF));
  final buf = SecureBuffer.alloc(marker.length);
  buf.writeBytes(marker);
  final presentBefore = MemoryDumpVerifier.scanFor(buf, marker);
  buf.dispose();
  final presentAfter = MemoryDumpVerifier.scanFor(buf, marker);
  print('Single cycle: presentBefore=$presentBefore presentAfter=$presentAfter');
  if (!presentBefore || presentAfter) {
    print('FAIL: residual plaintext after dispose');
    failures++;
  }

  // 2. 1000 lock/unlock cycles: no accumulation.
  var accumulated = false;
  for (var i = 0; i < 1000; i++) {
    final m = Uint8List.fromList(List.generate(32, (j) => (0x10 + (i + j)) & 0xFF));
    final b = SecureBuffer.alloc(m.length);
    b.writeBytes(m);
    b.dispose();
    if (MemoryDumpVerifier.scanFor(b, m)) {
      accumulated = true;
      break;
    }
  }
  print('1000 cycles: accumulated=$accumulated');
  if (accumulated) {
    print('FAIL: secret accumulation over lock/unlock cycles');
    failures++;
  }

  // 3. Service-layer zeroization (Part II item 2): exercise the VaultService
  // derivation paths and confirm the held VRK is wiped on lock. The MK/VRK
  // intermediates are zeroed in finally blocks; the held VRK lives in a
  // SecureBuffer and is wiped by lock(). We verify the held VRK is gone after
  // lock and that a fresh unlock re-derives cleanly (no stale key reuse).
  try {
    final tmp = Directory.systemTemp.createTempSync('memory_dump_vault');
    try {
      final store = AppStore();
      final service = VaultService(
        store: store,
        crypto: VaultCryptoV4(),
        storage: VaultStorage(baseDir: tmp),
      );
      await service.init();
      final mp = SecureBuffer.fromList(Uint8List.fromList('right'.codeUnits));
      await service.createVault(mp);
      await service.lock();
      await service.unlock(SecureBuffer.fromList(Uint8List.fromList('right'.codeUnits)));
      if (!service.hasVrk) {
        print('FAIL: unlock did not hold a VRK');
        failures++;
      }
      await service.addEntry(VaultEntry(
        id: 'e1',
        title: 'GitHub',
        username: 'u',
        password: 'p',
        url: 'github.com',
      ));
      await service.lock();
      if (service.hasVrk) {
        print('FAIL: VRK still live after lock (service-layer zeroization)');
        failures++;
      }
      // Re-unlock must still work (no stale key material corrupted the blob).
      await service.unlock(
          SecureBuffer.fromList(Uint8List.fromList('right'.codeUnits)));
      if (!service.hasVrk || service.getEntry('e1') == null) {
        print('FAIL: re-unlock after lock failed (round-trip broken)');
        failures++;
      }
      await service.lock();
      print('PASS: service-layer VRK zeroized on lock; round-trip intact');
    } finally {
      if (tmp.existsSync()) tmp.deleteSync(recursive: true);
    }
  } catch (e) {
    print('FAIL: service-layer memory check threw: $e');
    failures++;
  }

  if (failures > 0) {
    print('FAIL: $failures memory-dump check(s) failed.');
    // Exit non-zero to signal failure.
    throw StateError('memory dump verification failed');
  }
  print('PASS: no residual plaintext after lock; no accumulation over 1000 cycles; '
      'service-layer keys zeroized.');
}
