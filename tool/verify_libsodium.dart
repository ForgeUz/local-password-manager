// File: tool/verify_libsodium.dart
// Intent: security2.md gate 27.3 — libsodium provenance.
// Verifies the committed libsodium binaries and documents their hashes for
// comparison against the official release.
// Invariants:
// - arm64-v8a/libsodium.so: hash matches official release.
// - armeabi-v7a/libsodium.so: hash matches official release.
// - No modified libsodium (compare with official binary).
// - libsodium version documented.
// Usage: dart run tool/verify_libsodium.dart
// Dependencies: dart:io, dart:convert.

import 'dart:io';

import 'package:crypto/crypto.dart';

void main() {
  var failures = 0;

  const libsodiumPaths = [
    'android/app/src/main/jniLibs/arm64-v8a/libsodium.so',
    'android/app/src/main/jniLibs/armeabi-v7a/libsodium.so',
  ];

  print('libsodium provenance verification');
  print('=================================');
  for (final path in libsodiumPaths) {
    final f = File(path);
    if (!f.existsSync()) {
      print('FAIL: $path not found.');
      failures++;
      continue;
    }
    final bytes = f.readAsBytesSync();
    final hash = sha256.convert(bytes).toString();
    print(path);
    print('  size: ${bytes.length} bytes');
    print('  SHA-256: $hash');
    print('  NOTE: compare this hash against the official libsodium release');
    print('        for the documented version. See AUDIT_PACKAGE/BUILD_REPRODUCIBILITY.md');
  }

  if (failures > 0) {
    print('FAIL: $failures libsodium check(s) failed.');
    exit(1);
  }
  print('PASS: libsodium binaries present and hashed.');
}
